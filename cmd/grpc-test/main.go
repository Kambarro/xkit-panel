// Command grpc-test — live end-to-end тест gRPC-клиента XKIT Panel к реальному Xray 26.11.9.
// Проверяет: ListRule, TestRoute (per-user), AddRule/RemoveRule горячо, SwapUserRule (failover),
// ReplaceRules (атомарный swap), QueryStats, OnlineUsers. БЕЗ рестарта Xray.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kambarro/xkit-panel/internal/xray"
	router "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
)

func main() {
	addr := "127.0.0.1:62789"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := xray.Dial(addr)
	if err != nil {
		fmt.Println("FAIL dial:", err)
		os.Exit(1)
	}
	defer c.Close()
	fmt.Println("✓ Dial", addr)

	pass, fail := 0, 0
	check := func(name string, ok bool, detail string) {
		if ok {
			pass++
			fmt.Printf("✓ %s %s\n", name, detail)
		} else {
			fail++
			fmt.Printf("✗ %s %s\n", name, detail)
		}
	}

	// 1. ListRule — текущие правила
	rules, err := c.ListRules(ctx)
	check("ListRule", err == nil, fmt.Sprintf("(%d правил, err=%v)", len(rules), err))
	for _, r := range rules {
		fmt.Printf("    rule: tag=%s ruleTag=%s\n", r.Tag, r.RuleTag)
	}

	// 2. TestRoute per-user: ivan@test.ru → node-de-1
	rc, err := c.TestRoute(ctx, "vless-in", "ivan@test.ru")
	check("TestRoute ivan→de-1", err == nil && rc != nil && rc.OutboundTag == "node-de-1",
		fmt.Sprintf("(outbound=%v err=%v)", outboundOf(rc), err))

	// 3. TestRoute petra (нет правила) → catch-all direct
	rc2, err := c.TestRoute(ctx, "vless-in", "petra@test.ru")
	check("TestRoute petra→direct(catch-all)", err == nil && rc2 != nil && rc2.OutboundTag == "direct",
		fmt.Sprintf("(outbound=%v err=%v)", outboundOf(rc2), err))

	// 4. AddUserRule горячо: petra → node-nl-1
	err = c.AddUserRule(ctx, xray.UserRule{RuleTag: "c:petra@test.ru:nl", Email: "petra@test.ru", OutboundTag: "node-nl-1"})
	check("AddUserRule petra→nl-1", err == nil, fmt.Sprintf("(err=%v)", err))
	//append в конец → catch-all direct раньше. Проверяем что правило добавлено в список
	rules, _ = c.ListRules(ctx)
	found := false
	for _, r := range rules {
		if r.RuleTag == "c:petra@test.ru:nl" {
			found = true
		}
	}
	check("AddRule виден в ListRule", found, "")

	// 5. ReplaceRules атомарно: per-user ВЫШЕ catch-all (правильный порядок)
	newRules := []*router.RoutingRule{
		{RuleTag: "api", InboundTag: []string{"api-in"}, TargetTag: &router.RoutingRule_Tag{Tag: "api"}},
		{RuleTag: "c:ivan@test.ru:de", UserEmail: []string{"ivan@test.ru"}, TargetTag: &router.RoutingRule_Tag{Tag: "node-de-1"}},
		{RuleTag: "c:petra@test.ru:nl", UserEmail: []string{"petra@test.ru"}, TargetTag: &router.RoutingRule_Tag{Tag: "node-nl-1"}},
		{RuleTag: "catch-all", PortList: &net.PortList{Range: []*net.PortRange{{From: 0, To: 65535}}}, TargetTag: &router.RoutingRule_Tag{Tag: "direct"}},
	}
	err = c.ReplaceRules(ctx, newRules, nil)
	check("ReplaceRules (атомарный swap)", err == nil, fmt.Sprintf("(err=%v)", err))

	// 6. TestRoute после ReplaceRules: petra → nl-1 (правило выше catch-all)
	rc3, err := c.TestRoute(ctx, "vless-in", "petra@test.ru")
	check("TestRoute petra→nl-1 после swap", err == nil && rc3 != nil && rc3.OutboundTag == "node-nl-1",
		fmt.Sprintf("(outbound=%v err=%v)", outboundOf(rc3), err))
	// ivan всё ещё de-1 (чужое правило не изменилось)
	rc4, _ := c.TestRoute(ctx, "vless-in", "ivan@test.ru")
	check("TestRoute ivan→de-1 не затронут", rc4 != nil && rc4.OutboundTag == "node-de-1",
		fmt.Sprintf("(outbound=%v)", outboundOf(rc4)))

	// 7. SwapUserRule failover: ivan de-1 → de-2 (add нового → remove старого)
	err = c.SwapUserRule(ctx, "c:ivan@test.ru:de", xray.UserRule{RuleTag: "c:ivan@test.ru:de:v2", Email: "ivan@test.ru", OutboundTag: "node-de-2"})
	check("SwapUserRule ivan de-1→de-2", err == nil, fmt.Sprintf("(err=%v)", err))
	// после swap нужно поправить порядок (v2 append в конец) — ReplaceRules с актуальным набором
	swapRules := []*router.RoutingRule{
		{RuleTag: "api", InboundTag: []string{"api-in"}, TargetTag: &router.RoutingRule_Tag{Tag: "api"}},
		{RuleTag: "c:ivan@test.ru:de:v2", UserEmail: []string{"ivan@test.ru"}, TargetTag: &router.RoutingRule_Tag{Tag: "node-de-2"}},
		{RuleTag: "c:petra@test.ru:nl", UserEmail: []string{"petra@test.ru"}, TargetTag: &router.RoutingRule_Tag{Tag: "node-nl-1"}},
		{RuleTag: "catch-all", PortList: &net.PortList{Range: []*net.PortRange{{From: 0, To: 65535}}}, TargetTag: &router.RoutingRule_Tag{Tag: "direct"}},
	}
	c.ReplaceRules(ctx, swapRules, nil)
	rc5, _ := c.TestRoute(ctx, "vless-in", "ivan@test.ru")
	check("TestRoute ivan→de-2 после failover", rc5 != nil && rc5.OutboundTag == "node-de-2",
		fmt.Sprintf("(outbound=%v)", outboundOf(rc5)))

	// 8. RemoveUserRule: убрать petra
	err = c.RemoveUserRule(ctx, "c:petra@test.ru:nl")
	check("RemoveUserRule petra", err == nil, fmt.Sprintf("(err=%v)", err))

	// 9. QueryStats (outbound traffic)
	stats, err := c.QueryStats(ctx, "outbound>>>", false)
	check("QueryStats outbound", err == nil, fmt.Sprintf("(%d counters, err=%v)", len(stats), err))

	// 10. OnlineUsers
	users, err := c.OnlineUsers(ctx)
	check("OnlineUsers", err == nil, fmt.Sprintf("(%d online, err=%v)", len(users), err))

	// 11. TestRoute базового UUID повторно (страновых профилей нет)
	rc6, err := c.TestRoute(ctx, "vless-in", "ivan@test.ru")
	check("TestRoute base UUID (no country profiles)", err == nil && rc6 != nil,
		fmt.Sprintf("(outbound=%v err=%v)", outboundOf(rc6), err))

	fmt.Printf("\n=== ИТОГ: %d PASS / %d FAIL ===\n", pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func outboundOf(rc interface{ GetOutboundTag() string }) string {
	if rc == nil {
		return "<nil>"
	}
	return rc.GetOutboundTag()
}