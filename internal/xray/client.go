// Package xray — gRPC-клиент к живому Xray-core (control plane балансировщика).
// Использует готовые сгенерированные клиенты из библиотеки xray-core:
// RoutingService (AddRule/RemoveRule/ListRule/TestRoute), HandlerService (AlterInbound),
// StatsService (QueryStats/online), ObservatoryService (health/RTT).
// Всё горячо, без рестарта процесса. per-user routing: user:[email] → outboundTag.
package xray

import (
	"context"
	"fmt"
	"strings"
	"time"

	router "github.com/xtls/xray-core/app/router"
	routercmd "github.com/xtls/xray-core/app/router/command"
	proxycmd "github.com/xtls/xray-core/app/proxyman/command"
	statscmd "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vmess"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

// Client — соединение с Xray gRPC API (api inbound на мастере, 127.0.0.1:PORT).
type Client struct {
	conn    *grpc.ClientConn
	Routing routercmd.RoutingServiceClient
	Handler proxycmd.HandlerServiceClient
	Stats   statscmd.StatsServiceClient
	addr    string
}

// Dial подключается к Xray gRPC API. addr например "127.0.0.1:62789".
// Xray api inbound без TLS (локальный tunnel) → insecure. Для удалённого — TLS later.
func Dial(addr string) (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("xray dial %s: %w", addr, err)
	}
	return &Client{
		conn:    conn,
		Routing: routercmd.NewRoutingServiceClient(conn),
		Handler: proxycmd.NewHandlerServiceClient(conn),
		Stats:   statscmd.NewStatsServiceClient(conn),
		addr:    addr,
	}, nil
}

func (c *Client) Close() error { return c.conn.Close() }
func (c *Client) Addr() string { return c.addr }

// ConnBroken — соединение gRPC не в состоянии READY (рестарт xray рвёт его).
// Для health-watch внешнего рестарта: процесс мог вернуться быстрее тика.
func (c *Client) ConnBroken() bool {
	return c.conn.GetState() != connectivity.Ready
}

// Reconnect переподключается к Xray gRPC (после рестарта xray).
func (c *Client) Reconnect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, c.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("xray reconnect %s: %w", c.addr, err)
	}
	old := c.conn
	c.conn = conn
	c.Routing = routercmd.NewRoutingServiceClient(conn)
	c.Handler = proxycmd.NewHandlerServiceClient(conn)
	c.Stats = statscmd.NewStatsServiceClient(conn)
	if old != nil {
		old.Close()
	}
	return nil
}

// UserRule — базовое per-user routing rule: клиент (email) → нода (outboundTag).
// Страна клиента = clients.country в БД (vlessRoute-слой удалён, один UUID).
// ruleTag — уникальный ключ для RemoveRule, формат "c:<email>:<country>".
type UserRule struct {
	RuleTag     string // c:ivan@mail.ru:de
	Email       string // идентичность клиента в Xray
	OutboundTag string // node-de-1
}

// buildRule собирает RoutingRule из UserRule.
func buildRule(r UserRule) *router.RoutingRule {
	return &router.RoutingRule{
		RuleTag:   r.RuleTag,
		UserEmail: []string{r.Email},
		TargetTag: &router.RoutingRule_Tag{Tag: r.OutboundTag},
	}
}

// AddUserRule добавляет per-user правило горячо (shouldAppend=true).
// ВНИМАНИЕ: append кладёт в КОНЕЦ — per-user rules должны быть ВЫШЕ catch-all.
// Для гарантии порядка используй ReplaceRules (shouldAppend=false) с полным набором.
func (c *Client) AddUserRule(ctx context.Context, r UserRule) error {
	cfg := &router.Config{Rule: []*router.RoutingRule{buildRule(r)}}
	_, err := c.Routing.AddRule(ctx, &routercmd.AddRuleRequest{
		Config:       serial.ToTypedMessage(cfg),
		ShouldAppend: true,
	})
	if err != nil {
		return fmt.Errorf("AddRule %s: %w", r.RuleTag, err)
	}
	return nil
}

// RemoveUserRule удаляет правило по ruleTag горячо.
func (c *Client) RemoveUserRule(ctx context.Context, ruleTag string) error {
	_, err := c.Routing.RemoveRule(ctx, &routercmd.RemoveRuleRequest{RuleTag: ruleTag})
	if err != nil {
		return fmt.Errorf("RemoveRule %s: %w", ruleTag, err)
	}
	return nil
}

// ReplaceRules атомарно заменяет ВЕСЬ набор routing rules (shouldAppend=false).
// Главный механизм failover без обрыва: чужие правила не изменились → чужие сессии живут.
// Порядок правил сохраняется (per-user выше catch-all). Балансировщики тоже передаются.
// AppendRules — добавляет правила поверх существующих (ShouldAppend=true).
func (c *Client) AppendRules(ctx context.Context, rules []*router.RoutingRule) error {
	cfg := &router.Config{Rule: rules}
	_, err := c.Routing.AddRule(ctx, &routercmd.AddRuleRequest{
		Config:       serial.ToTypedMessage(cfg),
		ShouldAppend: true,
	})
	if err != nil {
		return fmt.Errorf("AppendRules: %w", err)
	}
	return nil
}

func (c *Client) ReplaceRules(ctx context.Context, rules []*router.RoutingRule, balancers []*router.BalancingRule) error {
	cfg := &router.Config{Rule: rules, BalancingRule: balancers}
	_, err := c.Routing.AddRule(ctx, &routercmd.AddRuleRequest{
		Config:       serial.ToTypedMessage(cfg),
		ShouldAppend: false,
	})
	if err != nil {
		return fmt.Errorf("ReplaceRules: %w", err)
	}
	return nil
}

// SwapUserRule меняет ноду клиента без микрозазора: add нового (v2 ruleTag) → remove старого.
// Новые соединения сразу на новой ноде, установленные доживают.
func (c *Client) SwapUserRule(ctx context.Context, oldRuleTag string, newRule UserRule) error {
	if err := c.AddUserRule(ctx, newRule); err != nil {
		return err
	}
	// remove старого после add нового (микрозазор минимален, новые уже на новой ноде)
	if err := c.RemoveUserRule(ctx, oldRuleTag); err != nil {
		return fmt.Errorf("swap remove old %s: %w", oldRuleTag, err)
	}
	return nil
}

// ListRules возвращает текущие правила (tag outbound + ruleTag).
func (c *Client) ListRules(ctx context.Context) ([]*routercmd.ListRuleItem, error) {
	resp, err := c.Routing.ListRule(ctx, &routercmd.ListRuleRequest{})
	if err != nil {
		return nil, fmt.Errorf("ListRule: %w", err)
	}
	return resp.Rules, nil
}

// TestRoute проверяет какой outbound выберет ядро для клиента БЕЗ трафика.
// email + inboundTag → OutboundTag/RuleTag (базовый UUID, без страновых профилей).
func (c *Client) TestRoute(ctx context.Context, inboundTag, email string) (*routercmd.RoutingContext, error) {
	rc := &routercmd.RoutingContext{
		InboundTag: inboundTag,
		User:       email,
		TargetPort: 443,
	}
	resp, err := c.Routing.TestRoute(ctx, &routercmd.TestRouteRequest{RoutingContext: rc})
	if err != nil {
		return nil, fmt.Errorf("TestRoute %s: %w", email, err)
	}
	return resp, nil
}

// QueryStats возвращает статистику по паттерну (reset=true для дельты за окно).
// Паттерны: "outbound>>>node-de-1>>>traffic>>>downlink", "user>>>email>>>traffic>>>downlink".
func (c *Client) QueryStats(ctx context.Context, pattern string, reset bool) ([]*statscmd.Stat, error) {
	resp, err := c.Stats.QueryStats(ctx, &statscmd.QueryStatsRequest{Pattern: pattern, Reset_: reset})
	if err != nil {
		return nil, fmt.Errorf("QueryStats %s: %w", pattern, err)
	}
	return resp.Stat, nil
}

// OnlineUsers возвращает список онлайн-клиентов (email).
// УРОК ядра 26.11.9: GetAllOnlineUsers отдаёт КЛЮЧИ online-карт
// ("user>>>email>>>online"), не голые email — нормализуем здесь.
func (c *Client) OnlineUsers(ctx context.Context) ([]string, error) {
	resp, err := c.Stats.GetAllOnlineUsers(ctx, &statscmd.GetAllOnlineUsersRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetAllOnlineUsers: %w", err)
	}
	var out []string
	for _, u := range resp.Users {
		if strings.HasPrefix(u, "user>>>") && strings.HasSuffix(u, ">>>online") {
			u = strings.TrimSuffix(strings.TrimPrefix(u, "user>>>"), ">>>online")
		}
		out = append(out, u)
	}
	return out, nil
}

// OnlineIPs возвращает IP-адреса онлайн-клиента (email) с timestamp последнего пакета.
// УРОК (P1 #11, 3x-ui ipLimit gRPC GetStatsOnlineIpList): per-client IP-лимит.
// name = "user>>>email>>>online". map[ip]unixTs.
func (c *Client) OnlineIPs(ctx context.Context, email string) (map[string]int64, error) {
	resp, err := c.Stats.GetStatsOnlineIpList(ctx, &statscmd.GetStatsRequest{
		Name: "user>>>" + email + ">>>online",
	})
	if err != nil {
		return nil, err
	}
	return resp.Ips, nil
}

// AddUser добавляет клиента в inbound горячо (HandlerService.AlterInbound AddUserOperation).
// УРОК (паника xray): account ДОЛЖЕН соответствовать протоколу inbound'а!
// vless.Account в trojan-inbound → panic «interface conversion: *vless.MemoryAccount,
// not *trojan.MemoryAccount» → xray падает. protoName: "vless"/"trojan"/"vmess".
func (c *Client) AddUser(ctx context.Context, inboundTag, email, uuid, flow string) error {
	return c.AddUserProto(ctx, inboundTag, email, uuid, flow, "vless")
}

// AddUserProto — AddUser с явным протоколом inbound'а (vless/trojan/vmess/hysteria2).
// trojan: password=uuid; vmess: id=uuid; hysteria2: auth=uuid (account.Auth).
func (c *Client) AddUserProto(ctx context.Context, inboundTag, email, uuid, flow, protoName string) error {
	var account *serial.TypedMessage
	switch protoName {
	case "trojan":
		account = serial.ToTypedMessage(&trojan.Account{Password: uuid})
	case "vmess":
		account = serial.ToTypedMessage(&vmess.Account{Id: uuid})
	case "hysteria2", "hysteria":
		account = serial.ToTypedMessage(&hyaccount.Account{Auth: uuid})
	default: // vless
		account = serial.ToTypedMessage(&vless.Account{Id: uuid, Flow: flow})
	}
	user := &protocol.User{Email: email, Account: account}
	op := &proxycmd.AddUserOperation{User: user}
	_, err := c.Handler.AlterInbound(ctx, &proxycmd.AlterInboundRequest{
		Tag:       inboundTag,
		Operation: serial.ToTypedMessage(op),
	})
	if err != nil {
		return fmt.Errorf("AddUser %s: %w", email, err)
	}
	return nil
}

// RemoveUser удаляет клиента из inbound горячо (RemoveUserOperation по email).
// Активные сессии не рвутся мгновенно (для жёсткого бана нужен drop коннектов — later).
func (c *Client) RemoveUser(ctx context.Context, inboundTag, email string) error {
	op := &proxycmd.RemoveUserOperation{Email: email}
	_, err := c.Handler.AlterInbound(ctx, &proxycmd.AlterInboundRequest{
		Tag:       inboundTag,
		Operation: serial.ToTypedMessage(op),
	})
	if err != nil {
		return fmt.Errorf("RemoveUser %s: %w", email, err)
	}
	return nil
}

// AddInbound создаёт inbound горячо (HandlerService.AddInbound, без рестарта Xray).
// УРОК (владелец): не ограничены 3X-UI — любой протокол/транспорт Xray 26.x.
// inboundJSON — полный JSON inbound'а (как в config.json): tag/listen/port/protocol/settings/streamSettings.
// Конвертация JSON→protobuf через core.LoadConfig (штатный парсер Xray).
func (c *Client) AddInbound(ctx context.Context, inboundJSON string) error {
	cfg, err := loadInboundConfig(inboundJSON)
	if err != nil {
		return fmt.Errorf("parse inbound: %w", err)
	}
	_, err = c.Handler.AddInbound(ctx, &proxycmd.AddInboundRequest{Inbound: cfg})
	if err != nil {
		return fmt.Errorf("AddInbound: %w", err)
	}
	return nil
}

// RemoveInbound удаляет inbound горячо (HandlerService.RemoveInbound по tag).
func (c *Client) RemoveInbound(ctx context.Context, tag string) error {
	_, err := c.Handler.RemoveInbound(ctx, &proxycmd.RemoveInboundRequest{Tag: tag})
	if err != nil {
		return fmt.Errorf("RemoveInbound %s: %w", tag, err)
	}
	return nil
}