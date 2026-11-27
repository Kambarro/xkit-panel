package api

import (
	"encoding/json"
	"testing"

	"github.com/kambarro/xkit-panel/internal/xray"
	router "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
)

// TestBestTransport — агрегация отчёта: лучший = максимум скорости среди РАБОЧИХ,
// при равенстве скорости — меньший RTT. Нерабочие не участвуют.
func TestBestTransport(t *testing.T) {
	cases := []struct {
		name string
		in   []SurveyResult
		want string
	}{
		{"empty", nil, ""},
		{"all failed", []SurveyResult{{Transport: "tcp-reality", OK: false}, {Transport: "awg", OK: false}}, ""},
		{"single ok", []SurveyResult{{Transport: "ws-tls", OK: true, DownloadMbps: 50}}, "ws-tls"},
		{"max speed wins", []SurveyResult{
			{Transport: "tcp-reality", OK: true, DownloadMbps: 90, RTTMs: 10},
			{Transport: "xhttp-reality", OK: true, DownloadMbps: 120, RTTMs: 40},
			{Transport: "hysteria2", OK: true, DownloadMbps: 30, RTTMs: 5},
		}, "xhttp-reality"},
		{"failed faster ignored", []SurveyResult{
			{Transport: "tcp-reality", OK: true, DownloadMbps: 90},
			{Transport: "hysteria2", OK: false, DownloadMbps: 999},
		}, "tcp-reality"},
		{"tie speed lower rtt", []SurveyResult{
			{Transport: "tcp-reality", OK: true, DownloadMbps: 100, RTTMs: 50},
			{Transport: "awg", OK: true, DownloadMbps: 100, RTTMs: 20},
		}, "awg"},
	}
	for _, c := range cases {
		if got := bestTransport(c.in); got != c.want {
			t.Errorf("%s: bestTransport=%q want %q", c.name, got, c.want)
		}
	}
}

// TestSurveyCandidates — grpc-tls НЕ в кандидатах (deprecated Xray 26.x), awg есть.
func TestSurveyCandidates(t *testing.T) {
	want := map[string]bool{"tcp-reality": true, "xhttp-reality": true, "ws-tls": true, "hysteria2": true, "awg": true}
	if len(surveyCandidates) != len(want) {
		t.Fatalf("candidates=%v want %d", surveyCandidates, len(want))
	}
	for _, c := range surveyCandidates {
		if !want[c] {
			t.Errorf("unexpected candidate %q (grpc-tls deprecated — не предлагать)", c)
		}
	}
}

// TestIsCatchAllRule — catch-all = port 0-65535 без user/inboundTag/domain/ip.
func TestIsCatchAllRule(t *testing.T) {
	catchAll := &router.RoutingRule{PortList: &net.PortList{Range: []*net.PortRange{{From: 0, To: 65535}}}}
	if !isCatchAllRule(catchAll) {
		t.Error("port 0-65535 rule must be catch-all")
	}
	perUser := &router.RoutingRule{UserEmail: []string{"a@b.c"}, PortList: &net.PortList{Range: []*net.PortRange{{From: 0, To: 65535}}}}
	if isCatchAllRule(perUser) {
		t.Error("per-user rule must NOT be catch-all")
	}
	inbound := &router.RoutingRule{InboundTag: []string{"survey-x"}, PortList: &net.PortList{Range: []*net.PortRange{{From: 0, To: 65535}}}}
	if isCatchAllRule(inbound) {
		t.Error("inboundTag rule must NOT be catch-all")
	}
	partial := &router.RoutingRule{PortList: &net.PortList{Range: []*net.PortRange{{From: 443, To: 443}}}}
	if isCatchAllRule(partial) {
		t.Error("port 443 only must NOT be catch-all")
	}
	if isCatchAllRule(nil) || isCatchAllRule(&router.RoutingRule{}) {
		t.Error("nil/no-port rule must NOT be catch-all")
	}
}

// TestSurveyRuleInsertBeforeCatchAll — снапшот routing из config.json парсится штатным
// парсером Xray, survey-правило вставляется ПЕРЕД catch-all (УРОК live MSK: append после
// catch-all → правило мертво, трафик идёт direct мимо туннеля).
func TestSurveyRuleInsertBeforeCatchAll(t *testing.T) {
	routingJSON := `{"domainStrategy":"IPIfNonMatch","rules":[
		{"type":"field","inboundTag":["api-in"],"outboundTag":"api"},
		{"type":"field","user":["ivan@test.ru"],"outboundTag":"node-nl-1","ruleTag":"c:ivan@test.ru:nl"},
		{"type":"field","port":"0-65535","outboundTag":"direct"}
	]}`
	parsed, err := xray.ParseRoutingConfig(routingJSON)
	if err != nil {
		t.Fatalf("ParseRoutingConfig: %v", err)
	}
	if len(parsed.Rule) != 3 {
		t.Fatalf("parsed %d rules, want 3", len(parsed.Rule))
	}
	surveyRule := &router.RoutingRule{RuleTag: "survey:test", InboundTag: []string{"survey-test"}, TargetTag: &router.RoutingRule_Tag{Tag: "node-nl-1"}}
	idx := len(parsed.Rule)
	for i, r := range parsed.Rule {
		if isCatchAllRule(r) {
			idx = i
			break
		}
	}
	if idx != 2 {
		t.Fatalf("catch-all idx=%d want 2", idx)
	}
	rules := append([]*router.RoutingRule{}, parsed.Rule[:idx]...)
	rules = append(rules, surveyRule)
	rules = append(rules, parsed.Rule[idx:]...)
	if len(rules) != 4 || rules[2].RuleTag != "survey:test" {
		t.Fatalf("survey rule must be at idx 2 (before catch-all), got %+v", rules)
	}
	if !isCatchAllRule(rules[3]) {
		t.Error("catch-all must stay LAST")
	}
	// per-user правило не тронуто (чужие сессии живут)
	if rules[1].RuleTag != "c:ivan@test.ru:nl" {
		t.Error("per-user rule must be preserved")
	}
}

// TestSurveyCleanupOrdering — defer-LIFO порядок уборки: сначала мастер (правило+inbound),
// затем нода (сервер+файл+ufw). Проверка на модели: cleanup-шаги регистрируются в порядке
// создания артефактов, выполняются в обратном (как defer в surveyOneCandidate/measureThroughTunnel).
func TestSurveyCleanupOrdering(t *testing.T) {
	var created, cleaned []string
	step := func(name string) func() {
		created = append(created, name)
		return func() { cleaned = append(cleaned, name) }
	}
	// модель surveyOneCandidate: apply → bench server → master inbound → rule → curl
	func() {
		c1 := step("node-bench-server")
		defer c1()
		func() {
			c2 := step("master-inbound")
			defer c2()
			c3 := step("master-rule")
			defer c3()
			// curl fails here — cleanup must still run
		}()
	}()
	wantCreated := []string{"node-bench-server", "master-inbound", "master-rule"}
	wantCleaned := []string{"master-rule", "master-inbound", "node-bench-server"}
	if len(cleaned) != len(created) {
		t.Fatalf("cleanup incomplete: created=%v cleaned=%v", created, cleaned)
	}
	for i := range wantCreated {
		if created[i] != wantCreated[i] {
			t.Errorf("created[%d]=%s want %s", i, created[i], wantCreated[i])
		}
		if cleaned[i] != wantCleaned[i] {
			t.Errorf("cleaned[%d]=%s want %s (LIFO: master before node)", i, cleaned[i], wantCleaned[i])
		}
	}
}

// TestSurveyReportJSON — отчёт сериализуется/десериализуется (settings survey_<nodeID>).
func TestSurveyReportJSON(t *testing.T) {
	rep := SurveyReport{NodeID: "node-nl-1", Running: false, Done: true, Original: "tcp-reality", Restored: true,
		Results: []SurveyResult{{Transport: "xhttp-reality", OK: true, RTTMs: 42.5, DownloadMbps: 123.4}}}
	rep.Best = bestTransport(rep.Results)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back SurveyReport
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Best != "xhttp-reality" || !back.Restored || back.Original != "tcp-reality" || len(back.Results) != 1 {
		t.Errorf("report roundtrip mismatch: %+v", back)
	}
	if back.Results[0].DownloadMbps != 123.4 {
		t.Errorf("speed lost in roundtrip: %v", back.Results[0])
	}
}
