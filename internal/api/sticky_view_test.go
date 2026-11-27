package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/kambarro/xkit-panel/internal/store"
)

// TestBalancerViewCurrentAssignments — sticky-карта API отдаёт ТОЛЬКО актуальное
// закрепление (QA-наследие client: ''/any/US → node-us-539 при country=NL скрыто),
// с человекочитаемым именем ноды и страной НОДЫ, не сырым ruleTag.
func TestBalancerViewCurrentAssignments(t *testing.T) {
	s := testStoreAPI(t)
	srv := NewServer(s, nil, "test", "test.local")
	for _, n := range []store.Node{
		{ID: "node-nl-1", Name: "Whisper", Country: "NL", Health: "alive", Enabled: true},
		{ID: "node-us-539", Name: "OldUS", Country: "US", Health: "alive", Enabled: true},
	} {
		if err := s.UpsertNode(n); err != nil { t.Fatal(err) }
	}
	if err := s.UpsertClient(store.Client{Email: "client", UUID: "u", SubID: "s", Country: "NL", Enabled: true}); err != nil { t.Fatal(err) }
	for _, a := range []store.Assignment{
		{Email: "client", Country: "", NodeID: "node-us-539", RuleTag: "c:client:", Status: "sticky"},
		{Email: "client", Country: "NL", NodeID: "node-nl-1", RuleTag: "c:client:NL", Status: "sticky"},
		{Email: "client", Country: "any", NodeID: "node-us-539", RuleTag: "c:client:any", Status: "sticky"},
		{Email: "client", Country: "US", NodeID: "node-us-539", RuleTag: "c:client:US", Status: "sticky"},
	} {
		if err := s.SetAssignment(a); err != nil { t.Fatal(err) }
	}
	s.DB().Exec(`UPDATE assignments SET updated_at=1000 WHERE email='client'`)
	s.DB().Exec(`UPDATE assignments SET updated_at=2000 WHERE email='client' AND country='NL'`)

	w := httptest.NewRecorder()
	srv.balancerView(w, httptest.NewRequest("GET", "/api/balancer", nil))
	var resp struct {
		Assignments []struct {
			Email       string `json:"email"`
			Country     string `json:"country"`
			Node        string `json:"node"`
			NodeName    string `json:"node_name"`
			NodeCountry string `json:"node_country"`
			Status      string `json:"status"`
			Variant     bool   `json:"variant"`
		} `json:"assignments"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil { t.Fatal(err) }
	if len(resp.Assignments) != 1 {
		t.Fatalf("карта показывает %d строк, want 1 (устаревшие скрыты): %s", len(resp.Assignments), w.Body.String())
	}
	a := resp.Assignments[0]
	if a.Email != "client" || a.NodeName != "Whisper" || a.NodeCountry != "NL" || a.Variant {
		t.Fatalf("строка карты: %+v", a)
	}
}

