package api

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/kambarro/xkit-panel/internal/reality"
)

// realityScanAPI — поиск целей маскировки (этап B, порт сканера XKIT main).
// Асинхронный скан с прогрессом (тихий, 3 потока). Результат — кандидаты ДА/ДА+.

type scanJob struct {
	mu       sync.Mutex
	Running  bool   `json:"running"`
	Done     int    `json:"done"`
	Total    int    `json:"total"`
	Phase    string `json:"phase"`
	Results  []reality.Candidate `json:"results"`
	Error    string `json:"error"`
}

var currentScan = &scanJob{}

// scanStart — POST /api/reality/scan: запустить скан {targets: "CIDR или список"}.
func (s *Server) scanStart(w http.ResponseWriter, r *http.Request) {
	var body struct{ Targets string `json:"targets"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400); return
	}
	targets, err := reality.ExpandTargets(body.Targets)
	if err != nil {
		http.Error(w, err.Error(), 400); return
	}
	currentScan.mu.Lock()
	if currentScan.Running {
		currentScan.mu.Unlock()
		http.Error(w, "скан уже запущен", 409); return
	}
	currentScan.Running = true
	currentScan.Done = 0
	currentScan.Total = len(targets)
	currentScan.Phase = "tcp"
	currentScan.Results = nil
	currentScan.Error = ""
	currentScan.mu.Unlock()

	go func() {
		results := reality.Scan(r.Context(), targets, func(done, total int) {
			currentScan.mu.Lock()
			currentScan.Done = done
			currentScan.Total = total
			currentScan.mu.Unlock()
		})
		currentScan.mu.Lock()
		currentScan.Results = results
		currentScan.Running = false
		currentScan.Phase = "done"
		currentScan.mu.Unlock()
		s.store.AddEvent("reality_scan", "ok", "скан целей маскировки завершён", "{}")
	}()
	writeJSON(w, map[string]any{"ok": true, "targets": len(targets)})
}

// scanStatus — GET /api/reality/scan: прогресс + результаты (кандидаты).
func (s *Server) scanStatus(w http.ResponseWriter, r *http.Request) {
	currentScan.mu.Lock()
	defer currentScan.mu.Unlock()
	writeJSON(w, map[string]any{
		"running": currentScan.Running,
		"done": currentScan.Done,
		"total": currentScan.Total,
		"phase": currentScan.Phase,
		"error": currentScan.Error,
		"candidates": reality.Candidates(currentScan.Results),
		"all_count": len(currentScan.Results),
	})
}