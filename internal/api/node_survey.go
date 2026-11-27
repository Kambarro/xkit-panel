package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kambarro/xkit-panel/internal/tunnel"
	"github.com/kambarro/xkit-panel/internal/xray"
	router "github.com/xtls/xray-core/app/router"
)

// Survey транспортов каскада ноды (порт legacy XKIT «опрос транспортов», owner-approved).
// Прогоняет ВСЕ рабочие транспорты (tcp-reality/xhttp-reality/ws-tls/hysteria2/awg;
// grpc-tls deprecated в Xray 26.x — НЕ предлагаем) через полный путь мастер→нода→интернет:
// на ноде временный HTTP-сервер с 16 MiB payload, на мастере временный dokodemo-door
// inbound + routing-правило → outbound ноды, curl меряет RTT и скорость скачивания.
// КРИТИЧНО (владелец): после КАЖДОГО кандидата — полная уборка тестовых артефактов
// (inbound+правило мастера, сервер+файл+ufw ноды), после survey — восстановление
// ОРИГИНАЛЬНОГО транспорта (точные ключи/uuid/sni из tunnel_cfg, без перегенерации).
//
// УРОК (live-проверка MSK): AppendRules кладёт правило в КОНЕЦ списка — ПОСЛЕ
// catch-all port:0-65535→direct, который перехватывает трафик раньше (правило мертво).
// Поэтому временное правило вставляется ПЕРЕД catch-all через ReplaceRules со снапшотом
// routing из config.json (geo-правила RU-direct и балансировщики сохраняются).

// surveyPayloadBytes — 16 MiB (owner approved; legacy XKIT мерял 8 MiB).
const surveyPayloadBytes = 16 * 1024 * 1024

// surveyCandidates — все транспорты каскада для опроса. grpc-tls исключён (deprecated).
var surveyCandidates = []string{"tcp-reality", "xhttp-reality", "ws-tls", "hysteria2", "awg"}

// SurveyResult — результат одного кандидата.
type SurveyResult struct {
	Transport    string  `json:"transport"`
	OK           bool    `json:"ok"`
	RTTMs        float64 `json:"rtt_ms"`
	DownloadMbps float64 `json:"download_mbps"`
	Error        string  `json:"error,omitempty"`
}

// SurveyReport — отчёт survey ноды (хранится в settings survey_<nodeID> + память).
type SurveyReport struct {
	NodeID     string         `json:"node_id"`
	StartedAt  int64          `json:"started_at"`
	FinishedAt int64          `json:"finished_at,omitempty"`
	Running    bool           `json:"running"`
	Done       bool           `json:"done"`
	Progress   string         `json:"progress"`
	Results    []SurveyResult `json:"results"`
	Best       string         `json:"best,omitempty"`
	Original   string         `json:"original_transport"`
	Restored   bool           `json:"restored"`
	Error      string         `json:"error,omitempty"`
}

var (
	surveyMu   sync.Mutex
	surveyJobs = map[string]*SurveyReport{} // nodeID → отчёт (живой job или последний)
)

// surveyRunning — идёт ли survey этой ноды (guard для смены транспорта/повторного запуска).
func surveyRunning(nodeID string) bool {
	surveyMu.Lock()
	defer surveyMu.Unlock()
	j := surveyJobs[nodeID]
	return j != nil && j.Running
}

// bestTransport — лучший РАБОЧИЙ транспорт: максимум download_mbps, при равенстве — меньше RTT.
// Нерабочие кандидаты не участвуют. Пустая строка если рабочих нет.
func bestTransport(results []SurveyResult) string {
	best := ""
	var bestSpeed, bestRTT float64
	for _, r := range results {
		if !r.OK {
			continue
		}
		if best == "" || r.DownloadMbps > bestSpeed || (r.DownloadMbps == bestSpeed && r.RTTMs < bestRTT) {
			best, bestSpeed, bestRTT = r.Transport, r.DownloadMbps, r.RTTMs
		}
	}
	return best
}

// POST /api/nodes/survey {id} — запустить survey транспортов (background job).
func (s *Server) surveyStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "id обязателен", 400)
		return
	}
	var host, health, tr, tunnelCfg string
	var port int
	if err := s.store.DB().QueryRow(`SELECT host,port,health,tunnel,tunnel_cfg FROM nodes WHERE id=?`, req.ID).Scan(&host, &port, &health, &tr, &tunnelCfg); err != nil {
		http.Error(w, "нода не найдена", 404)
		return
	}
	if health == "down" {
		http.Error(w, "нода down — survey невозможен (сначала восстановите ноду)", 409)
		return
	}
	if tr == "" {
		http.Error(w, "нода без xray-каскада — survey транспортов неприменим", 400)
		return
	}
	if s.xray == nil {
		http.Error(w, "xray gRPC недоступен на мастере", 503)
		return
	}
	surveyMu.Lock()
	if j := surveyJobs[req.ID]; j != nil && j.Running {
		surveyMu.Unlock()
		http.Error(w, "survey этой ноды уже запущен", 409)
		return
	}
	report := &SurveyReport{NodeID: req.ID, StartedAt: time.Now().Unix(), Running: true,
		Progress: "0/" + strconv.Itoa(len(surveyCandidates)), Original: tr, Results: []SurveyResult{}}
	surveyJobs[req.ID] = report
	surveyMu.Unlock()
	s.store.AddEvent("node_survey", "info", fmt.Sprintf("нода %s: survey транспортов запущен (%d кандидатов, оригинал %s)", req.ID, len(surveyCandidates), tr), fmt.Sprintf(`{"node":%q}`, req.ID))
	go s.runSurvey(req.ID, host, port, tr, tunnelCfg, report)
	writeJSON(w, map[string]any{"started": true, "id": req.ID, "total": len(surveyCandidates)})
}

// GET /api/nodes/survey?id= — прогресс + результаты (UI polling).
func (s *Server) surveyStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id обязателен", 400)
		return
	}
	surveyMu.Lock()
	j := surveyJobs[id]
	var snapshot *SurveyReport
	if j != nil {
		cp := *j
		cp.Results = append([]SurveyResult{}, j.Results...)
		snapshot = &cp
	}
	surveyMu.Unlock()
	if snapshot == nil {
		// после рестарта панели — последний отчёт из settings
		if raw := s.store.GetSetting("survey_"+id, ""); raw != "" {
			var rep SurveyReport
			if json.Unmarshal([]byte(raw), &rep) == nil {
				rep.Running = false
				writeJSON(w, rep)
				return
			}
		}
		writeJSON(w, map[string]any{"running": false, "done": false, "results": []SurveyResult{}})
		return
	}
	writeJSON(w, snapshot)
}

// runSurvey — тело background job. Оригинальные параметры сохраняются ОДИН раз в начале;
// каждый кандидат: apply → bench → cleanup (defer-гарантия); в конце — restore оригинала.
func (s *Server) runSurvey(nodeID, host string, port int, origTr, origTunnelCfg string, report *SurveyReport) {
	// финализация: отчёт в settings + событие (даже при панике)
	defer func() {
		if rec := recover(); rec != nil {
			surveyMu.Lock()
			report.Error = fmt.Sprintf("panic: %v", rec)
			report.Running = false
			report.Done = true
			surveyMu.Unlock()
			s.store.AddEvent("node_survey", "error", fmt.Sprintf("нода %s: survey panic: %v", nodeID, rec), fmt.Sprintf(`{"node":%q}`, nodeID))
		}
		surveyMu.Lock()
		report.FinishedAt = time.Now().Unix()
		report.Running = false
		report.Done = true
		report.Best = bestTransport(report.Results)
		b, _ := json.Marshal(report)
		surveyMu.Unlock()
		s.store.SetSetting("survey_"+nodeID, string(b))
		s.store.AddEvent("node_survey", "ok", fmt.Sprintf("нода %s: survey завершён (лучший: %s, восстановлен: %v)", nodeID, report.Best, report.Restored), fmt.Sprintf(`{"node":%q}`, nodeID))
	}()

	// оригинальные параметры — ОДИН раз, точные ключи из tunnel_cfg (без перегенерации)
	origParams := s.paramsFromCfg(origTr, host, port, origTunnelCfg)
	origParams.MTU = s.store.NodeMTU(nodeID)
	origLastGood := s.store.NodeLastGoodCfg(nodeID)
	// AWG-каскад ноды до survey (если был — восстановим после, не потеряем)
	cascadesMu.Lock()
	awgWasRunning := cascades[nodeID] != nil && cascades[nodeID].running
	var awgPort int
	if c := cascades[nodeID]; c != nil {
		awgPort = c.nodePort
	}
	cascadesMu.Unlock()

	restoreOriginal := func() bool {
		if origTr == "awg" {
			// оригинал — AWG-каскад: xray-конфиг ноды вернём из last_good (если был),
			// outbound мастера восстановит startAWGCascade (SOCKS). applyTunnelBothEnds
			// для "awg" неприменим (это не xray-транспорт).
			if origLastGood != "" {
				s.deliverNodeConfig(nodeID, host, origLastGood)
				s.store.SetNodeLastGoodCfg(nodeID, origLastGood)
			}
			s.store.DB().Exec(`UPDATE nodes SET tunnel=?, tunnel_cfg=? WHERE id=?`, origTr, origTunnelCfg, nodeID)
			if _, e := s.startAWGCascade(nodeID, host, awgPort); e != nil {
				s.store.AddEvent("survey_restore_failed", "error", fmt.Sprintf("нода %s: AWG-каскад не восстановлен: %v", nodeID, e), fmt.Sprintf(`{"node":%q}`, nodeID))
				return false
			}
			s.store.AddEvent("node_survey", "ok", fmt.Sprintf("нода %s: оригинальный AWG-каскад восстановлен", nodeID), fmt.Sprintf(`{"node":%q}`, nodeID))
			return true
		}
		// xray-транспорт оригинала: точные uuid/sni/ключи из сохранённого tunnel_cfg
		err := s.applyTunnelBothEnds(nodeID, host, origParams)
		if err == nil {
			s.store.DB().Exec(`UPDATE nodes SET tunnel=?, tunnel_cfg=? WHERE id=?`, origTr, origTunnelCfg, nodeID)
			nodeProto := "tcp"
			if origParams.Transport == tunnel.Hysteria2 {
				nodeProto = "udp"
			}
			s.sshToNode(host, fmt.Sprintf("ufw allow %d/%s comment 'XKIT:node-tunnel' >/dev/null 2>&1; echo OK", port, nodeProto))
			s.syncFirewall()
		} else {
			// retry once (директива: restore обязателен)
			time.Sleep(2 * time.Second)
			err = s.applyTunnelBothEnds(nodeID, host, origParams)
			if err == nil {
				s.store.DB().Exec(`UPDATE nodes SET tunnel=?, tunnel_cfg=? WHERE id=?`, origTr, origTunnelCfg, nodeID)
			}
		}
		if err != nil {
			s.store.AddEvent("survey_restore_failed", "error", fmt.Sprintf("нода %s: НЕ восстановлен оригинальный транспорт %s: %v", nodeID, origTr, err), fmt.Sprintf(`{"node":%q}`, nodeID))
			return false
		}
		// AWG-каскад был запущен до survey — переподнять (оригинал мог быть awg)
		if awgWasRunning {
			if _, e := s.startAWGCascade(nodeID, host, awgPort); e != nil {
				s.store.AddEvent("node_survey", "warn", fmt.Sprintf("нода %s: AWG-каскад не восстановлен: %v", nodeID, e), fmt.Sprintf(`{"node":%q}`, nodeID))
			}
		}
		s.store.AddEvent("node_survey", "ok", fmt.Sprintf("нода %s: оригинальный транспорт %s восстановлен", nodeID, origTr), fmt.Sprintf(`{"node":%q}`, nodeID))
		return true
	}
	// defer-гарантия: restore даже если кандидаты упали/паника выше
	defer func() {
		surveyMu.Lock()
		report.Progress = "restore"
		surveyMu.Unlock()
		ok := restoreOriginal()
		surveyMu.Lock()
		report.Restored = ok
		surveyMu.Unlock()
	}()

	for i, cand := range surveyCandidates {
		surveyMu.Lock()
		report.Progress = fmt.Sprintf("%d/%d %s", i+1, len(surveyCandidates), cand)
		surveyMu.Unlock()
		res := s.surveyOneCandidate(nodeID, host, port, cand)
		surveyMu.Lock()
		report.Results = append(report.Results, res)
		surveyMu.Unlock()
	}
}

// surveyOneCandidate — применить кандидат, замерить полный путь, убрать артефакты.
// Cleanup гарантирован defer'ом даже при ошибке/таймауте замера.
func (s *Server) surveyOneCandidate(nodeID, host string, port int, cand string) SurveyResult {
	res := SurveyResult{Transport: cand}
	if cand == "awg" {
		s.surveyAWGCandidate(nodeID, host, &res)
		return res
	}
	// 1) применить транспорт-кандидат на ОБА конца (тот же код-путь что ручная смена)
	if err := s.applyTransport(nodeID, tunnel.Transport(cand)); err != nil {
		res.Error = "apply: " + err.Error()
		return res
	}
	// 2) бенч полного пути + cleanup (defer — даже при ошибке)
	benchPort, cleanupBench, err := s.startNodeBenchServer(host)
	if err != nil {
		res.Error = "bench server: " + err.Error()
		return res
	}
	defer cleanupBench()
	s.measureThroughTunnel(nodeID, host, benchPort, &res)
	return res
}

// surveyAWGCandidate — AWG-кандидат. Если каскад уже запущен — меряем через его SOCKS
// напрямую (не пересоздаём). Если нет — временный каскад (существующий код startAWGCascade),
// замер, затем ПОЛНОЕ удаление (stop + DeleteAWGCascade + возврат outbound).
func (s *Server) surveyAWGCandidate(nodeID, host string, res *SurveyResult) {
	cascadesMu.Lock()
	existing := cascades[nodeID]
	cascadesMu.Unlock()
	temporary := existing == nil || !existing.running
	var c *awgCascade
	if temporary {
		var err error
		c, err = s.startAWGCascade(nodeID, host, 0)
		if err != nil {
			res.Error = "awg cascade: " + err.Error()
			// startAWGCascade мог частично подняться — гарантированная уборка
			s.stopAWGCascade(nodeID)
			s.store.DeleteAWGCascade(nodeID)
			s.restoreMasterOutboundXray(nodeID)
			return
		}
		defer func() {
			s.stopAWGCascade(nodeID)
			s.store.DeleteAWGCascade(nodeID)
			s.restoreMasterOutboundXray(nodeID)
		}()
	} else {
		c = existing
	}
	// бенч-сервер на ноде + замер через SOCKS каскада (полный путь мастер→AWG→нода→интернет)
	benchPort, cleanupBench, err := s.startNodeBenchServer(host)
	if err != nil {
		res.Error = "bench server: " + err.Error()
		return
	}
	defer cleanupBench()
	c.mu.Lock()
	socksPort := c.socksPort
	c.mu.Unlock()
	s.measureViaSOCKS(host, benchPort, socksPort, res)
}

// startNodeBenchServer — временный HTTP-сервер на ноде: 16 MiB random payload,
// python3 http.server на случайном высоком порту (0.0.0.0), ufw открыт временно.
// Возвращает порт + cleanup-функцию (kill сервера + rm файла + ufw delete).
// Cleanup идемпотентен и безопасен при частичном старте.
// УРОК: порт выбирается НА НОДЕ (bind :0), не на мастере — на ноде он мог быть занят.
func (s *Server) startNodeBenchServer(host string) (int, func(), error) {
	out, err := s.sshToNode(host, `python3 -c "import socket;s=socket.socket();s.bind(('0.0.0.0',0));print(s.getsockname()[1]);s.close()"`)
	if err != nil {
		return 0, nil, fmt.Errorf("node port pick: %v: %s", err, strings.TrimSpace(out))
	}
	benchPort, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || benchPort < 1024 || benchPort > 65535 {
		return 0, nil, fmt.Errorf("node port pick: некорректный порт %q", strings.TrimSpace(out))
	}
	dir := fmt.Sprintf("/tmp/xkit-survey-%d", benchPort)
	// cleanup регистрируем ДО старта — уберёт даже частично созданные артефакты.
	// УРОК: pkill -f 'http.server PORT' совпадает с командной строкой собственного
	// shell'а (текст паттерна внутри cmd) → убивает свою SSH-сессию. Bracket-трюк
	// '[h]ttp.server' не матчит литерал паттерна, но матчит реальный процесс.
	cleanup := func() {
		cmd := fmt.Sprintf(`pkill -f '[h]ttp.server %d' 2>/dev/null; rm -rf %s; ufw delete allow %d/tcp >/dev/null 2>&1; echo CLEANED`, benchPort, dir, benchPort)
		s.sshToNode(host, cmd)
	}
	// payload: 16 MiB random (os.urandom), сервер: python3 http.server bind 0.0.0.0
	setup := fmt.Sprintf(`mkdir -p %s && python3 -c "import os;open('%s/payload.bin','wb').write(os.urandom(%d))" && cd %s && (setsid nohup python3 -m http.server %d --bind 0.0.0.0 >/dev/null 2>&1 &) && ufw allow %d/tcp comment 'XKIT:survey-bench' >/dev/null 2>&1; sleep 1; curl -s -o /dev/null -w '%%{http_code}' --max-time 5 http://127.0.0.1:%d/payload.bin -r 0-0`, dir, dir, surveyPayloadBytes, dir, benchPort, benchPort, benchPort)
	out, err = s.sshToNode(host, setup)
	if err != nil || (!strings.Contains(out, "206") && !strings.Contains(out, "200")) {
		cleanup()
		return 0, nil, fmt.Errorf("bench server не поднялся: %v: %s", err, strings.TrimSpace(out))
	}
	return benchPort, cleanup, nil
}

// freeTCPPort — случайный свободный порт (net.Listen :0 pattern).
func freeTCPPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port, nil
}

// measureThroughTunnel — замер полного пути через xray-туннель ноды:
// временный dokodemo-door inbound на мастере (127.0.0.1:localPort → host:benchPort)
// + routing-правило inboundTag→outbound ноды ПЕРЕД catch-all, curl через локальный вход.
// Cleanup (RemoveInbound + RemoveRule) гарантирован defer'ом.
func (s *Server) measureThroughTunnel(nodeID, host string, benchPort int, res *SurveyResult) {
	localPort, err := freeTCPPort()
	if err != nil {
		res.Error = "local port: " + err.Error()
		return
	}
	tag := fmt.Sprintf("survey-%s-%d", nodeID, localPort)
	ruleTag := "survey:" + tag
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// cleanup мастера — defer (даже при ошибке AddRule/curl/таймауте)
	cleanupMaster := func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer ccancel()
		s.xray.RemoveUserRule(cctx, ruleTag)
		s.xray.RemoveInbound(cctx, tag)
	}
	defer cleanupMaster()
	// 1) временный dokodemo-door inbound (target = публичный адрес ноды:benchPort)
	ibJSON := fmt.Sprintf(`{"tag":%q,"listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door","settings":{"address":%q,"port":%d,"network":"tcp"}}`, tag, localPort, host, benchPort)
	if err := s.xray.AddInbound(ctx, ibJSON); err != nil {
		res.Error = "AddInbound: " + err.Error()
		return
	}
	// 2) routing-правило ПЕРЕД catch-all (УРОК: append → после catch-all → мертво).
	// Снапшот routing из config.json (RU-direct geo + per-user + catch-all + балансировщики),
	// вставляем survey-правило перед первым catch-all (port 0-65535 без ruleTag/user).
	if err := s.insertSurveyRule(ctx, ruleTag, tag, nodeID); err != nil {
		res.Error = "routing rule: " + err.Error()
		return
	}
	// 3) curl через локальный вход: RTT (starttransfer−connect) + скорость 16 MiB
	s.curlBench(fmt.Sprintf("http://127.0.0.1:%d/payload.bin", localPort), "", res)
}

// insertSurveyRule — вставить временное правило inboundTag→nodeID ПЕРЕД catch-all.
// ReplaceRules со снапшотом config.json: geo-правила (RU-direct) парсятся штатным
// парсером Xray, балансировщики сохраняются. Если снапшот недоступен — ОШИБКА
// (append после catch-all замерил бы direct-путь мимо туннеля — ложный результат).
func (s *Server) insertSurveyRule(ctx context.Context, ruleTag, inboundTag, nodeID string) error {
	surveyRule := &router.RoutingRule{
		RuleTag:    ruleTag,
		InboundTag: []string{inboundTag},
		TargetTag:  &router.RoutingRule_Tag{Tag: nodeID},
	}
	data, err := os.ReadFile("/usr/local/etc/xray/config.json")
	if err != nil {
		return fmt.Errorf("master config недоступен: %w", err)
	}
	var cfg map[string]any
	if json.Unmarshal(data, &cfg) != nil {
		return fmt.Errorf("master config не парсится")
	}
	routing, _ := cfg["routing"].(map[string]any)
	if routing == nil {
		return fmt.Errorf("master config без routing-секции")
	}
	routingJSON, _ := json.Marshal(routing)
	parsed, err := xray.ParseRoutingConfig(string(routingJSON))
	if err != nil {
		return fmt.Errorf("parse routing: %w", err)
	}
	rules := parsed.Rule
	// вставка ПЕРЕД первым catch-all (port 0-65535, без user/inboundTag/ruleTag)
	idx := len(rules)
	for i, r := range rules {
		if isCatchAllRule(r) {
			idx = i
			break
		}
	}
	newRules := make([]*router.RoutingRule, 0, len(rules)+1)
	newRules = append(newRules, rules[:idx]...)
	newRules = append(newRules, surveyRule)
	newRules = append(newRules, rules[idx:]...)
	return s.xray.ReplaceRules(ctx, newRules, parsed.BalancingRule)
}

// isCatchAllRule — catch-all: port 0-65535 без user/inboundTag/domain/ip (перехватывает всё).
func isCatchAllRule(r *router.RoutingRule) bool {
	if r == nil || r.PortList == nil || len(r.PortList.Range) == 0 {
		return false
	}
	if len(r.UserEmail) > 0 || len(r.InboundTag) > 0 || len(r.Domain) > 0 || len(r.Ip) > 0 {
		return false
	}
	for _, pr := range r.PortList.Range {
		if pr.From == 0 && pr.To == 65535 {
			return true
		}
	}
	return false
}

// measureViaSOCKS — замер через SOCKS5 AWG-каскада (curl --socks5-hostname).
func (s *Server) measureViaSOCKS(host string, benchPort, socksPort int, res *SurveyResult) {
	url := fmt.Sprintf("http://%s:%d/payload.bin", host, benchPort)
	s.curlBench(url, fmt.Sprintf("127.0.0.1:%d", socksPort), res)
}

// curlBench — curl замера: RTT ≈ time_starttransfer − time_connect, скорость = speed_download.
// socksAddr != "" → --socks5-hostname (AWG). --max-time 30 на 16 MiB (owner: ~40s на кандидата).
func (s *Server) curlBench(url, socksAddr string, res *SurveyResult) {
	args := []string{"-s", "-o", "/dev/null", "--max-time", "30",
		"-w", "%{time_connect} %{time_starttransfer} %{speed_download} %{http_code} %{size_download}", url}
	if socksAddr != "" {
		args = append([]string{"--socks5-hostname", socksAddr}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "curl", args...).Output()
	if err != nil {
		res.Error = "curl: " + err.Error()
		return
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 5 {
		res.Error = "curl output: " + string(out)
		return
	}
	connect, _ := strconv.ParseFloat(fields[0], 64)
	starttransfer, _ := strconv.ParseFloat(fields[1], 64)
	speed, _ := strconv.ParseFloat(fields[2], 64)
	code := fields[3]
	size, _ := strconv.ParseFloat(fields[4], 64)
	if code != "200" {
		res.Error = "http " + code
		return
	}
	if size < surveyPayloadBytes {
		res.Error = fmt.Sprintf("неполная загрузка: %.0f/%d байт", size, surveyPayloadBytes)
		return
	}
	res.OK = true
	res.RTTMs = (starttransfer - connect) * 1000
	if res.RTTMs < 0 {
		res.RTTMs = 0
	}
	res.DownloadMbps = speed * 8 / 1e6
}
