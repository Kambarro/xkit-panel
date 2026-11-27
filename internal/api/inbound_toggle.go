package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/kambarro/xkit-panel/internal/store"
)

// toggleInbound — POST /api/inbounds/toggle: переключатель протокола (вкл/выкл на лету).
// УРОК (владелец): протоколы — просто переключатели в панели; подписки меняются динамически.
// enabled=false → RemoveInbound горячо (порт закрывается, подписка больше не отдаёт протокол).
// enabled=true → AddInbound горячо + AddUser всех клиентов (чтоб подписка сразу работала).
func (s *Server) toggleInbound(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tag     string `json:"tag"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Tag == "" {
		http.Error(w, "tag required", 400); return
	}
	if body.Tag == "api-in" || body.Tag == "api" {
		http.Error(w, "нельзя переключать служебный api-inbound", 400); return
	}
	// УРОК: vless-reality:443 — якорь маскировки. Нельзя выключить inbound.
	// Переключатель для него = in_sub (скрыть/показать в подписке), inbound ВСЕГДА работает.
	if body.Tag == "vless-reality" {
		if err := s.store.SetInboundInSub(body.Tag, body.Enabled); err != nil {
			http.Error(w, err.Error(), 500); return
		}
		state := "скрыт из подписок"
		if body.Enabled { state = "виден в подписках" }
		s.store.AddEvent("inbound_toggle", "ok", fmt.Sprintf("vless-reality %s (inbound всегда работает — якорь маскировки)", state), "{}")
		writeJSON(w, map[string]any{"ok": true, "tag": body.Tag, "enabled": true, "in_sub": body.Enabled})
		return
	}
	ib, _ := s.store.GetInbound(body.Tag)
	if ib == nil { http.Error(w, "inbound not found", 404); return }

	if s.xray != nil {
		if body.Enabled {
			// УРОК (QA BUG-3): SetInboundEnabled ДО gRPC-восстановления — иначе
			// EffectiveProtocols («все включённые») не включает сам inbound →
			// ProtocolAllowed=false для всех → hy2 clients[]/ws users пусты.
			if err := s.store.SetInboundEnabled(body.Tag, true); err != nil {
				http.Error(w, err.Error(), 500); return
			}
			// hy2: пересоздание с clients[] из БД (аудит #2) — один код-путь
			if ib.Protocol == "hysteria2" || ib.Protocol == "hysteria" {
				if _, _, err := s.syncHysteria2Access(r.Context(), ib); err != nil {
					s.store.SetInboundEnabled(body.Tag, false) // откат: не оставлять enabled без inbound
					http.Error(w, "hy2 sync: "+err.Error(), 500); return
				}
			} else {
				// включить: AddInbound + все клиенты.
				// УРОК (QA): если inbound уже жив в xray (RemoveInbound ранее не сработал) —
				// AddInbound на существующий тег зависает/ошибается. Сначала идемпотентный Remove.
				_ = s.xray.RemoveInbound(r.Context(), body.Tag)
				inboundJSON := buildInboundJSON(*ib)
				if err := s.xray.AddInbound(r.Context(), inboundJSON); err != nil {
					s.store.SetInboundEnabled(body.Tag, false) // откат
					http.Error(w, "gRPC AddInbound: "+err.Error(), 500); return
				}
				// добавим всех enabled клиентов в этот inbound (горячо)
				s.addClientsToInbound(r, *ib)
			}
		} else {
			// выключить: RemoveInbound (порт закрывается).
			// УРОК (QA): ErrNoClue/"not enough information"/"not found" = inbound уже отсутствует
			// в живом xray (например после рестарта xray) — это НЕ ошибка, идемпотентно.
			if err := s.xray.RemoveInbound(r.Context(), body.Tag); err != nil {
				es := err.Error()
				if !strings.Contains(es, "not enough information") && !strings.Contains(es, "not found") {
					s.store.AddEvent("inbound_toggle", "warn", "gRPC RemoveInbound: "+es, "{}")
				}
			}
			if err := s.store.SetInboundEnabled(body.Tag, false); err != nil {
				http.Error(w, err.Error(), 500); return
			}
		}
	} else {
		if err := s.store.SetInboundEnabled(body.Tag, body.Enabled); err != nil {
			http.Error(w, err.Error(), 500); return
		}
	}
	state := "выключен"
	if body.Enabled { state = "включён" }
	// auto_add: новый включённый протокол с auto_add=1 добавляется в группы с auto_add=1.
	// Клиенты без override/группы получают все включённые автоматически (effective set).
	if body.Enabled && s.store.InboundAutoAdd(body.Tag) {
		s.store.AddProtocolToAutoAddSquads(body.Tag)
	}
	s.store.AddEvent("inbound_toggle", "ok", fmt.Sprintf("протокол %s %s (подписки обновятся на лету)", body.Tag, state), "{}")
	s.syncFirewall() // автоматика UFW: вкл → порт открыт, выкл → закрыт
	writeJSON(w, map[string]any{"ok": true, "tag": body.Tag, "enabled": body.Enabled})
}

// addClientsToInbound — добавляет всех enabled клиентов в inbound (при включении протокола).
// УРОК (QA-дедлок): MaxOpenConns(1) — НЕЛЬЗЯ ProtocolAllowed (вложенный Query) пока открыт rows.
// Сначала собираем клиентов в срез (rows.Close), потом фильтруем/добавляем.
func (s *Server) addClientsToInbound(r *http.Request, ib store.Inbound) {
	if s.xray == nil { return }
	// hy2: clients[] пересозданием (аудит #2) — AddUser не персистится в settings
	if ib.Protocol == "hysteria2" || ib.Protocol == "hysteria" {
		if _, _, err := s.syncHysteria2Access(r.Context(), &ib); err != nil {
			s.store.AddEvent("inbound_toggle", "warn", fmt.Sprintf("hy2 sync %s: %v", ib.Tag, err), "{}")
		}
		return
	}
	type cl struct{ email, uuid string }
	var clients []cl
	rows, err := s.store.DB().Query(`SELECT email,uuid FROM clients WHERE enabled=1`)
	if err != nil { return }
	for rows.Next() {
		var c cl
		rows.Scan(&c.email, &c.uuid)
		clients = append(clients, c)
	}
	rows.Close()
	for _, c := range clients {
		// вариант B: добавляем только клиентов, которым разрешён этот протокол
		if !s.store.ProtocolAllowed(c.email, ib.Tag) { continue }
		flow := ""
		if ib.Protocol == "vless" && (ib.Network == "tcp" || ib.Network == "") && (ib.Security == "reality" || ib.Security == "tls") {
			flow = "xtls-rprx-vision"
		}
		if userProto(ib.Protocol) {
			if err := s.xray.AddUserProto(r.Context(), ib.Tag, c.email, c.uuid, flow, ib.Protocol); err != nil {
				s.store.AddEvent("inbound_toggle", "warn", fmt.Sprintf("AddUser %s в %s: %v", c.email, ib.Tag, err), "{}")
			}
		}
		// hysteria: клиенты в settings JSON (пароль) — добавляются при создании inbound
	}
}

// setClientCountry — POST /api/clients/country: закрепить предпочтительную страну клиента.
// УРОК (владелец): варианты закрепления стран в панели; подписка отдаёт предпочтительную первой.
func (s *Server) setClientCountry(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email   string `json:"email"`
		Country string `json:"country"` // "" = авто (без закрепления)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		http.Error(w, "email required", 400); return
	}
	// УРОК (QA BUG-6): несуществующий клиент → 404 (было 200 ok + warn FK в журнале).
	if cl, _ := s.store.GetClient(body.Email); cl == nil {
		http.Error(w, "client not found", 404); return
	}
	// единая точка смены страны: валидация (канон + живая нода), запись, аудит.
	// Админский путь — без rate-limit (minInterval=0).
	code, cerr := s.store.ChangeClientCountry(body.Email, body.Country, 0, "admin")
	if errors.Is(cerr, store.ErrCountryUnavailable) {
		http.Error(w, "нет нод в стране "+body.Country, 400); return
	}
	if cerr != nil {
		http.Error(w, cerr.Error(), 500); return
	}
	country := strings.TrimSpace(body.Country)
	if country == "" || strings.EqualFold(country, "any") { country = "any" }
	// переназначим маршрут (если каскад); базовое правило пересобрать горячо
	// (QA BUG-1b: после смены страны базовое не должно залипать на старой ноде)
	if s.ctrl != nil {
		if _, err := s.ctrl.PushAssignment(r.Context(), body.Email, country); err != nil {
			s.store.AddEvent("client_country", "warn", fmt.Sprintf("назначение %s: %v", body.Email, err), "{}")
		}
	}
	writeJSON(w, map[string]any{"ok": true, "email": body.Email, "country": country, "country_code": code})
}

// availableCountries — GET /api/countries: доступные страны мастера (из нод, код — канон).
func (s *Server) availableCountries(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.DB().Query(`SELECT DISTINCT n.country, COALESCE(cc.code, n.country_code) FROM nodes n LEFT JOIN country_codes cc ON cc.country=n.country WHERE n.enabled=1 AND COALESCE(cc.code, n.country_code)>0 ORDER BY n.country`)
	if err != nil { http.Error(w, err.Error(), 500); return }
	defer rows.Close()
	type cc struct { Country string `json:"country"`; Code uint32 `json:"code"` }
	var out []cc
	for rows.Next() {
		var c cc
		rows.Scan(&c.Country, &c.Code)
		out = append(out, c)
	}
	if out == nil { out = []cc{} }
	writeJSON(w, out)
}

// enabledInboundSpecs — включённые протоколы мастера для подписок (динамически).
func (s *Server) enabledInboundSpecs() []inboundSpecForSub {
	ibs, err := s.store.AllInbounds()
	if err != nil { return nil }
	var out []inboundSpecForSub
	for _, ib := range ibs {
		if !ib.Enabled { continue }
		if ib.Tag == "api-in" || ib.Tag == "api" { continue }
		out = append(out, inboundSpecForSub{ib})
	}
	return out
}

type inboundSpecForSub struct{ ib store.Inbound }

// syncInboundUsers — синхронизирует клиентов во ВСЕХ включённых vless-inbound (после создания клиента).
func (s *Server) syncInboundUsers(r *http.Request, email, uuid string) {
	if s.xray == nil { return }
	ibs, _ := s.store.AllInbounds()
	for _, ib := range ibs {
		if !ib.Enabled || !userProto(ib.Protocol) { continue }
		if ib.Tag == "api-in" || ib.Tag == "api" { continue }
		// hy2: доступ пересозданием с clients[] (аудит #2, персист в БД)
		if ib.Protocol == "hysteria2" || ib.Protocol == "hysteria" {
			if _, _, err := s.syncHysteria2Access(r.Context(), &ib); err != nil {
				s.store.AddEvent("client_sync", "warn", fmt.Sprintf("hy2 sync %s: %v", ib.Tag, err), "{}")
			}
			continue
		}
		// вариант B: новый клиент добавляется только в разрешённые протоколы (effective set)
		if !s.store.ProtocolAllowed(email, ib.Tag) { continue }
		flow := ""
		if (ib.Network == "tcp" || ib.Network == "") && (ib.Security == "reality" || ib.Security == "tls") {
			flow = "xtls-rprx-vision"
		}
		if err := s.xray.AddUserProto(r.Context(), ib.Tag, email, uuid, flow, ib.Protocol); err != nil {
			// не фатально: inbound мог быть уже с этим юзером
			if !strings.Contains(err.Error(), "already") {
				s.store.AddEvent("client_sync", "warn", fmt.Sprintf("AddUser %s в %s: %v", email, ib.Tag, err), "{}")
			}
		}
	}
}