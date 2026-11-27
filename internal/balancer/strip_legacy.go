package balancer

import (
	"encoding/json"
	"log"
	"os"
	"strings"
)

// StripLegacyCountryRules — миграция упрощения (решение владельца): cs/vlessRoute-
// слой удалён, страна клиента = clients.country. При старте панели вырезаем из
// config.json мастера легаси country-select правила (cs:/cspd:/cspi:) — старые
// подписки со страновыми UUID остаются auth-валидными (ProcessUUID обнулял байты
// 6-7), их трафик попадает в базовое per-user правило. Вызывать ДО первого
// syncAllRules; идемпотентно (нет легаси — файл не трогаем). Возвращает число снятых.
func StripLegacyCountryRules() int {
	data, err := os.ReadFile(masterConfigPath)
	if err != nil {
		return 0
	}
	var cfg map[string]any
	if json.Unmarshal(data, &cfg) != nil {
		return 0
	}
	r, _ := cfg["routing"].(map[string]any)
	if r == nil {
		return 0
	}
	rules, _ := r["rules"].([]any)
	var kept []any
	removed := 0
	for _, rl := range rules {
		rm, ok := rl.(map[string]any)
		if !ok {
			kept = append(kept, rl)
			continue
		}
		tag, _ := rm["ruleTag"].(string)
		if strings.HasPrefix(tag, "cs:") || strings.HasPrefix(tag, "cspd:") || strings.HasPrefix(tag, "cspi:") {
			removed++
			continue
		}
		// легаси vlessRoute в per-user правилах без cs-тега (ручные правки) — тоже снимаем
		if _, has := rm["vlessRoute"]; has {
			if users, _ := rm["user"].([]any); len(users) > 0 {
				removed++
				continue
			}
		}
		kept = append(kept, rl)
	}
	if removed == 0 {
		return 0
	}
	r["rules"] = kept
	cfg["routing"] = r
	out, _ := json.MarshalIndent(cfg, "", " ")
	if err := os.WriteFile(masterConfigPath, out, 0644); err != nil {
		log.Printf("strip cs-правил: запись config.json: %v", err)
		return 0
	}
	log.Printf("миграция: снято %d легаси cs/vlessRoute правил из config.json", removed)
	return removed
}