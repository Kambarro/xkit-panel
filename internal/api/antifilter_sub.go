package api

import (
	"net/http"

	"github.com/kambarro/xkit-panel/internal/subscription"
)

// ServeAntifilterBlocked — blocked-наборы для клиентских подписок (без auth,
// случайный subId как у подписки). Вызывается из main.go /<prefix>/<id>/antifilter/<kind>.
func (s *Server) ServeAntifilterBlocked(w http.ResponseWriter, r *http.Request, subID, kind string) {
	var email string
	err := s.store.DB().QueryRow(`SELECT email FROM clients WHERE sub_id=? AND enabled=1`, subID).Scan(&email)
	if err != nil || s.afMgr == nil {
		http.NotFound(w, r) // анти-пробинг: мусор → 404 как decoy
		return
	}
	s.afMgr.ServeBlocked(w, r, kind)
}

// AntifilterSubscriptionRules — mode-aware набор для генераторов подписок.
// Возвращает nil если режим не antifilter (генераторы остаются дефолтными).
func (s *Server) AntifilterSubscriptionRules(hasNodes bool) *subscription.AntifilterRules {
	if s.store.EffectiveRoutingMode(hasNodes) != "antifilter" || s.afMgr == nil || !s.afMgr.Ready() {
		return nil
	}
	ar := subscription.AntifilterFromAlways(s.store.AlwaysRules())
	if ds, err := s.afMgr.BlockedDomains(); err == nil {
		ar.BlockedDomains = ds
	}
	return &ar
}