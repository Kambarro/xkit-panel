package api

import (
	"fmt"
	"net/http"

	"github.com/kambarro/xkit-panel/internal/subscription"
)

// Happ cryptoLink (P1 #15): зашифрованная ссылка подписки для клиента Happ.
// GET /api/clients/crypto-link?email=... → {link, available}.
// Скрывает адрес подписки — пользователь не может посмотреть/расшарить конфиги.

func (s *Server) clientCryptoLink(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cl, err := s.store.GetClient(email)
	if err != nil || cl == nil {
		http.Error(w, "client not found", 404); return
	}
	if !subscription.HappCryptoAvailable() {
		writeJSON(w, map[string]any{"available": false, "link": ""}); return
	}
	subURL := fmt.Sprintf("https://%s/%s/%s", s.domain, s.store.SubPrefix(), cl.SubID)
	link, err := subscription.HappCryptoLink(subURL)
	if err != nil {
		http.Error(w, err.Error(), 500); return
	}
	writeJSON(w, map[string]any{"available": true, "link": link, "sub_url": subURL})
}