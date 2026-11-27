package store

// IP-лимит per-client (P1 #11).
func (s *Store) SetClientIPLimit(email string, limit int) error {
 _,err:=s.db.Exec(`UPDATE clients SET ip_limit=? WHERE email=?`,limit,email)
 return err
}

func (s *Store) ClientIPLimit(email string) int {
 var n int
 s.db.QueryRow(`SELECT ip_limit FROM clients WHERE email=?`,email).Scan(&n)
 return n
}
