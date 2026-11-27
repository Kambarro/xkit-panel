package store

import (
 "database/sql"
 "encoding/json"
)

// Squad — группа доступа/тариф (P1 #8, Remnawave internal squads).
// группа = набор inbounds (протоколов) + дефолтные лимиты для клиентов группы.
type Squad struct {
 ID         string   `json:"id"`
 Name       string   `json:"name"`
 Inbounds   []string `json:"inbounds"` // tag'и протоколов
 Country    string   `json:"country"`
 HWIDLimit  int      `json:"hwid_limit"`
 QuotaGB    int      `json:"quota_gb"`
 ExpiryDays int      `json:"expiry_days"`
 Autorenew  string   `json:"autorenew_mode"`
 AutoAdd    bool     `json:"auto_add"` // новые auto_add-протоколы добавляются в набор группы
}

func (s *Store) UpsertSquad(sq Squad) error {
 ib,_:=json.Marshal(sq.Inbounds)
 aa:=0; if sq.AutoAdd{aa=1}
 _,err:=s.db.Exec(`INSERT INTO squads(id,name,inbounds,country,hwid_limit,quota_gb,expiry_days,autorenew_mode,auto_add)
  VALUES(?,?,?,?,?,?,?,?,?)
  ON CONFLICT(id) DO UPDATE SET name=excluded.name,inbounds=excluded.inbounds,country=excluded.country,
  hwid_limit=excluded.hwid_limit,quota_gb=excluded.quota_gb,expiry_days=excluded.expiry_days,autorenew_mode=excluded.autorenew_mode,auto_add=excluded.auto_add`,
  sq.ID,sq.Name,string(ib),sq.Country,sq.HWIDLimit,sq.QuotaGB,sq.ExpiryDays,sq.Autorenew,aa)
 return err
}

func (s *Store) GetSquad(id string) (*Squad,error) {
 var sq Squad; var ib string; var aa int
 err:=s.db.QueryRow(`SELECT id,name,inbounds,country,hwid_limit,quota_gb,expiry_days,autorenew_mode,auto_add FROM squads WHERE id=?`,id).
  Scan(&sq.ID,&sq.Name,&ib,&sq.Country,&sq.HWIDLimit,&sq.QuotaGB,&sq.ExpiryDays,&sq.Autorenew,&aa)
 if err==sql.ErrNoRows{return nil,nil}
 if err!=nil{return nil,err}
 json.Unmarshal([]byte(ib),&sq.Inbounds)
 sq.AutoAdd=aa==1
 return &sq,nil
}

func (s *Store) AllSquads() ([]Squad,error) {
 rows,err:=s.db.Query(`SELECT id,name,inbounds,country,hwid_limit,quota_gb,expiry_days,autorenew_mode,auto_add FROM squads ORDER BY name`)
 if err!=nil{return nil,err}
 defer rows.Close()
 var out []Squad
 for rows.Next(){
  var sq Squad; var ib string; var aa int
  if err:=rows.Scan(&sq.ID,&sq.Name,&ib,&sq.Country,&sq.HWIDLimit,&sq.QuotaGB,&sq.ExpiryDays,&sq.Autorenew,&aa);err!=nil{return nil,err}
  json.Unmarshal([]byte(ib),&sq.Inbounds)
  sq.AutoAdd=aa==1
  out=append(out,sq)
 }
 return out,rows.Err()
}

func (s *Store) DeleteSquad(id string) error {
 // клиенты группы → squad_id='' (не удаляем клиентов)
 s.db.Exec(`UPDATE clients SET squad_id='' WHERE squad_id=?`,id)
 _,err:=s.db.Exec(`DELETE FROM squads WHERE id=?`,id)
 return err
}

// AssignSquad — назначить клиента в группу (применяет дефолты группы: hwid/quota/expiry/autorenew).
func (s *Store) AssignSquad(email,squadID string) error {
 _,err:=s.db.Exec(`UPDATE clients SET squad_id=? WHERE email=?`,squadID,email)
 return err
}

// SquadClients — клиенты группы.
func (s *Store) SquadClients(squadID string) ([]string,error) {
 rows,err:=s.db.Query(`SELECT email FROM clients WHERE squad_id=?`,squadID)
 if err!=nil{return nil,err}
 defer rows.Close()
 var out []string
 for rows.Next(){var e string;rows.Scan(&e);out=append(out,e)}
 return out,rows.Err()
}
