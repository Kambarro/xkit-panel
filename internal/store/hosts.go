package store

import "database/sql"

// MasterHost — рекламная точка входа мастера (P1 #10, CDN-фронтинг/per-host SNI).
type MasterHost struct {
 ID       int    `json:"id"`
 Address  string `json:"address"`
 Port     int    `json:"port"`
 SNI      string `json:"sni"`
 Label    string `json:"label"`
 Priority int    `json:"priority"`
 Enabled  bool   `json:"enabled"`
}

func (s *Store) AddMasterHost(h MasterHost) (int64,error) {
 en:=0; if h.Enabled{en=1}
 if h.Port==0{h.Port=443}
 res,err:=s.db.Exec(`INSERT INTO master_hosts(address,port,sni,label,priority,enabled) VALUES(?,?,?,?,?,?)`,
  h.Address,h.Port,h.SNI,h.Label,h.Priority,en)
 if err!=nil{return 0,err}
 return res.LastInsertId()
}

func (s *Store) AllMasterHosts() ([]MasterHost,error) {
 rows,err:=s.db.Query(`SELECT id,address,port,sni,label,priority,enabled FROM master_hosts WHERE enabled=1 ORDER BY priority,id`)
 if err!=nil{return nil,err}
 defer rows.Close()
 var out []MasterHost
 for rows.Next(){
  var h MasterHost; var en int
  if err:=rows.Scan(&h.ID,&h.Address,&h.Port,&h.SNI,&h.Label,&h.Priority,&en);err!=nil{return nil,err}
  h.Enabled=en==1
  out=append(out,h)
 }
 return out,rows.Err()
}

func (s *Store) DeleteMasterHost(id int) error {
 _,err:=s.db.Exec(`DELETE FROM master_hosts WHERE id=?`,id)
 return err
}

var _ = sql.ErrNoRows
