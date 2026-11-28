package main

import (
	"path/filepath"
	"testing"

	"github.com/kambarro/xkit-panel/internal/auth"
	"github.com/kambarro/xkit-panel/internal/store"
)

func TestApplyBootstrapPassOnReinstall(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	au := auth.New(st)

	if _, err := au.EnsureAdmin("admin1", "oldpass"); err != nil {
		t.Fatal(err)
	}

	// переустановка принесла новый пароль -> он должен лечь в БД
	changed, err := applyBootstrapPass(st, au, "admin1", "freshpass")
	if err != nil || !changed {
		t.Fatalf("первый бутстрап должен сменить пароль, changed=%v err=%v", changed, err)
	}
	if !auth.VerifyPassword("freshpass", mustHash(t, st, "admin1")) {
		t.Fatal("новый пароль не запиcан в БД")
	}
	if !au.MustChange("admin1") {
		t.Fatal("после бутстрапа должен стоять must_change=1")
	}

	// обычный рестарт с тем же паролем -> менять нельзя
	changed, err = applyBootstrapPass(st, au, "admin1", "freshpass")
	if err != nil || changed {
		t.Fatalf("повторный бутстрап с тем же паролем не должен трогать БД, changed=%v err=%v", changed, err)
	}

	// ещё одна переустановка с новым паролем -> смена
	if _, err = applyBootstrapPass(st, au, "admin1", "freshpass2"); err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword("freshpass2", mustHash(t, st, "admin1")) {
		t.Fatal("второй бутстрап не сменил пароль")
	}
}

func TestApplyBootstrapPassMissingAdmin(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	au := auth.New(st)
	changed, err := applyBootstrapPass(st, au, "nobody", "somepass")
	if err != nil || changed {
		t.Fatalf("несуществующий админ: changed=%v err=%v", changed, err)
	}
}

func mustHash(t *testing.T, st *store.Store, username string) string {
	t.Helper()
	var h string
	if err := st.DB().QueryRow(`SELECT pass_hash FROM admins WHERE username=?`, username).Scan(&h); err != nil {
		t.Fatal(err)
	}
	return h
}