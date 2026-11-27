package api

// security.go — общие проверки входных данных (аудит SEC-01/02/04/06).
// УРОК: всё, что попадает в shell-команды (версии, SNI, path), проходит строгую
// валидацию ДО интерполяции; тела запросов ограничены по размеру.

import (
	_ "embed"
	"net/http"
	"regexp"
)

// versionRe — версия компонента строго X.Y.Z (никаких кавычек/;/$() в shell).
var versionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// validVersion — SEC-01/SEC-02: версия для URL релиза и shell-скрипта обновления.
func validVersion(v string) bool { return versionRe.MatchString(v) }

// tunnelFieldRe — SEC-04: SNI/path/serviceName только безопасные символы
// (домены, пути, имена сервисов). Кавычки, пробелы, $, ;, переводы строк — запрещены.
var tunnelFieldRe = regexp.MustCompile(`^[A-Za-z0-9._:/-]+$`)

// validTunnelField — проверка полей туннеля перед доставкой конфига на ноду.
func validTunnelField(v string) bool { return tunnelFieldRe.MatchString(v) }

// maxBodyBytes — SEC-06: лимит тела JSON-запроса (1 MiB).
const maxBodyBytes = 1 << 20

// limitBody — middleware: http.MaxBytesReader на все запросы с телом (JSON-декодеры).
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// allowedSigners — SEC-05: публичный ключ подписи релизов (копия assets/allowed_signers
// из корня репо; go:embed не умеет ссылаться на родительские каталоги).
// Обновлять ВМЕСТЕ с assets/allowed_signers при ротации ключа.
//
//go:embed assets/allowed_signers
var allowedSigners string