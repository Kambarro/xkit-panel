package sidecar

// ResourceCost — оценка нагрузки сайдкара (для предупреждения при выборе протокола).
// УРОК (владелец): «при выборе протоколов напоминать что тот или иной увеличит нагрузку
// на систему, если не нужно не включайте». Целимся в минимальный набор ресурсов.
// Значения ориентировочные (idle RAM + заметка), уточняются live-замерами.
type ResourceCost struct {
	RAMMB    int    // примерная RAM idle (МБ)
	CPU      string // "низкая"/"средняя"/"высокая"
	NoteRu   string
	NoteEn   string
	Light    bool   // лёгкий (можно рекомендовать для слабых VPS)
}

// Costs — нагрузка по типам сайдкаров и Xray-протоколов.
var Costs = map[string]ResourceCost{
	// Xray-протоколы (один процесс, inbound добавляет мало)
	"vless-reality": {RAMMB: 0, CPU: "низкая", NoteRu: "Внутри Xray — почти не добавляет нагрузки. Рекомендуется.", NoteEn: "Inside Xray — adds almost no load. Recommended.", Light: true},
	"vless-xhttp":   {RAMMB: 0, CPU: "низкая", NoteRu: "Внутри Xray — минимальная нагрузка, лучший анти-DPI.", NoteEn: "Inside Xray — minimal load, best anti-DPI.", Light: true},
	"vless-ws":      {RAMMB: 0, CPU: "низкая", NoteRu: "Внутри Xray — минимальная нагрузка.", NoteEn: "Inside Xray — minimal load.", Light: true},
	"trojan":        {RAMMB: 0, CPU: "низкая", NoteRu: "Внутри Xray — минимальная нагрузка.", NoteEn: "Inside Xray — minimal load.", Light: true},
	"vmess":         {RAMMB: 0, CPU: "низкая", NoteRu: "Внутри Xray — минимальная нагрузка.", NoteEn: "Inside Xray — minimal load.", Light: true},
	// Нативные сайдкар-демоны (отдельный процесс = +RAM)
	"hysteria2": {RAMMB: 30, CPU: "средняя", NoteRu: "Отдельный демон (~30 МБ RAM). Быстрый на мобильных/потерях (UDP+brutal), но QUIC грузит CPU больше. Включайте если нужен.", NoteEn: "Separate daemon (~30 MB RAM). Fast on mobile/loss (UDP+brutal) but QUIC uses more CPU. Enable only if needed.", Light: false},
	"tuic":      {RAMMB: 20, CPU: "средняя", NoteRu: "Отдельный демон (~20 МБ RAM). UDP/QUIC, 0-RTT. Включайте если нужен.", NoteEn: "Separate daemon (~20 MB RAM). UDP/QUIC, 0-RTT. Enable only if needed.", Light: false},
	"naive":     {RAMMB: 40, CPU: "средняя", NoteRu: "Отдельный демон (~40 МБ RAM). Лучшая маскировка под HTTPS, но тяжелее. Включайте если нужен.", NoteEn: "Separate daemon (~40 MB RAM). Best HTTPS mimicry but heavier. Enable only if needed.", Light: false},
	"ss2022":    {RAMMB: 10, CPU: "низкая", NoteRu: "Лёгкий демон на Rust (~10 МБ RAM). Экономный.", NoteEn: "Lightweight Rust daemon (~10 MB RAM). Economical.", Light: true},
	"mtproto":   {RAMMB: 10, CPU: "низкая", NoteRu: "Лёгкий демон (~10 МБ RAM), только для Telegram.", NoteEn: "Light daemon (~10 MB RAM), Telegram only.", Light: true},
	"mieru":     {RAMMB: 15, CPU: "низкая", NoteRu: "Лёгкий демон на Rust (~15 МБ RAM).", NoteEn: "Lightweight Rust daemon (~15 MB RAM).", Light: true},
	"amnezia":   {RAMMB: 15, CPU: "низкая", NoteRu: "Внутри панели (Go) — ~15 МБ, лёгкий. Устойчив к DPI.", NoteEn: "Inside panel (Go) — ~15 MB, light. DPI-resistant.", Light: true},
}

// CostFor — нагрузка по kind (с дефолтом для неизвестных).
func CostFor(kind string) ResourceCost {
	if c, ok := Costs[kind]; ok {
		return c
	}
	return ResourceCost{RAMMB: 20, CPU: "средняя", NoteRu: "Отдельный демон — добавляет нагрузку. Включайте если нужен.", NoteEn: "Separate daemon — adds load. Enable only if needed.", Light: false}
}