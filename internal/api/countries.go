package api

import "net/http"

// countries.go — справочник стран для выбора ноды (код ISO + ru/en названия).
// УРОК (владелец): «не все знают код страны — выпадающий список с подсказкой,
// начинать ввод можно с кода, по-русски или английски».

type countryEntry struct {
	Code string `json:"code"`
	RU   string `json:"ru"`
	EN   string `json:"en"`
}

var countryList = []countryEntry{
	{"NL", "Нидерланды", "Netherlands"},
	{"DE", "Германия", "Germany"},
	{"US", "США", "United States"},
	{"GB", "Великобритания", "United Kingdom"},
	{"FR", "Франция", "France"},
	{"FI", "Финляндия", "Finland"},
	{"SE", "Швеция", "Sweden"},
	{"NO", "Норвегия", "Norway"},
	{"DK", "Дания", "Denmark"},
	{"PL", "Польша", "Poland"},
	{"CZ", "Чехия", "Czechia"},
	{"AT", "Австрия", "Austria"},
	{"CH", "Швейцария", "Switzerland"},
	{"IT", "Италия", "Italy"},
	{"ES", "Испания", "Spain"},
	{"PT", "Португалия", "Portugal"},
	{"IE", "Ирландия", "Ireland"},
	{"BE", "Бельгия", "Belgium"},
	{"LU", "Люксембург", "Luxembourg"},
	{"IS", "Исландия", "Iceland"},
	{"EE", "Эстония", "Estonia"},
	{"LV", "Латвия", "Latvia"},
	{"LT", "Литва", "Lithuania"},
	{"UA", "Украина", "Ukraine"},
	{"MD", "Молдова", "Moldova"},
	{"RO", "Румыния", "Romania"},
	{"BG", "Болгария", "Bulgaria"},
	{"HU", "Венгрия", "Hungary"},
	{"SK", "Словакия", "Slovakia"},
	{"SI", "Словения", "Slovenia"},
	{"HR", "Хорватия", "Croatia"},
	{"RS", "Сербия", "Serbia"},
	{"GR", "Греция", "Greece"},
	{"TR", "Турция", "Turkey"},
	{"CY", "Кипр", "Cyprus"},
	{"GE", "Грузия", "Georgia"},
	{"AM", "Армения", "Armenia"},
	{"AZ", "Азербайджан", "Azerbaijan"},
	{"KZ", "Казахстан", "Kazakhstan"},
	{"UZ", "Узбекистан", "Uzbekistan"},
	{"KG", "Кыргызстан", "Kyrgyzstan"},
	{"RU", "Россия", "Russia"},
	{"BY", "Беларусь", "Belarus"},
	{"AE", "ОАЭ", "United Arab Emirates"},
	{"IL", "Израиль", "Israel"},
	{"SG", "Сингапур", "Singapore"},
	{"JP", "Япония", "Japan"},
	{"KR", "Южная Корея", "South Korea"},
	{"HK", "Гонконг", "Hong Kong"},
	{"TW", "Тайвань", "Taiwan"},
	{"IN", "Индия", "India"},
	{"TH", "Таиланд", "Thailand"},
	{"VN", "Вьетнам", "Vietnam"},
	{"MY", "Малайзия", "Malaysia"},
	{"ID", "Индонезия", "Indonesia"},
	{"PH", "Филиппины", "Philippines"},
	{"AU", "Австралия", "Australia"},
	{"NZ", "Новая Зеландия", "New Zealand"},
	{"CA", "Канада", "Canada"},
	{"MX", "Мексика", "Mexico"},
	{"BR", "Бразилия", "Brazil"},
	{"AR", "Аргентина", "Argentina"},
	{"CL", "Чили", "Chile"},
	{"CO", "Колумбия", "Colombia"},
	{"ZA", "ЮАР", "South Africa"},
	{"EG", "Египет", "Egypt"},
	{"MA", "Марокко", "Morocco"},
	{"NG", "Нигерия", "Nigeria"},
	{"KE", "Кения", "Kenya"},
	{"SA", "Саудовская Аравия", "Saudi Arabia"},
	{"QA", "Катар", "Qatar"},
	{"BH", "Бахрейн", "Bahrain"},
	{"OM", "Оман", "Oman"},
	{"JO", "Иордания", "Jordan"},
	{"PK", "Пакистан", "Pakistan"},
	{"BD", "Бангладеш", "Bangladesh"},
	{"LK", "Шри-Ланка", "Sri Lanka"},
	{"NP", "Непал", "Nepal"},
	{"MN", "Монголия", "Mongolia"},
	{"CN", "Китай", "China"},
	{"MO", "Макао", "Macao"},
}

// GET /api/countries/reference — справочник (для autocomplete в формах ноды).
// BUG-01: был дубль маршрута /api/countries (перезатирал availableCountries).
func (s *Server) countries(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, countryList)
}
