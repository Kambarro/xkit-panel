package subscription

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Happ cryptoLink (P1 #15, Remnawave Happ): зашифрованная ссылка подписки.
// УРОК: скрывает адрес подписки от пользователя — нельзя посмотреть/расшарить конфиги.
// Ключи вшиты в клиент Happ. Реализуем crypt3 (RSA-4096 PKCS#1 v1.5, официальный публичный
// ключ = pkcs1_2) В ПРОЦЕССЕ — без внешнего API (как QR-генерация, директива владельца).
// Формат: happ://crypt3/<base64(chunked RSA ciphertext)>, блок 512 байт, plaintext <=501.
// crypt3 deprecated вендором (рекомендуют crypt5), но публичный ключ доступен только для него;
// crypt5 требует приватные ключи из клиента — не извлекаем. crypt3 работает в Happ.

const happPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlBetA0wjbaj+h7oJ/d/h
pNrXvAcuhOdFGEFcfCxSWyLzWk4SAQ05gtaEGZyetTax2uqagi9HT6lapUSUe2S8
nMLJf5K+LEs9TYrhhBdx/B0BGahA+lPJa7nUwp7WfUmSF4hir+xka5ApHjzkAQn6
cdG6FKtSPgq1rYRPd1jRf2maEHwiP/e/jqdXLPP0SFBjWTMt/joUDgE7v/IGGB0L
Q7mGPAlgmxwUHVqP4bJnZ//5sNLxWMjtYHOYjaV+lixNSfhFM3MdBndjpkmgSfmg
D5uYQYDL29TDk6Eu+xetUEqry8ySPjUbNWdDXCglQWMxDGjaqYXMWgxBA1UKjUBW
wbgr5yKTJ7mTqhlYEC9D5V/LOnKd6pTSvaMxkHXwk8hBWvUNWAxzAf5JZ7EVE3jt
0j682+/hnmL/hymUE44yMG1gCcWvSpB3BTlKoMnl4yrTakmdkbASeFRkN3iMRewa
IenvMhzJh1fq7xwX94otdd5eLB2vRFavrnhOcN2JJAkKTnx9dwQwFpGEkg+8U613
+Tfm/f82l56fFeoFN98dD2mUFLFZoeJ5CG81ZeXrH83niI0joX7rtoAZIPWzq3Y1
Zb/Zq+kK2hSIhphY172Uvs8X2Qp2ac9UoTPM71tURsA9IvPNvUwSIo/aKlX5KE3I
VE0tje7twWXL5Gb1sfcXRzsCAwEAAQ==
-----END PUBLIC KEY-----`

var happPubKey *rsa.PublicKey

func init() {
	block, _ := pem.Decode([]byte(happPublicKeyPEM))
	if block == nil {
		return
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}
	happPubKey, _ = pub.(*rsa.PublicKey)
}

// HappCryptoLink шифрует URL подписки в happ://crypt3/… (RSA-4096 chunked PKCS1v15).
func HappCryptoLink(subURL string) (string, error) {
	if happPubKey == nil {
		return "", fmt.Errorf("happ public key not loaded")
	}
	data := []byte(subURL)
	const chunk = 501
	var cipher []byte
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		enc, err := rsa.EncryptPKCS1v15(rand.Reader, happPubKey, data[off:end])
		if err != nil {
			return "", err
		}
		cipher = append(cipher, enc...)
	}
	return "happ://crypt3/" + base64.StdEncoding.EncodeToString(cipher), nil
}

// HappCryptoAvailable — доступен ли ключ (для UI).
func HappCryptoAvailable() bool { return happPubKey != nil }
