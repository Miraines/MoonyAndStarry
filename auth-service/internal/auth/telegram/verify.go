package telegram

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// CheckAuth verifies telegram login hash according to official docs
func CheckAuth(params map[string]string, hash, token string) bool {
	// 1. Лексикографическая сортировка ключей.
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 2. Формируем data-check-string.
	var sb strings.Builder
	for i, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(params[k])
		if i < len(keys)-1 {
			sb.WriteByte('\n')
		}
	}
	data := sb.String()

	// 3. Секрет = SHA256(botToken).
	secret := sha256.Sum256([]byte(token))

	// 4. HMAC-SHA256(data, secret).
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(data))
	expected := hex.EncodeToString(mac.Sum(nil))

	// 5. Сравнение.
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(hash)))
}

// CheckWebAppAuth verifies init_data from Telegram Web Apps according to
// https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
// Params should contain all fields except "hash" and "signature".
func CheckWebAppAuth(params map[string]string, hash, token string) bool {
	// 1. Sort keys except hash and signature
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "hash" || k == "signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 2. Build data-check-string
	var sb strings.Builder
	for i, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(params[k])
		if i < len(keys)-1 {
			sb.WriteByte('\n')
		}
	}
	data := sb.String()

	// 3. secret_key = HMAC_SHA256(bot_token, "WebAppData")
	mac1 := hmac.New(sha256.New, []byte("WebAppData"))
	mac1.Write([]byte(token))
	secret := mac1.Sum(nil)

	// 4. expected_hash = HMAC_SHA256(data-check-string, secret_key)
	mac2 := hmac.New(sha256.New, secret)
	mac2.Write([]byte(data))
	expected := hex.EncodeToString(mac2.Sum(nil))

	// 5. Compare
	return hmac.Equal([]byte(strings.ToLower(hash)), []byte(strings.ToLower(expected)))
}
