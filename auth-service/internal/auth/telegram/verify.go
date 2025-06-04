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
