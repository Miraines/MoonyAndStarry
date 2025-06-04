package telegram

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// CheckAuth verifies telegram login hash according to official docs
func CheckAuth(params map[string]string, hash string, token string) bool {

	// 1. Алфавитная сортировка ключей
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 2. Data-check-string c \\n между парами
	var sb strings.Builder
	for i, k := range keys {
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(params[k])
		if i != len(keys)-1 {
			sb.WriteRune('\n')
		}
	}
	data := sb.String()

	// 3. Secret = SHA256(botToken)
	secret := sha256.Sum256([]byte(token))

	// 4. HMAC-SHA256(data, secret)
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(data))
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(hash))
}
