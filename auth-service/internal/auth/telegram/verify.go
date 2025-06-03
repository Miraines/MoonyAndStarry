package telegram

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// CheckAuth verifies telegram login hash according to official docs
func CheckAuth(fields map[string]string, botToken string) bool {
	hash := fields["hash"]
	delete(fields, "hash")

	var keys []string
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var data string
	for i, k := range keys {
		if i > 0 {
			data += "\n"
		}
		data += k + "=" + fields[k]
	}

	secretKey := sha256.Sum256([]byte(botToken))
	h := hmac.New(sha256.New, secretKey[:])
	h.Write([]byte(data))
	expected := hex.EncodeToString(h.Sum(nil))

	return expected == hash
}
