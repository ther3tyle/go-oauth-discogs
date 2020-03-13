package util

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

func PercentEncode(input string) string {
	var buf bytes.Buffer
	for _, b := range []byte(input) {
		if shouldEscape(b) {
			// escape byte
			buf.Write([]byte(fmt.Sprintf("%%%02X", b)))
		} else {
			//write as is
			buf.WriteByte(b)
		}
	}
	return buf.String()
}

func Nonce() string {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	HandleError(err)

	var nonce string
	encoded := base64.StdEncoding.EncodeToString(token)
	for _, e := range encoded {
		if unicode.IsLetter(e) {
			nonce += string(e)
		}
	}
	return nonce
}

func HandleError(err error) {
	if err != nil {
		log.Fatalf("error: %v", err)
	}
}

// RFC 3986 2.1
// Every letters other than a-zA-Z0-9 must be escaped.
func shouldEscape(c byte) bool {
	if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
		return false
	}
	switch c {
	case '-', '.', '_', '~':
		return false
	}
	return true
}

func NormalizeParam(v url.Values) string {
	params := make([]string, 0, len(v))
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		params = append(params, fmt.Sprintf("%s=%s", PercentEncode(k), PercentEncode(v.Get(k))))
	}

	return strings.Join(params, "&")
}
