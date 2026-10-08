package report

import (
	"testing"
	"unicode"
)

func FuzzClean(f *testing.F) {
	f.Add("plain text")
	f.Add("a\u202eb\u200bc\x1b[31m\r\nd\U000e0041")
	f.Add("\xff\xfe")
	f.Fuzz(func(t *testing.T, s string) {
		for _, r := range Clean(s) {
			if unicode.Is(unicode.Cf, r) || r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 {
				t.Fatalf("Clean(%q) kept %U", s, r)
			}
		}
	})
}
