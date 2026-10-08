package incident

import (
	"testing"
)

func FuzzIncidentParse(f *testing.F) {
	files, err := presetFS.ReadDir("presets")
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range files {
		b, err := presetFS.ReadFile("presets/" + e.Name())
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte("id: x\nwindow: {start: 2026-01-01T00:00:00Z, end: 2026-01-02T00:00:00Z}\nnpm: [{name: a, versions: ['*']}]\n"))
	f.Add([]byte("window: {start: 1}\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		inc, err := Parse(b)
		if inc == nil {
			if err == nil {
				t.Fatal("nil incident without error")
			}
			return
		}
		if inc.Validate() == nil && err != nil {
			t.Fatalf("Parse error %v but Validate passes", err)
		}
	})
}
