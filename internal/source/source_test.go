package source

import (
	"sync"
	"testing"
	"time"
)

func TestParseAtMostTwoAtOnce(t *testing.T) {
	var mu sync.Mutex
	cur, peak := 0, 0
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			Parse(func() {
				mu.Lock()
				cur++
				peak = max(peak, cur)
				mu.Unlock()
				time.Sleep(5 * time.Millisecond)
				mu.Lock()
				cur--
				mu.Unlock()
			})
		})
	}
	wg.Wait()
	if peak != 2 {
		t.Fatalf("peak concurrent parses %d, want 2", peak)
	}
}
