package events

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
)

// Security review R9 (I-17): several writers (impr serve and a CLI run, each
// its own process) append to one log without forking its chain. Each writer
// here opens the log itself, as a separate process would.
func TestConcurrentWritersKeepOneChain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "events")
	const writers, each = 8, 25
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bus := &Bus{Env: fixedEnv(), Sinks: []Sink{Log{Dir: dir}}, Warn: func(f string, a ...any) { t.Errorf(f, a...) }}
			for i := 0; i < each; i++ {
				bus.Emit(context.Background(), "verification.run.completed", "p", map[string]any{"n": i})
			}
		}()
	}
	wg.Wait()
	n, err := Log{Dir: dir}.Verify()
	if err != nil || n != writers*each {
		t.Fatalf("verify after concurrent writes: %d of %d, %v", n, writers*each, err)
	}
}
