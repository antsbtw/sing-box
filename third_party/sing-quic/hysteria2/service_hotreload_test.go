package hysteria2

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestServiceUpdateUsersConcurrent exercises the runtime hot-update path
// (UpdateUsers) concurrently with the auth read path (the same map load that
// ServeHTTP performs on every new handshake). It must be race-free under
// `go test -race`: the userMap is an atomic.Pointer that UpdateUsers swaps
// wholesale while readers Load() it. This is the concurrency guarantee that
// lets a VPN egress add/remove users without disturbing live connections.
func TestServiceUpdateUsersConcurrent(t *testing.T) {
	s := &Service[int]{}
	initial := make(map[string]int)
	s.userMap.Store(&initial)

	const writers = 4
	const readers = 8
	const iterations = 2000

	var writerWG sync.WaitGroup
	var readerWG sync.WaitGroup
	stop := make(chan struct{})
	var reads atomic.Int64

	// Writers continuously push full user sets (hot reload), then finish.
	for w := 0; w < writers; w++ {
		writerWG.Add(1)
		go func(base int) {
			defer writerWG.Done()
			for i := 0; i < iterations; i++ {
				n := (i % 16) + 1
				users := make([]int, n)
				passwords := make([]string, n)
				for j := 0; j < n; j++ {
					users[j] = base*1000 + j
					passwords[j] = string(rune('a'+base)) + string(rune('0'+j))
				}
				s.UpdateUsers(users, passwords)
			}
		}(w)
	}

	// Readers continuously perform the auth-path map load until signalled.
	for r := 0; r < readers; r++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				m := *s.userMap.Load()
				_, _ = m["a0"]
				reads.Add(1)
			}
		}()
	}

	writerWG.Wait() // all hot-reloads done
	close(stop)     // tell readers to exit
	readerWG.Wait()

	if reads.Load() == 0 {
		t.Fatal("no reads performed")
	}
}

// TestServiceUpdateUsersReplacesMap verifies UpdateUsers fully replaces the auth
// map (full-set semantics): a password present before but absent from the new
// set is no longer authenticated, and the new set's passwords are.
func TestServiceUpdateUsersReplacesMap(t *testing.T) {
	s := &Service[int]{}
	initial := make(map[string]int)
	s.userMap.Store(&initial)

	s.UpdateUsers([]int{0, 1}, []string{"old0", "old1"})
	m := *s.userMap.Load()
	if _, ok := m["old0"]; !ok {
		t.Fatal("old0 should be present after first update")
	}

	// Full-set replace: only new1/new2 remain.
	s.UpdateUsers([]int{0, 1}, []string{"new1", "new2"})
	m = *s.userMap.Load()
	if _, ok := m["old0"]; ok {
		t.Fatal("old0 should be gone after full-set replace")
	}
	if _, ok := m["new1"]; !ok {
		t.Fatal("new1 should be present")
	}
	if _, ok := m["new2"]; !ok {
		t.Fatal("new2 should be present")
	}
}
