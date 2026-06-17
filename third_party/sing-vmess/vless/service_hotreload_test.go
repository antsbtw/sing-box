package vless

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

// TestServiceUpdateUsersConcurrent exercises the runtime hot-update path
// (UpdateUsers) concurrently with the auth read path that NewConnection performs
// on every new handshake (the userMap/userFlow lookups). It must be race-free
// under `go test -race`: both maps are bundled in a userTable held by an
// atomic.Pointer that UpdateUsers swaps wholesale while readers Load() it. This
// reproduces the exact "换表 vs 新握手" race that two separate field assignments
// (s.userMap=/s.userFlow=) would expose: with the old code -race would flag a
// data race here; with the atomic swap it must stay clean. It also proves there
// is no "new userMap + old userFlow" tearing window, since a single Load()
// observes both maps from the same snapshot.
func TestServiceUpdateUsersConcurrent(t *testing.T) {
	s := NewService[int](logger.NOP(), nil)

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
				uuids := make([]string, n)
				flows := make([]string, n)
				for j := 0; j < n; j++ {
					users[j] = base*1000 + j
					// Deterministic non-UUID strings exercise the
					// uuid.NewV5 fallback path in UpdateUsers.
					uuids[j] = string(rune('a'+base)) + string(rune('0'+j))
					if j%2 == 0 {
						flows[j] = FlowVision
					} else {
						flows[j] = ""
					}
				}
				s.UpdateUsers(users, uuids, flows)
			}
		}(w)
	}

	// Readers continuously perform the auth-path snapshot Load + map lookups
	// (mirroring NewConnection) until signalled.
	for r := 0; r < readers; r++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			var probe [16]byte
			for {
				select {
				case <-stop:
					return
				default:
				}
				users := s.users.Load()
				if u, ok := users.userMap[probe]; ok {
					_ = users.userFlow[u]
				}
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

// TestServiceUpdateUsersReplacesTable verifies UpdateUsers fully replaces both
// maps (full-set semantics) atomically: a UUID present before but absent from
// the new set is no longer authenticated, the new set's UUIDs are, and each
// user's flow is observed consistently with its userMap entry (no tearing).
func TestServiceUpdateUsersReplacesTable(t *testing.T) {
	s := NewService[int](logger.NOP(), nil)

	s.UpdateUsers(
		[]int{0, 1},
		[]string{"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"},
		[]string{FlowVision, ""},
	)
	first := s.users.Load()
	if len(first.userMap) != 2 {
		t.Fatalf("expected 2 users after first update, got %d", len(first.userMap))
	}

	// Full-set replace: only the new UUID remains.
	s.UpdateUsers(
		[]int{5},
		[]string{"33333333-3333-3333-3333-333333333333"},
		[]string{FlowVision},
	)
	second := s.users.Load()
	if len(second.userMap) != 1 {
		t.Fatalf("expected 1 user after full-set replace, got %d", len(second.userMap))
	}
	// The replaced-out users must be gone; flow map must match exactly.
	for _, u := range second.userMap {
		if u != 5 {
			t.Fatalf("unexpected user %d survived replace", u)
		}
		if second.userFlow[u] != FlowVision {
			t.Fatalf("flow tearing: user %d flow = %q, want %q", u, second.userFlow[u], FlowVision)
		}
	}
}
