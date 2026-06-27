package trojan

import (
	"strconv"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

// TestUpdateUsersRace exercises the atomic user-table swap under concurrent
// readers (mirroring NewConnection's key lookup) and writers (UpdateUsers).
// Run with -race: a data race here would mean a hot reload can corrupt auth
// for a live connection.
func TestUpdateUsersRace(t *testing.T) {
	svc := NewService[int](nil, nil, logger.NOP())
	if err := svc.UpdateUsers([]int{0, 1}, []string{"pass-0", "pass-1"}); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})

	// readers: mimic the read path, not part of the writer WaitGroup.
	var readers sync.WaitGroup
	for r := 0; r < 8; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			k0 := Key("pass-0")
			for {
				select {
				case <-stop:
					return
				default:
					_ = svc.table.Load().keys[k0]
				}
			}
		}()
	}

	// writers: keep swapping the full user set with distinct, conflict-free creds.
	var writers sync.WaitGroup
	for w := 0; w < 2; w++ {
		writers.Add(1)
		go func(base int) {
			defer writers.Done()
			for i := 0; i < 2000; i++ {
				u := base*100000 + i
				_ = svc.UpdateUsers(
					[]int{u, u + 1},
					[]string{"w" + strconv.Itoa(u) + "-a", "w" + strconv.Itoa(u) + "-b"},
				)
			}
		}(w)
	}

	writers.Wait()
	close(stop)
	readers.Wait()
}
