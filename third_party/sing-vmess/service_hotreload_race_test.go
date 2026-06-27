package vmess

import (
	"strconv"
	"sync"
	"testing"
)

// TestServiceUpdateUsersRace exercises the atomic AEAD auth-table swap under
// concurrent readers (mimicking NewConnection's userIdCipher/userKey lookups)
// and writers (UpdateUsers). Run with -race. alterId is 0 throughout (otun /
// modern AEAD), so the legacy alterId path is not involved.
func TestServiceUpdateUsersRace(t *testing.T) {
	svc := NewService[int](nil)
	if err := svc.UpdateUsers([]int{0}, []string{"b831381d-6324-4d53-ad4f-8cda48b30811"}, []int{0}); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for r := 0; r < 8; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					// mirror the read path: snapshot then range userIdCipher + read userKey
					tbl := svc.authTable.Load()
					for u, blk := range tbl.userIdCipher {
						_ = blk
						_ = tbl.userKey[u]
					}
				}
			}
		}()
	}

	var writers sync.WaitGroup
	for w := 0; w < 2; w++ {
		writers.Add(1)
		go func(base int) {
			defer writers.Done()
			for i := 0; i < 1500; i++ {
				u := base*100000 + i
				// deterministic distinct uuid per iteration
				uuid := "00000000-0000-4000-8000-" + strconv.Itoa(1000000000000+u)
				_ = svc.UpdateUsers([]int{u}, []string{uuid}, []int{0})
			}
		}(w)
	}

	writers.Wait()
	close(stop)
	readers.Wait()
}
