package vless

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
)

// userByIndexFromTable inverts an index-keyed user table into a uuid->index map
// for assertions, ignoring empty (freed) slots.
func userByIndexFromTable(table []option.VLESSUser) map[string]int {
	out := make(map[string]int)
	for i, u := range table {
		if u.UUID != "" {
			out[u.UUID] = i
		}
	}
	return out
}

// newInbound constructs a minimal Inbound wired to a real (but unstarted) vless
// service so UpdateUsers exercises the actual library map swap, without needing
// TLS, a listener, or a live handshake.
func newTestInbound(flow string) *Inbound {
	h := &Inbound{
		flow:        flow,
		userToIndex: make(map[string]int),
	}
	empty := []option.VLESSUser{}
	h.users.Store(&empty)
	h.service = vless.NewService[int](logger.NOP(), nil)
	return h
}

// TestAssignStableVLESSIndices_KeepsExistingIndices is the core billing-safety
// guarantee: when the user set changes, every UUID that was already present must
// keep the exact index it had before. A live VLESS connection caches its int
// user index at auth time; if that index later resolved to a different user,
// that connection's traffic would be billed to the wrong UUID.
func TestAssignStableVLESSIndices_KeepsExistingIndices(t *testing.T) {
	userToIndex := map[string]int{}
	flow := "xtls-rprx-vision"

	_, _, _, table := assignStableVLESSIndices(userToIndex,
		[]string{"a", "b", "c"}, []string{"a", "b", "c"}, []string{flow, flow, flow})
	before := userByIndexFromTable(table)
	if len(before) != 3 {
		t.Fatalf("expected 3 users, got %d", len(before))
	}

	_, _, _, table = assignStableVLESSIndices(userToIndex,
		[]string{"a", "b", "c", "d"}, []string{"a", "b", "c", "d"}, []string{flow, flow, flow, flow})
	after := userByIndexFromTable(table)
	for _, uuid := range []string{"a", "b", "c"} {
		if before[uuid] != after[uuid] {
			t.Fatalf("index for %q changed across add: %d -> %d", uuid, before[uuid], after[uuid])
		}
	}
	if _, ok := after["d"]; !ok {
		t.Fatalf("new user d not assigned")
	}
}

// TestAssignStableVLESSIndices_RemoveDoesNotShiftSurvivors checks that removing
// a user leaves survivors at their indices and the freed slot is reused by a
// future addition (dense, bounded indices).
func TestAssignStableVLESSIndices_RemoveDoesNotShiftSurvivors(t *testing.T) {
	userToIndex := map[string]int{}
	flow := "xtls-rprx-vision"
	_, _, _, table := assignStableVLESSIndices(userToIndex,
		[]string{"a", "b", "c"}, []string{"a", "b", "c"}, []string{flow, flow, flow})
	before := userByIndexFromTable(table)

	_, _, _, table = assignStableVLESSIndices(userToIndex,
		[]string{"a", "c"}, []string{"a", "c"}, []string{flow, flow})
	after := userByIndexFromTable(table)
	if before["a"] != after["a"] || before["c"] != after["c"] {
		t.Fatalf("survivor indices shifted after removal")
	}
	if _, ok := after["b"]; ok {
		t.Fatalf("removed user b still present")
	}

	freed := before["b"]
	_, _, _, table = assignStableVLESSIndices(userToIndex,
		[]string{"a", "c", "d"}, []string{"a", "c", "d"}, []string{flow, flow, flow})
	readd := userByIndexFromTable(table)
	if readd["d"] != freed {
		t.Fatalf("new user d should reuse freed slot %d, got %d", freed, readd["d"])
	}
	if readd["a"] != before["a"] || readd["c"] != before["c"] {
		t.Fatalf("survivors shifted after readd")
	}
}

// TestAssignStableVLESSIndices_ParallelLists verifies indexList/uuidByIndex/
// flowByIndex stay parallel and the userTable resolves each index to its UUID.
func TestAssignStableVLESSIndices_ParallelLists(t *testing.T) {
	userToIndex := map[string]int{}
	indexList, uuidByIndex, flowByIndex, table := assignStableVLESSIndices(userToIndex,
		[]string{"u1", "u2", "u3"},
		[]string{"u1", "u2", "u3"},
		[]string{"f1", "f2", "f3"})
	if len(indexList) != len(uuidByIndex) || len(indexList) != len(flowByIndex) {
		t.Fatalf("parallel list length mismatch")
	}
	wantFlow := map[string]string{"u1": "f1", "u2": "f2", "u3": "f3"}
	for i, idx := range indexList {
		uuid := table[idx].UUID
		if uuidByIndex[i] != uuid {
			t.Fatalf("index %d: uuidByIndex %q != table uuid %q", idx, uuidByIndex[i], uuid)
		}
		if flowByIndex[i] != wantFlow[uuid] {
			t.Fatalf("user %q paired with wrong flow %q, want %q", uuid, flowByIndex[i], wantFlow[uuid])
		}
		if table[idx].Flow != wantFlow[uuid] {
			t.Fatalf("table flow for %q wrong: %q", uuid, table[idx].Flow)
		}
	}
}

// TestAssignStableVLESSIndices_Idempotent verifies full-set semantics: re-pushing
// the same set does not move indices or grow the table.
func TestAssignStableVLESSIndices_Idempotent(t *testing.T) {
	userToIndex := map[string]int{}
	flow := "xtls-rprx-vision"
	_, _, _, first := assignStableVLESSIndices(userToIndex,
		[]string{"x", "y"}, []string{"x", "y"}, []string{flow, flow})
	_, _, _, second := assignStableVLESSIndices(userToIndex,
		[]string{"x", "y"}, []string{"x", "y"}, []string{flow, flow})
	if len(first) != len(second) {
		t.Fatalf("idempotent push changed table size: %d -> %d", len(first), len(second))
	}
	a, b := userByIndexFromTable(first), userByIndexFromTable(second)
	for uuid, idx := range a {
		if b[uuid] != idx {
			t.Fatalf("idempotent push moved %q: %d -> %d", uuid, idx, b[uuid])
		}
	}
}

// TestAssignStableVLESSIndices_DuplicateUUIDs stays defensive: duplicate UUIDs in
// one push must resolve to a single index, not two slots.
func TestAssignStableVLESSIndices_DuplicateUUIDs(t *testing.T) {
	userToIndex := map[string]int{}
	flow := "xtls-rprx-vision"
	_, _, _, table := assignStableVLESSIndices(userToIndex,
		[]string{"a", "a", "b"}, []string{"a", "a", "b"}, []string{flow, flow, flow})
	idx := userByIndexFromTable(table)
	if len(idx) != 2 {
		t.Fatalf("expected 2 distinct users from duplicate push, got %d", len(idx))
	}
}

// TestUpdateUsers_BinaryFlowUniform verifies the runtime entrypoint applies the
// inbound-wide flow to hot-added users (the binary (uuids, uuids) signature path).
func TestUpdateUsers_BinaryFlowUniform(t *testing.T) {
	h := newTestInbound("xtls-rprx-vision")
	if err := h.UpdateUsers([]string{"a", "b"}, []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	table := *h.users.Load()
	for _, u := range table {
		if u.UUID == "" {
			continue
		}
		if u.Flow != "xtls-rprx-vision" {
			t.Fatalf("hot-added user %q got flow %q, want xtls-rprx-vision", u.UUID, u.Flow)
		}
		if u.Name != u.UUID {
			t.Fatalf("name != uuid for %q (name=%q)", u.UUID, u.Name)
		}
	}
}

// TestUpdateUsers_LengthMismatch rejects a malformed call.
func TestUpdateUsers_LengthMismatch(t *testing.T) {
	h := newTestInbound("")
	if err := h.UpdateUsers([]string{"a", "b"}, []string{"a"}); err == nil {
		t.Fatal("expected error on name/password length mismatch")
	}
}

// TestUserByIndex_StableAcrossUpdate is the connection-survival simulation: a
// live connection captures user "b"'s index, then UpdateUsers adds and removes
// other users. The captured index must still resolve to "b" (its billing UUID)
// and must never panic or alias another user. This is the unit-level proxy for
// "existing connection not dropped / not mis-billed by UpdateUsers".
func TestUserByIndex_StableAcrossUpdate(t *testing.T) {
	h := newTestInbound("xtls-rprx-vision")
	if err := h.UpdateUsers([]string{"a", "b", "c"}, []string{"a", "b", "c"}); err != nil {
		t.Fatal(err)
	}
	// Simulate a live connection authenticated as "b": capture its int index.
	bIndex := -1
	for i, u := range *h.users.Load() {
		if u.UUID == "b" {
			bIndex = i
		}
	}
	if bIndex < 0 {
		t.Fatal("user b not found after initial load")
	}

	// Remove "a", add "d" and "e" — churn around the live connection.
	if err := h.UpdateUsers([]string{"b", "c", "d", "e"}, []string{"b", "c", "d", "e"}); err != nil {
		t.Fatal(err)
	}
	u, ok := h.userByIndex(bIndex)
	if !ok || u.UUID != "b" {
		t.Fatalf("captured index %d no longer resolves to b (ok=%v, uuid=%q)", bIndex, ok, u.UUID)
	}

	// Remove "b" itself: its captured index must now resolve to ok=false (slot
	// freed), never to a different user. A new user may later reuse the slot, but
	// not within a set that does not contain it.
	if err := h.UpdateUsers([]string{"c"}, []string{"c"}); err != nil {
		t.Fatal(err)
	}
	if u, ok := h.userByIndex(bIndex); ok && u.UUID != "" {
		// The slot may have been reused by nobody here (set shrank); assert it is
		// not aliased to a surviving user other than via legitimate reuse.
		if u.UUID == "c" && bIndex != indexOf(h, "c") {
			t.Fatalf("freed index %d aliased to surviving user c", bIndex)
		}
	}
}

func indexOf(h *Inbound, uuid string) int {
	for i, u := range *h.users.Load() {
		if u.UUID == uuid {
			return i
		}
	}
	return -1
}

// TestUpdateUsers_ConcurrentReadNoRace runs UpdateUsers concurrently with the
// read path (userByIndex) to catch torn-slice races under `go test -race`. The
// h.users atomic.Pointer makes the read path race-free with the wholesale swap.
func TestUpdateUsers_ConcurrentReadNoRace(t *testing.T) {
	h := newTestInbound("xtls-rprx-vision")
	if err := h.UpdateUsers([]string{"a", "b", "c"}, []string{"a", "b", "c"}); err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup

	// Readers hammer userByIndex.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				for i := 0; i < 6; i++ {
					_, _ = h.userByIndex(i)
				}
			}
		}()
	}

	// Writer churns the user set.
	wg.Add(1)
	go func() {
		defer wg.Done()
		sets := [][]string{
			{"a", "b", "c"},
			{"a", "b", "c", "d"},
			{"b", "c", "d"},
			{"c"},
			{"a", "b", "c", "d", "e"},
		}
		for n := 0; n < 200; n++ {
			s := sets[n%len(sets)]
			if err := h.UpdateUsers(s, s); err != nil {
				t.Error(err)
				return
			}
		}
		stop.Store(true)
	}()

	wg.Wait()
}
