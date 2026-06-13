//go:build with_quic

package hysteria2

import (
	"testing"
)

// buildNameByIndex inverts the index-keyed nameList into a name->index map for
// assertions, ignoring empty (freed) slots.
func nameByIndex(nameList []string) map[string]int {
	out := make(map[string]int)
	for i, name := range nameList {
		if name != "" {
			out[name] = i
		}
	}
	return out
}

// TestAssignStableIndices_KeepsExistingIndices is the core billing-safety
// guarantee: when the user set changes, every name that was already present
// must keep the exact index it had before. A live hysteria2 connection caches
// its int user index at auth time; if that index later resolved to a different
// name, that connection's traffic would be billed to the wrong UUID.
func TestAssignStableIndices_KeepsExistingIndices(t *testing.T) {
	nameToIndex := map[string]int{}

	// Initial set of three users.
	_, _, nameList := assignStableIndices(nameToIndex, []string{"a", "b", "c"}, []string{"pa", "pb", "pc"})
	before := nameByIndex(nameList)
	if len(before) != 3 {
		t.Fatalf("expected 3 users, got %d", len(before))
	}

	// Add a fourth user; the original three must keep their indices.
	_, _, nameList = assignStableIndices(nameToIndex, []string{"a", "b", "c", "d"}, []string{"pa", "pb", "pc", "pd"})
	after := nameByIndex(nameList)
	for _, name := range []string{"a", "b", "c"} {
		if before[name] != after[name] {
			t.Fatalf("index for %q changed across add: %d -> %d", name, before[name], after[name])
		}
	}
	if _, ok := after["d"]; !ok {
		t.Fatalf("new user d not assigned")
	}
}

// TestAssignStableIndices_RemoveDoesNotShiftSurvivors checks that removing a
// user does not renumber the survivors (the removed slot is left as a gap and
// reused only by future additions).
func TestAssignStableIndices_RemoveDoesNotShiftSurvivors(t *testing.T) {
	nameToIndex := map[string]int{}
	_, _, nameList := assignStableIndices(nameToIndex, []string{"a", "b", "c"}, []string{"pa", "pb", "pc"})
	before := nameByIndex(nameList)

	// Remove "b".
	_, _, nameList = assignStableIndices(nameToIndex, []string{"a", "c"}, []string{"pa", "pc"})
	after := nameByIndex(nameList)
	if before["a"] != after["a"] || before["c"] != after["c"] {
		t.Fatalf("survivor indices shifted after removal: a %d->%d, c %d->%d",
			before["a"], after["a"], before["c"], after["c"])
	}
	if _, ok := after["b"]; ok {
		t.Fatalf("removed user b still present")
	}

	// Add "d": it should reuse b's freed slot, not extend the list.
	freedSlot := before["b"]
	_, _, nameList = assignStableIndices(nameToIndex, []string{"a", "c", "d"}, []string{"pa", "pc", "pd"})
	readd := nameByIndex(nameList)
	if readd["d"] != freedSlot {
		t.Fatalf("new user d should reuse freed slot %d, got %d", freedSlot, readd["d"])
	}
	if readd["a"] != before["a"] || readd["c"] != before["c"] {
		t.Fatalf("survivors shifted after readd")
	}
}

// TestAssignStableIndices_ParallelLists verifies userList[i]/passwordList[i]
// stay parallel and that the nameList resolves each user's index back to the
// password it was given (name==password in the realm case, but we use distinct
// values here to catch mis-pairing).
func TestAssignStableIndices_ParallelLists(t *testing.T) {
	nameToIndex := map[string]int{}
	userList, passwordList, nameList := assignStableIndices(
		nameToIndex,
		[]string{"u1", "u2", "u3"},
		[]string{"pw1", "pw2", "pw3"},
	)
	if len(userList) != len(passwordList) {
		t.Fatalf("userList/passwordList length mismatch: %d vs %d", len(userList), len(passwordList))
	}
	// password expected for each name.
	wantPw := map[string]string{"u1": "pw1", "u2": "pw2", "u3": "pw3"}
	for i, index := range userList {
		name := nameList[index]
		if passwordList[i] != wantPw[name] {
			t.Fatalf("user %q (index %d) paired with wrong password %q, want %q",
				name, index, passwordList[i], wantPw[name])
		}
	}
}

// TestAssignStableIndices_Idempotent verifies full-set semantics: re-pushing the
// same set produces the same index assignment and does not grow the list.
func TestAssignStableIndices_Idempotent(t *testing.T) {
	nameToIndex := map[string]int{}
	_, _, first := assignStableIndices(nameToIndex, []string{"x", "y"}, []string{"px", "py"})
	_, _, second := assignStableIndices(nameToIndex, []string{"x", "y"}, []string{"px", "py"})
	if len(first) != len(second) {
		t.Fatalf("idempotent push changed list size: %d -> %d", len(first), len(second))
	}
	a, b := nameByIndex(first), nameByIndex(second)
	for name, idx := range a {
		if b[name] != idx {
			t.Fatalf("idempotent push moved %q: %d -> %d", name, idx, b[name])
		}
	}
}
