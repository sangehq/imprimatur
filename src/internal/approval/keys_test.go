package approval

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
)

// Security review (I-02): one person listed under two names, with one key,
// is one approver. The policy says so, and Check counts keys, not names.
func TestApproversMustHaveDistinctKeys(t *testing.T) {
	alice := newPerson(t, "alice")
	twin := person{name: "alice2", key: alice.key, pub: alice.pub}
	pol := Policy{Approvers: []Approver{{alice.name, alice.pub}, {twin.name, twin.pub}}, Required: 2}
	if ps := pol.Problems(); !strings.Contains(strings.Join(ps, " "), "same key") {
		t.Fatalf("two names with one key: %v", ps)
	}
	r, now := testRun(t), time.Now()
	_, err := Check(context.Background(), runner(), pol, r, now, []File{approve(t, alice, r, now, time.Hour), approve(t, twin, r, now, time.Hour)})
	if contract.CodeOf(err) != contract.SignFailed {
		t.Fatalf("one key under two names met required 2: %v", err)
	}
}
