package cli

import (
	"context"
	"path/filepath"

	"github.com/sangehq/imprimatur/src/internal/events"
)

// logOnly writes an event to the event log without the bus's fan-out: for
// what the webhook outbox reports from inside the bus, where publishing again
// would deadlock or loop. Such events are local-class, so they never leave.
func (a *App) logOnly(short, subject string, data any) {
	d, err := a.dirs()
	if err != nil {
		return
	}
	id, err := events.InstallID(d.State)
	if err != nil {
		return
	}
	ev, err := events.Env{Now: a.Now, NewID: events.NewID, InstallID: id}.New(short, subject, data)
	if err != nil {
		return
	}
	if err := (events.Log{Dir: filepath.Join(d.State, "events")}).Write(context.Background(), ev); err != nil {
		a.say("events    %s not recorded: %v", short, err)
	}
}
