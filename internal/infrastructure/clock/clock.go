// Package clock is the production domain.Clock adapter.
package clock

import "time"

// Clock reads the system wall clock.
type Clock struct{}

// New returns the system clock.
func New() Clock { return Clock{} }

// Now returns the current time.
func (Clock) Now() time.Time { return time.Now() }
