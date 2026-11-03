package domain

import "context"

// FeatureFlag is one named platform switch as the edge reports it.
type FeatureFlag struct {
	Name        string
	Enabled     bool
	Description string
}

// FlagSet is the flag document with the version a client can cache against.
type FlagSet struct {
	Version string
	Flags   []FeatureFlag
}

// FlagSource reads the platform flag document from orbit-auth.
type FlagSource interface {
	ListFlags(ctx context.Context) (FlagSet, error)
}
