package db

import (
	"testing"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

func TestMemoryLimitFor(t *testing.T) {
	const mb = 1 << 20

	tests := []struct {
		name       string
		ecosystems []model.Ecosystem
		want       int64
	}{
		{
			// The measured case: 110 MB retained, and 330 MiB was the limit
			// that took peak RSS from 467 MB to 338 MB.
			name:       "npm sizes to its own index",
			ecosystems: []model.Ecosystem{model.EcosystemNPM},
			want:       330 * mb,
		},
		{
			// A limit sized for npm alone would bind on a project that loads
			// everything, which is why this is derived rather than fixed.
			name: "every ecosystem gets room for all of them",
			ecosystems: []model.Ecosystem{
				model.EcosystemNPM, model.EcosystemPyPI,
				model.EcosystemGo, model.EcosystemCrates,
			},
			want: (110 + 59 + 11 + 3) * 3 * mb,
		},
		{
			// Go retains 11 MB. Three times that would make the collector
			// work hard on a project that was never the problem.
			name:       "a small ecosystem gets the floor",
			ecosystems: []model.Ecosystem{model.EcosystemGo},
			want:       limitFloor,
		},
		{
			name:       "no ecosystems still gets the floor",
			ecosystems: nil,
			want:       limitFloor,
		},
		{
			// An ecosystem with no measurement contributes nothing rather than
			// producing a limit below what is already loaded.
			name:       "an unknown ecosystem does not shrink the limit",
			ecosystems: []model.Ecosystem{model.Ecosystem("Maven")},
			want:       limitFloor,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MemoryLimitFor(tt.ecosystems); got != tt.want {
				t.Errorf("MemoryLimitFor = %d MB, want %d MB", got/mb, tt.want/mb)
			}
		})
	}
}

func TestMemoryLimitIsRaisedOnlyOnce(t *testing.T) {
	// Every supported ecosystem must exceed the floor when combined, or the
	// derivation is doing nothing and a constant would be honest instead.
	all := []model.Ecosystem{
		model.EcosystemNPM, model.EcosystemPyPI,
		model.EcosystemGo, model.EcosystemCrates,
	}
	if MemoryLimitFor(all) <= MemoryLimitFor([]model.Ecosystem{model.EcosystemNPM}) {
		t.Error("loading everything must allow more heap than loading npm alone")
	}
}
