// Regression test added by Seal for CVE-2026-33812. Upstream's fix
// (commit 854c274) shipped no test; this covers the source.view large-read
// probe that avoids a multi-MiB allocation for data the reader cannot satisfy.

package sfnt

import (
	"bytes"
	"testing"
)

// TestSourceViewLargeAllocGuard verifies that source.view rejects a >1MiB read
// whose backing io.ReaderAt is truncated, returning errInvalidBounds from the
// one-byte probe before allocating, while still serving a large read whose data
// is genuinely present.
func TestSourceViewLargeAllocGuard(t *testing.T) {
	const large = 8 << 20 // 8 MiB, comfortably over the 1<<20 guard threshold.

	// Truncated backing store: only 1 KiB present, but 8 MiB is requested.
	// Without the guard this would allocate 8 MiB up front; with it, the probe
	// read at end-1 fails first.
	truncated := &source{r: bytes.NewReader(make([]byte, 1024))}
	if _, err := truncated.view(nil, 0, large); err != errInvalidBounds {
		t.Errorf("view on truncated reader: got err %v, want errInvalidBounds", err)
	}

	// Legitimate large read: the backing store actually holds the bytes, so the
	// probe succeeds and the full length is returned.
	full := &source{r: bytes.NewReader(make([]byte, large))}
	b, err := full.view(nil, 0, large)
	if err != nil {
		t.Fatalf("view on full reader: unexpected err %v", err)
	}
	if len(b) != large {
		t.Errorf("view on full reader: got %d bytes, want %d", len(b), large)
	}
}
