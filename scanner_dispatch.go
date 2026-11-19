package embargo

import (
	"cmp"
	"slices"

	"github.com/nao1215/embargo/internal/ascii"
	"github.com/nao1215/embargo/internal/detect"
)

type dispatchHint struct {
	hint []byte
	mask uint64
}

// dispatchBucket holds the hints that start with one lowered byte. Hintless
// entries and one-byte hints match on that byte; longer hints are sorted by
// their second byte, which second lists, so a lookup compares only the hints
// whose first two bytes match.
type dispatchBucket struct {
	long   []dispatchHint
	second []byte
	// short is the mask of the hintless entries and one-byte hints.
	short uint64
}

func newDispatchBucket(entries []dispatchHint) dispatchBucket {
	var bucket dispatchBucket
	for _, entry := range entries {
		if len(entry.hint) < len("ab") {
			bucket.short |= entry.mask
		} else {
			bucket.long = append(bucket.long, entry)
		}
	}
	slices.SortStableFunc(bucket.long, func(a, b dispatchHint) int { return cmp.Compare(a.hint[1], b.hint[1]) })
	for _, entry := range bucket.long {
		bucket.second = append(bucket.second, entry.hint[1])
	}
	return bucket
}

// buildDispatch compiles immutable first-byte buckets once per scanner. The
// selection mask has one bit per built-in, so there can be at most 64.
func (s *Scanner) buildDispatch() {
	var buckets [256][]dispatchHint
	for i, entries := range s.hintCache {
		mask := uint64(1) << i
		if len(entries) == 0 {
			starts := detect.StartBytes(s.detectors[i])
			if starts == nil {
				s.unconditional |= mask
			}
			for _, b := range starts {
				buckets[b] = append(buckets[b], dispatchHint{mask: mask})
			}
		}
		for _, entry := range entries {
			b := entry.lowered[0]
			buckets[b] = append(buckets[b], dispatchHint{hint: entry.lowered, mask: mask})
		}
	}
	// A dense table lets selectDetectors skip most bytes without loading a
	// bucket: follow holds the possible second bytes after each first byte,
	// and is empty when no hint starts with that byte.
	for b, bucket := range &buckets {
		s.follow[b] = followingBytes(bucket)
		s.hintIndex[b] = newDispatchBucket(bucket)
	}
}

// byteSet is a 256-bit membership table of wordBits-bit words.
type byteSet [4]uint64

const wordBits = 64

func (set *byteSet) add(b byte) { set[b/wordBits] |= 1 << (b % wordBits) }

func (set *byteSet) has(b byte) bool { return set[b/wordBits]&(1<<(b%wordBits)) != 0 }

// followingBytes returns the lowered second bytes of a bucket's hints; a
// one-byte or hintless entry can be followed by anything.
func followingBytes(bucket []dispatchHint) byteSet {
	var set byteSet
	for _, entry := range bucket {
		if len(entry.hint) < len("ab") {
			return byteSet{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
		}
		set.add(entry.hint[1])
	}
	return set
}

func (s *Scanner) selectDetectors(data []byte) uint64 {
	// A single detector benefits from the standard library substring search;
	// walking every byte through dispatch buckets would add work for no sharing.
	if len(s.detectors) == 1 {
		return s.selectSingleDetector(data)
	}
	selected := s.unconditional
	all := uint64(1)<<len(s.detectors) - 1
	last := len(data) - 1
	for i := 0; i < last && selected != all; i++ {
		b, next := ascii.ToLower(data[i]), ascii.ToLower(data[i+1])
		if !s.follow[b].has(next) {
			continue
		}
		bucket := &s.hintIndex[b]
		selected |= bucket.short
		// The second bytes are sorted, so the hints that can match sit together.
		for j := 0; j < len(bucket.second) && bucket.second[j] <= next; j++ {
			entry := &bucket.long[j]
			if bucket.second[j] == next && selected&entry.mask == 0 && len(entry.hint) <= len(data)-i && foldedPrefix(data[i+2:], entry.hint[2:]) {
				selected |= entry.mask
			}
		}
	}
	if last >= 0 {
		// The final byte only reaches the hints of one byte.
		selected |= s.hintIndex[ascii.ToLower(data[last])].short
	}
	return selected
}

// selectSingleDetector selects the only detector when any of its hints occurs
// in data, using one case-folded substring search instead of dispatch buckets.
func (s *Scanner) selectSingleDetector(data []byte) uint64 {
	var folded []byte
	var ready bool
	if matchesAnyHint(s.hintCache[0], data, &folded, &ready) {
		return 1
	}
	return 0
}

func foldedPrefix(data, hint []byte) bool {
	for i, b := range hint {
		if ascii.ToLower(data[i]) != b {
			return false
		}
	}
	return true
}
