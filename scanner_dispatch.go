package embargo

import (
	"github.com/nao1215/embargo/internal/ascii"
	"github.com/nao1215/embargo/internal/detect"
)

type dispatchHint struct {
	hint []byte
	mask uint64
}

// buildDispatch compiles immutable first-byte buckets once per scanner. The
// selection mask has one bit per built-in, so there can be at most 64.
func (s *Scanner) buildDispatch() {
	for i, entries := range s.hintCache {
		mask := uint64(1) << i
		if len(entries) == 0 {
			starts := detect.StartBytes(s.detectors[i])
			if starts == nil {
				s.unconditional |= mask
			}
			for _, b := range starts {
				s.hintIndex[b] = append(s.hintIndex[b], dispatchHint{mask: mask})
			}
		}
		for _, entry := range entries {
			b := entry.lowered[0]
			s.hintIndex[b] = append(s.hintIndex[b], dispatchHint{hint: entry.lowered, mask: mask})
		}
	}
	// A dense table lets selectDetectors skip most bytes without loading a
	// bucket: follow holds the possible second bytes after each first byte,
	// and is empty when no hint starts with that byte.
	for b, bucket := range &s.hintIndex {
		s.follow[b] = followingBytes(bucket)
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

// mayStartHint reports whether data[i], already lowered as b, can begin a
// hint given the byte after it; the final byte only reaches its bucket.
func (s *Scanner) mayStartHint(data []byte, i int, b byte) bool {
	return i+1 == len(data) || s.follow[b].has(ascii.ToLower(data[i+1]))
}

func (s *Scanner) selectDetectors(data []byte) uint64 {
	// A single detector benefits from the standard library substring search;
	// walking every byte through dispatch buckets would add work for no sharing.
	if len(s.detectors) == 1 {
		return s.selectSingleDetector(data)
	}
	selected := s.unconditional
	all := uint64(1)<<len(s.detectors) - 1
	for i, b := range data {
		b = ascii.ToLower(b)
		if !s.mayStartHint(data, i, b) {
			continue
		}
		for _, entry := range s.hintIndex[b] {
			if selected&entry.mask != 0 || len(entry.hint) > len(data)-i {
				continue
			}
			if foldedPrefix(data[i:], entry.hint) {
				selected |= entry.mask
			}
		}
		if selected == all {
			break
		}
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
