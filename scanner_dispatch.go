package embargo

import "github.com/nao1215/embargo/internal/ascii"

type dispatchHint struct {
	hint []byte
	mask uint64
}

// buildDispatch compiles immutable first-byte buckets once per scanner.
func (s *Scanner) buildDispatch() {
	for i, entries := range s.hintCache {
		mask := uint64(1) << i
		if len(entries) == 0 {
			switch Kind(s.detectors[i].Name()) { //nolint:exhaustive // Only hintless numeric detectors need extra dispatch constraints.
			case KindMyNumber, KindABARouting, KindUKSortCode:
				for b := byte('0'); b <= '9'; b++ {
					s.hintIndex[b] = append(s.hintIndex[b], dispatchHint{mask: mask})
				}
				s.hintIndex[0xef] = append(s.hintIndex[0xef], dispatchHint{mask: mask})
			default:
				s.unconditional |= mask
			}
		}
		for _, entry := range entries {
			b := entry.lowered[0]
			s.hintIndex[b] = append(s.hintIndex[b], dispatchHint{hint: entry.lowered, mask: mask})
		}
	}
	// A dense table lets selectDetectors skip most bytes without loading a bucket.
	for b, bucket := range s.hintIndex {
		s.hinted[b] = len(bucket) > 0
	}
}

func (s *Scanner) selectDetectors(data []byte) uint64 {
	// A single detector benefits from the standard library substring search;
	// walking every byte through dispatch buckets would add work for no sharing.
	if len(s.detectors) == 1 {
		var folded []byte
		var ready bool
		if matchesAnyHint(s.hintCache[0], data, &folded, &ready) {
			return 1
		}
		return 0
	}
	selected := s.unconditional
	all := uint64(1)<<len(s.detectors) - 1
	for i, b := range data {
		b = ascii.ToLower(b)
		if !s.hinted[b] {
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

func foldedPrefix(data, hint []byte) bool {
	for i, b := range hint {
		if ascii.ToLower(data[i]) != b {
			return false
		}
	}
	return true
}
