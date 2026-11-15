// Two named writers share a four-byte limit. Check closes registration; failed
// checks and writes after Check are sticky, and cleanup reports unchecked use.
module recorder {
 var s: { size: int, writers: Set[int], expected: Set[int], checked: bool, failed: bool, reported: bool, errors: int, op: str, which: int }
 action init = s' = { size: 0, writers: Set(), expected: Set(), checked: false, failed: false, reported: false, errors: 0, op: "init", which: 0 }
 action step = {
  nondet op = Set("write", "expect", "check", "cleanup").oneOf()
  nondet w = 0.to(1).oneOf()
  val invalid = s.checked and Set("write", "expect").contains(op)
  val overflow = op == "write" and s.size == 4
  val invalidCheck = op == "check" and (s.failed or s.size == 0 or s.expected == Set() or not(s.expected.subseteq(s.writers)))
  val cleanupError = op == "cleanup" and (not(s.checked) or (s.failed and not(s.reported)))
  s' = {
   size: if (op == "write" and not(s.checked) and s.size < 4) s.size + 1 else s.size,
   writers: if (op == "write" and not(s.checked)) s.writers.union(Set(w)) else s.writers,
   expected: if (op == "expect" and not(s.checked)) s.expected.union(Set(w)) else s.expected,
   checked: s.checked or op == "check",
   failed: s.failed or invalid or overflow or invalidCheck,
   reported: if (op == "check") invalidCheck else s.reported,
   errors: s.errors + (if (invalidCheck or cleanupError) 1 else 0),
   op: op, which: w
  }
 }
 val invariant = s.size.in(0.to(4)) and (s.reported implies s.failed)
}
