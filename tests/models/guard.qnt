// The parent retains both pipes under one limit, then checks complete streams.
// Abstract chunks have one byte. Replay uses larger chunks and the same limit.
module guard {
 var s: { sizes: List[int], leaks: Set[int], phase: int, overflow: bool, timeout: bool, scannerFailed: bool, exitFailed: bool, replay: Set[int], code: int, op: str, which: int }
 action init = s' = { sizes: [0,0], leaks: Set(), phase: 0, overflow: false, timeout: false, scannerFailed: false, exitFailed: false, replay: Set(), code: 0, op: "init", which: 0 }
 action capture = {
  // Favor writes so bounded replay reaches the shared limit before termination.
  // This changes sampling weights, not the possible transition relation.
  nondet choice = 0.to(11).oneOf()
  val op = ["safe", "safe", "safe", "safe", "leak", "leak", "leak", "leak", "finish", "timeout", "scannerFailure", "exitFailure"][choice]
  nondet w = 0.to(1).oneOf()
  val writing = Set("safe", "leak").contains(op)
  val full = s.sizes[0] + s.sizes[1] == 4
  all {
   s.phase == 0,
   op != "scannerFailure" or s.sizes[0] + s.sizes[1] > 0,
   s' = { ...s,
    sizes: if (writing and not(full)) s.sizes.replaceAt(w, s.sizes[w] + 1) else s.sizes,
    leaks: if (op == "leak") s.leaks.union(Set(w)) else s.leaks,
    overflow: s.overflow or (writing and full),
    phase: if (writing) 0 else 1,
    timeout: op == "timeout", scannerFailed: op == "scannerFailure", exitFailed: op == "exitFailure",
    op: op, which: w
   }
  }
 }
 action check = all {
  s.phase == 1,
  s' = { ...s, phase: 2, op: "check",
   code: if (s.overflow or s.timeout or s.scannerFailed or s.exitFailed or s.leaks != Set()) 1 else 0,
   replay: if (s.overflow or s.timeout or s.scannerFailed) Set() else Set(0,1).exclude(s.leaks)
  }
 }
 action done = all { s.phase == 2, s' = { ...s, op: "done" } }
 action step = any { capture, check, done }
 val invariant = s.sizes[0] + s.sizes[1] <= 4 and s.replay.intersect(s.leaks) == Set() and
  ((s.timeout or s.overflow or s.scannerFailed) implies s.replay == Set()) and
  (s.replay != Set() implies s.phase == 2)
}
