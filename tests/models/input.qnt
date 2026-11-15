// Values are abstract IDs; byte copying and formatting are checked by replay.
module input {
 var s: { value: int, snapshot: int, failed: bool, op: str }
 action init = s' = { value: 0, snapshot: 0, failed: false, op: "init" }
 action step = {
  nondet op = Set("scanA", "scanB", "scanNil", "scanInvalid", "text", "marker", "json", "badJSON", "snapshot").oneOf()
  val bad = Set("scanInvalid", "marker", "badJSON").contains(op)
  val empty = bad or op == "scanNil"
  s' = { value: if (op == "snapshot") s.value else if (empty) 0 else if (op == "scanB") 2 else 1,
         snapshot: if (op == "snapshot") s.value else s.snapshot, failed: bad, op: op }
 }
 val invariant = (s.failed implies s.value == 0) and s.value.in(0.to(2)) and s.snapshot.in(0.to(2))
}
