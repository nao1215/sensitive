import Std

namespace Embargo
-- The textbook doubles a digit and adds its decimal digits. The optimized
-- reference subtracts nine instead; this lemma covers every decimal digit.
def doubleDigit (d : Nat) : Nat := if 2*d > 9 then 2*d-9 else 2*d

theorem double_textbook (d : Nat) (h : d < 10) :
    doubleDigit d = (2*d)/10 + (2*d)%10 := by
  unfold doubleDigit
  split <;> omega

-- Reduce all other digits to their residue. This finite proof applies at either
-- parity, for an arbitrary number of unchanged digits on either side.
set_option maxRecDepth 10000 in
set_option maxHeartbeats 0 in
theorem luhn_single_digit : ∀ (r a b : Fin 10) (twice : Bool), a ≠ b →
    (r.val + (if twice then doubleDigit a.val else a.val)) % 10 ≠
    (r.val + (if twice then doubleDigit b.val else b.val)) % 10 := by decide

def luhn (digits : List Nat) : Bool :=
  ((digits.reverse.zipIdx.map fun (d, i) => if i%2 == 1 then doubleDigit d else d).sum % 10) == 0

def decimal (n : Nat) : List Nat → Nat
 | [] => n
 | d :: ds => decimal (n*10+d) ds

def stream97 (n : Nat) : List Nat → Nat
 | [] => n%97
 | d :: ds => stream97 ((n*10+d)%97) ds

theorem mod97_step (n d : Nat) : ((n%97)*10+d)%97 = (n*10+d)%97 := by omega

theorem decimal_mod (ds : List Nat) (n : Nat) : decimal (n%97) ds % 97 = decimal n ds % 97 := by
 induction ds generalizing n with
 | nil => simp [decimal]
 | cons d ds ih =>
   simp only [decimal]
   have a := ih (n*10+d)
   have b := ih ((n%97)*10+d)
   rw [mod97_step] at b
   omega

theorem stream_textbook (ds : List Nat) (n : Nat) : stream97 n ds = decimal n ds % 97 := by
 induction ds generalizing n with
 | nil => rfl
 | cons d ds ih => simpa [stream97, decimal, decimal_mod] using ih ((n*10+d)%97)

-- One changed decimal digit contributes a nonzero residue for every possible
-- power of ten modulo 97. This covers arbitrary positions, without a length cap.
set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
theorem mod97_single_digit : ∀ (a b : Fin 10) (p : Fin 97),
 a ≠ b → p.val ≠ 0 → (a.val*p.val)%97 ≠ (b.val*p.val)%97 := by decide

theorem ten_preserves_nonzero : ∀ p : Fin 97,
 p.val ≠ 0 → (p.val * 10) % 97 ≠ 0 := by decide

theorem power_ten_nonzero (n : Nat) : 10^n % 97 ≠ 0 := by
 induction n with
 | zero => decide
 | succ n ih =>
   have h := ten_preserves_nonzero ⟨10^n % 97, Nat.mod_lt _ (by decide)⟩ ih
   simpa [Nat.pow_succ, Nat.mul_mod] using h

theorem unchanged_digits_cancel (r a b : Nat) (h : a % 97 ≠ b % 97) :
 (r+a) % 97 ≠ (r+b) % 97 := by omega

def myWeight (i : Nat) : Nat := i%6+2

theorem my_weight_textbook : ∀ i : Fin 11,
 myWeight i.val = if i.val < 6 then i.val+2 else i.val-4 := by decide

def myCheck (ds : List Nat) : Nat :=
 let r := (ds.reverse.zipIdx.map fun (d,i) => d * myWeight i).sum % 11
 if r ≤ 1 then 0 else 11-r

-- My Number merges residues zero and one. Rejecting every single digit change
-- is false, so proving that claim would certify a different algorithm.
theorem my_number_collision :
 myCheck [0,0,0,0,0,0,0,0,0,0,0] = myCheck [2,0,0,0,0,0,0,0,0,0,0] := by decide

-- Each decoded byte consumes one original byte or a three-byte escape. The
-- sentinel is the sum; invalid escapes are sequences of one-byte chunks.
def position : List Nat → Nat → Nat
 | [], _ => 0
 | _ :: _, 0 => 0
 | w :: ws, i+1 => w + position ws i

theorem position_monotone (ws : List Nat) (i j : Nat) (h : i ≤ j) : position ws i ≤ position ws j := by
 induction ws generalizing i j with
 | nil => simp [position]
 | cons w ws ih =>
   cases i <;> cases j <;> simp only [position]
   all_goals first | omega | exact Nat.add_le_add_left (ih _ _ (by omega)) _

theorem position_bound (ws : List Nat) (i : Nat) : position ws i ≤ ws.sum := by
 induction ws generalizing i with
 | nil => simp [position]
 | cons w ws ih => cases i <;> simp [position, Nat.add_le_add_left (ih _) w]

theorem mapped_range (ws : List Nat) (a b : Nat) (h : a ≤ b) :
 position ws a ≤ position ws b ∧ position ws b ≤ ws.sum :=
 ⟨position_monotone ws a b h, position_bound ws b⟩

def covered (ranges : List (Nat × Nat)) (i : Nat) : Bool :=
 ranges.any fun (a,b) => a ≤ i && i < b

def maskByte (ranges : List (Nat × Nat)) (i : Nat) (original : Char) : Char :=
 if covered ranges i then '*' else original

theorem covered_union (rs : List (Nat × Nat)) (i : Nat) :
 covered rs i = true ↔ ∃ r ∈ rs, r.1 ≤ i ∧ i < r.2 := by simp [covered, Bool.and_eq_true]

theorem outside_unchanged (rs : List (Nat × Nat)) (i : Nat) (c : Char)
 (h : ¬ ∃ r ∈ rs, r.1 ≤ i ∧ i < r.2) : maskByte rs i c = c := by
 simp [maskByte, show covered rs i = false from Bool.eq_false_iff.mpr (fun x => h ((covered_union rs i).mp x))]

theorem inside_replaced (rs : List (Nat × Nat)) (i : Nat) (c : Char)
 (h : ∃ r ∈ rs, r.1 ≤ i ∧ i < r.2) : maskByte rs i c = '*' := by
 simp [maskByte, (covered_union rs i).mpr h]
end Embargo
