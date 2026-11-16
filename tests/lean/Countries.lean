import Reference

namespace Embargo

def countryMod11 (ds : List Nat) (cycle : Nat) : Nat :=
 let r := (ds.reverse.zipIdx.map fun (d,i) => d*(2+i%cycle)).sum % 11
 if r < 2 then 0 else 11-r

def cpfCheck (ds : List Nat) : Nat :=
 (ds.zipIdx.map fun (d,i) => d*(i+1)).sum % 11 % 10

def cpfSecond (ds : List Nat) : Nat :=
 (ds.zipIdx.map fun (d,i) => d*i).sum % 11 % 10

def nhsCheck (ds : List Nat) : Nat :=
 (11 - (ds.zipIdx.map fun (d,i) => d*(10-i)).sum % 11) % 11

def chinaCheck (ds : List Nat) : Nat :=
 (12 - ds.foldl (fun r d => (r+d)*2%11) 0) % 11

def rrnCheck (ds : List Nat) : Nat :=
 (11 - (ds.zipIdx.map fun (d,i) => d*(2+i%8)).sum % 11) % 10

-- D5 is represented as five rotations followed by five reflections.
def d5 (a b : Nat) : Nat :=
 (a%5 + (if a < 5 then b%5 else 5-b%5))%5 +
 (if (a < 5) == (b < 5) then 0 else 5)

def verhoeffPermutation (d : Nat) : Nat := [1,5,7,6,2,8,3,0,9,4][d]!
def permute (n d : Nat) : Nat := (List.range n).foldl (fun v _ => verhoeffPermutation v) d

def verhoeff (ds : List Nat) : Bool :=
 (ds.reverse.zipIdx.foldl (fun state (d,i) => d5 state (permute (i%8) d)) 0) == 0

theorem d5_identity : ∀ d : Fin 10, d5 0 d.val = d.val := by decide

theorem permutation_period : ∀ d : Fin 10, permute 8 d.val = d.val := by decide

theorem mod11_digit_range : ∀ r : Fin 11, (if r.val < 2 then 0 else 11-r.val) < 10 := by decide

theorem nhs_rejects_ten : (11-1)%11 = 10 := by decide

-- These are references, not proofs that a registry issued a number or that the Go parser implements Lean.
end Embargo
