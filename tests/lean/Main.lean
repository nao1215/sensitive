import Reference

open Embargo

def digits (s : String) : List Nat := s.toList.map (fun c => c.toNat - 48)
def padded (n width : Nat) : String :=
 let s := toString n
 String.ofList (List.replicate (width-s.length) '0') ++ s

def emit (fields : List String) : IO Unit := do
 (← IO.getStdout).putStrLn (String.intercalate "\t" fields)

def main : IO Unit := do
 for n in List.range 100 do
  for c in List.range 10 do
   let card := "4" ++ padded n 14 ++ toString c
   emit ["pan",card,toString (luhn (digits card))]
  let body := padded n 11
  let number := body ++ toString (myCheck (digits body))
  emit ["mynumber",number,"true"]
  for i in List.range 12 do
   let changed := String.ofList (number.toList.zipIdx.map fun (c,j) => if i==j then Char.ofNat (48+(c.toNat-48+1)%10) else c)
   emit ["mynumber",changed,toString (myCheck ((digits changed).take 11) == (digits changed)[11]!)]
  let account := padded n 18
  for check in List.range 100 do
   let text := "DE" ++ padded check 2 ++ account
   emit ["iban",text,toString (check ≥ 2 && check ≤ 98 && stream97 0 (digits (account ++ "1314" ++ padded check 2)) == 1)]
 -- Cover every selection of escaped bytes for a fixed ASCII email.
 for bits in List.range 128 do
  let chars := "a@b.com".toList
  let tokens := chars.zipIdx.map fun (c,i) =>
   if bits / 2^i % 2 == 0 then String.singleton c
   else "%" ++ String.ofList ["0123456789ABCDEF".toList[c.toNat/16]!, "0123456789ABCDEF".toList[c.toNat%16]!]
  let widths := List.replicate 6 1 ++ tokens.map String.length ++ [1]
  emit ["percent", "note (" ++ String.join tokens ++ ")", toString (position widths 6), toString (position widths 13)]
 for a in List.range 12 do
  for b in List.range 12 do
   let ranges := [(a,a+3),(b,b+4)]
   let original := "abcdefghijklmnop"
   let masked := String.ofList (original.toList.zipIdx.map fun (c,i) => maskByte ranges i c)
   emit ["mask", original, toString a, toString (a+3), toString b, toString (b+4), masked]
 emit ["mynumber","000000000000","true"]
 emit ["mynumber","200000000000","true"]
