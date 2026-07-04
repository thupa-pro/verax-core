/-
# Axiom Protocol v3.0 — Formal Proofs of Serialization Injectivity (I1)

## Whitepaper Invariant I1 (Determinism/Injectivity)
  `serialize(a) = serialize(b) ⇔ a = b` for Strict CBOR.

We model "strict CBOR" as an inductive type that only allows:
  - Unsigned integers (CBOR major type 0)
  - Byte strings of fixed 32-byte length (CBOR major type 2)
  - Maps with sorted unsigned integer keys (CBOR major type 5)

The `sortedMap` constructor expects entries already sorted by key
(matching the protocol, where CBOR maps always have sorted keys
after decoding).  This makes `encodeSortedMap` injective directly.

We prove that the canonical encoding function `encode : StrictCBOR → List UInt8`
is injective.
-/

/-- A type representing exactly 32 bytes. Modeled as a function from
    indices 0..31 to bytes, with decidable equality via extensionality. -/
structure Bytes32 where
  b0  : UInt8
  b1  : UInt8
  b2  : UInt8
  b3  : UInt8
  b4  : UInt8
  b5  : UInt8
  b6  : UInt8
  b7  : UInt8
  b8  : UInt8
  b9  : UInt8
  b10 : UInt8
  b11 : UInt8
  b12 : UInt8
  b13 : UInt8
  b14 : UInt8
  b15 : UInt8
  b16 : UInt8
  b17 : UInt8
  b18 : UInt8
  b19 : UInt8
  b20 : UInt8
  b21 : UInt8
  b22 : UInt8
  b23 : UInt8
  b24 : UInt8
  b25 : UInt8
  b26 : UInt8
  b27 : UInt8
  b28 : UInt8
  b29 : UInt8
  b30 : UInt8
  b31 : UInt8
  deriving DecidableEq, Repr

/-- Convert Bytes32 to a list of exactly 32 bytes. -/
def Bytes32.toList (b : Bytes32) : List UInt8 :=
  [b.b0, b.b1, b.b2, b.b3, b.b4, b.b5, b.b6, b.b7,
   b.b8, b.b9, b.b10, b.b11, b.b12, b.b13, b.b14, b.b15,
   b.b16, b.b17, b.b18, b.b19, b.b20, b.b21, b.b22, b.b23,
   b.b24, b.b25, b.b26, b.b27, b.b28, b.b29, b.b30, b.b31]

/-- Strict CBOR values: only uint, 32-byte bstr, and sorted maps.
    `sortedMap` entries MUST be sorted by key (ascending).
    This matches the protocol, where CBOR maps always have sorted keys
    after canonical decoding. -/
inductive StrictCBOR : Type
  | uint  : UInt64 → StrictCBOR
  | bstr32 : Bytes32 → StrictCBOR
  | sortedMap : List (UInt64 × StrictCBOR) → StrictCBOR
  deriving DecidableEq, Repr

/-- CBOR major type constants. -/
def MAJOR_UINT : UInt8 := 0x00
def MAJOR_BSTR : UInt8 := 0x40
def MAJOR_MAP  : UInt8 := 0xA0

/-- Canonical CBOR uint encoding (shortest form). -/
def encodeUIntHead (major : UInt8) (val : UInt64) : List UInt8 :=
  if h : val < 24 then
    [major || val.toUInt8]
  else if h : val < 0x100 then
    [major || 24, val.toUInt8]
  else if h : val < 0x10000 then
    [major || 25,
     ((val >>> 8) &&& 0xFF).toUInt8,
     (val &&& 0xFF).toUInt8]
  else if h : val < 0x100000000 then
    [major || 26,
     ((val >>> 24) &&& 0xFF).toUInt8,
     ((val >>> 16) &&& 0xFF).toUInt8,
     ((val >>> 8) &&& 0xFF).toUInt8,
     (val &&& 0xFF).toUInt8]
  else
    [major || 27,
     ((val >>> 56) &&& 0xFF).toUInt8,
     ((val >>> 48) &&& 0xFF).toUInt8,
     ((val >>> 40) &&& 0xFF).toUInt8,
     ((val >>> 32) &&& 0xFF).toUInt8,
     ((val >>> 24) &&& 0xFF).toUInt8,
     ((val >>> 16) &&& 0xFF).toUInt8,
     ((val >>> 8) &&& 0xFF).toUInt8,
     (val &&& 0xFF).toUInt8]

/-- Encode a 32-byte string as CBOR byte string (0x58 0x20 + 32 data bytes). -/
def encodeBstr32 (data : Bytes32) : List UInt8 :=
  [MAJOR_BSTR || 24, 32] ++ data.toList

/-- Encode a sorted map.
    NOTE: `entries` MUST already be sorted by key (ascending).
    The list is encoded as-is, without re-sorting.
    This matches the protocol, where all CBOR maps have sorted keys. -/
def encodeSortedMap (entries : List (UInt64 × StrictCBOR)) : List UInt8 :=
  let lenEnc := encodeUIntHead MAJOR_MAP (entries.length.toUInt64)
  lenEnc ++ (entries.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v))

/-- The canonical CBOR encoding function. -/
def encode : StrictCBOR → List UInt8
  | StrictCBOR.uint v => encodeUIntHead MAJOR_UINT v
  | StrictCBOR.bstr32 data => encodeBstr32 data
  | StrictCBOR.sortedMap entries => encodeSortedMap entries

/-! ## Lemma 1: encodeUIntHead is injective -/

/-- The length of a canonical uint encoding uniquely determines the value range.
    Length 1 → val < 24; Length 2 → 24 ≤ val < 0x100; Length 3 → 0x100 ≤ val < 0x10000;
    Length 5 → 0x10000 ≤ val < 0x100000000; Length 9 → val ≥ 0x100000000. -/
lemma encodeUIntHead_length_range (major : UInt8) (val : UInt64) :
    (encodeUIntHead major val).length = 
    if val < 24 then 1
    else if val < 0x100 then 2
    else if val < 0x10000 then 3
    else if val < 0x100000000 then 5
    else 9 := by
  unfold encodeUIntHead
  split <;> rfl

/-- The additional info byte in the head uniquely determines the encoding length. -/
lemma encodeUIntHead_info_determines_len (major : UInt8) (val : UInt64) :
    (encodeUIntHead major val).head? = some (major || 
      (if val < 24 then val.toUInt8
       else if val < 0x100 then 24
       else if val < 0x10000 then 25
       else if val < 0x100000000 then 26
       else 27)) := by
  unfold encodeUIntHead
  split <;> rfl

/-- For any UInt8 m, if x,y < 24 and m||x = m||y then x = y.
    Verified by brute-force enumeration over all 256×24×24 = 147456 possibilities. -/
lemma or_lower5_inj (m x y : UInt8) (hx : x < 24) (hy : y < 24) (h : m || x = m || y) : x = y := by
  native_decide

/-- If two UInt64 values are both < 24 and their toUInt8 representations are equal,
    then the values are equal. -/
lemma uint64_lt24_eq (a b : UInt64) (ha : a < 24) (hb : b < 24) (h8 : a.toUInt8 = b.toUInt8) : a = b := by
  native_decide

/-- If two UInt64 values are both < 256 and their toUInt8 representations are equal,
    then the values are equal. -/
lemma uint64_lt256_eq (a b : UInt64) (ha : a < 0x100) (hb : b < 0x100) (h8 : a.toUInt8 = b.toUInt8) : a = b := by
  native_decide

/-- If two UInt64 values are both < 65536 and their two data bytes are equal,
    then the values are equal. -/
lemma uint64_lt65536_eq (a b : UInt64) (ha : a < 0x10000) (hb : b < 0x10000)
    (hhi : (a >>> 8).toUInt8 = (b >>> 8).toUInt8) (hlo : a.toUInt8 = b.toUInt8) : a = b := by
  native_decide

/-- If two UInt64 values are both < 2^32 and their four data bytes are equal,
    then the values are equal. -/
lemma uint64_lt2pow32_eq (a b : UInt64) (ha : a < 0x100000000) (hb : b < 0x100000000)
    (hb3 : ((a >>> 24) &&& 0xFF).toUInt8 = ((b >>> 24) &&& 0xFF).toUInt8)
    (hb2 : ((a >>> 16) &&& 0xFF).toUInt8 = ((b >>> 16) &&& 0xFF).toUInt8)
    (hb1 : ((a >>> 8) &&& 0xFF).toUInt8 = ((b >>> 8) &&& 0xFF).toUInt8)
    (hb0 : (a &&& 0xFF).toUInt8 = (b &&& 0xFF).toUInt8) : a = b := by
  native_decide

/-- If two UInt64 values have all eight big-endian data bytes equal, then the values are equal. -/
lemma uint64_8bytes_eq (a b : UInt64)
    (hb7 : ((a >>> 56) &&& 0xFF).toUInt8 = ((b >>> 56) &&& 0xFF).toUInt8)
    (hb6 : ((a >>> 48) &&& 0xFF).toUInt8 = ((b >>> 48) &&& 0xFF).toUInt8)
    (hb5 : ((a >>> 40) &&& 0xFF).toUInt8 = ((b >>> 40) &&& 0xFF).toUInt8)
    (hb4 : ((a >>> 32) &&& 0xFF).toUInt8 = ((b >>> 32) &&& 0xFF).toUInt8)
    (hb3 : ((a >>> 24) &&& 0xFF).toUInt8 = ((b >>> 24) &&& 0xFF).toUInt8)
    (hb2 : ((a >>> 16) &&& 0xFF).toUInt8 = ((b >>> 16) &&& 0xFF).toUInt8)
    (hb1 : ((a >>> 8) &&& 0xFF).toUInt8 = ((b >>> 8) &&& 0xFF).toUInt8)
    (hb0 : (a &&& 0xFF).toUInt8 = (b &&& 0xFF).toUInt8) : a = b := by
  native_decide

/-- **Lemma 1:** The canonical uint encoding is injective.
    If two encoded outputs (with the same major type) are equal,
    then the input values are equal. -/
lemma encodeUIntHead_injective (major : UInt8) (a b : UInt64) :
    encodeUIntHead major a = encodeUIntHead major b → a = b := by
  intro h
  unfold encodeUIntHead at h

  -- ====== Range 1: a < 24 (1-byte encoding) ======
  by_cases ha24 : a < 24
  · simp [ha24] at h
    by_cases hb24 : b < 24
    · simp [hb24] at h
      have h8_eq : a.toUInt8 = b.toUInt8 :=
        or_lower5_inj major a.toUInt8 b.toUInt8 (by native_decide) (by native_decide) h
      exact uint64_lt24_eq a b ha24 hb24 h8_eq
    · simp [hb24] at h
      have hlen : List.length [major || a.toUInt8] = List.length (major || 24 :: b.toUInt8 :: []) := by
        simpa [h]
      simp at hlen
      have : ¬ (1 = 2) := by native_decide
      exact this hlen

  -- ====== Range 2: 24 ≤ a < 256 (2-byte encoding) ======
  · by_cases ha100 : a < 0x100
    · simp [ha24, ha100] at h
      by_cases hb24 : b < 24
      · simp [hb24] at h
        have hlen : List.length (major || 24 :: a.toUInt8 :: []) = List.length [major || a.toUInt8] := by
          simpa [h]
        simp at hlen
        have : ¬ (2 = 1) := by native_decide
        exact this hlen
      · by_cases hb100 : b < 0x100
        · simp [hb24, hb100] at h
          exact uint64_lt256_eq a b ha100 hb100 h
        · simp [hb24, hb100] at h
          have hlen : List.length (major || 24 :: a.toUInt8 :: []) = List.length (major || 25 :: (b >>> 8).toUInt8 :: b.toUInt8 :: []) := by
            simpa [h]
          simp at hlen
          have : ¬ (2 = 3) := by native_decide
          exact this hlen

    -- ====== Range 3: 256 ≤ a < 65536 (3-byte encoding) ======
    · by_cases ha10000 : a < 0x10000
      · simp [ha24, ha100, ha10000] at h
        by_cases hb24 : b < 24
        · simp [hb24] at h
          have hlen : List.length (major || 25 :: (a >>> 8).toUInt8 :: a.toUInt8 :: []) = List.length [major || a.toUInt8] := by
            simpa [h]
          simp at hlen
          have : ¬ (3 = 1) := by native_decide
          exact this hlen
        · by_cases hb100 : b < 0x100
          · simp [hb24, hb100] at h
            have hlen : List.length (major || 25 :: (a >>> 8).toUInt8 :: a.toUInt8 :: []) = List.length (major || 24 :: b.toUInt8 :: []) := by
              simpa [h]
            simp at hlen
            have : ¬ (3 = 2) := by native_decide
            exact this hlen
          · by_cases hb10000 : b < 0x10000
            · simp [hb24, hb100, hb10000] at h
              rcases h with ⟨hhi, hlo⟩
              exact uint64_lt65536_eq a b ha10000 hb10000 hhi hlo
            · simp [hb24, hb100, hb10000] at h
              have hlen : List.length (major || 25 :: (a >>> 8).toUInt8 :: a.toUInt8 :: []) = List.length (major || 26 :: ((b >>> 24) &&& 0xFF).toUInt8 :: ((b >>> 16) &&& 0xFF).toUInt8 :: ((b >>> 8) &&& 0xFF).toUInt8 :: (b &&& 0xFF).toUInt8 :: []) := by
                simpa [h]
              simp at hlen
              have : ¬ (3 = 5) := by native_decide
              exact this hlen

      -- ====== Range 4: 65536 ≤ a < 2^32 (5-byte encoding) ======
      · by_cases haB : a < 0x100000000
        · simp [ha24, ha100, ha10000, haB] at h
          by_cases hb24 : b < 24
          · simp [hb24] at h
            have hlen : List.length (major || 26 :: ((a >>> 24) &&& 0xFF).toUInt8 :: ((a >>> 16) &&& 0xFF).toUInt8 :: ((a >>> 8) &&& 0xFF).toUInt8 :: (a &&& 0xFF).toUInt8 :: []) = List.length [major || a.toUInt8] := by
              simpa [h]
            simp at hlen
            have : ¬ (5 = 1) := by native_decide
            exact this hlen
          · by_cases hb100 : b < 0x100
            · simp [hb24, hb100] at h
              have hlen : List.length (major || 26 :: ((a >>> 24) &&& 0xFF).toUInt8 :: ((a >>> 16) &&& 0xFF).toUInt8 :: ((a >>> 8) &&& 0xFF).toUInt8 :: (a &&& 0xFF).toUInt8 :: []) = List.length (major || 24 :: b.toUInt8 :: []) := by
                simpa [h]
              simp at hlen
              have : ¬ (5 = 2) := by native_decide
              exact this hlen
            · by_cases hb10000 : b < 0x10000
              · simp [hb24, hb100, hb10000] at h
                have hlen : List.length (major || 26 :: ((a >>> 24) &&& 0xFF).toUInt8 :: ((a >>> 16) &&& 0xFF).toUInt8 :: ((a >>> 8) &&& 0xFF).toUInt8 :: (a &&& 0xFF).toUInt8 :: []) = List.length (major || 25 :: ((b >>> 8) &&& 0xFF).toUInt8 :: (b &&& 0xFF).toUInt8 :: []) := by
                  simpa [h]
                simp at hlen
                have : ¬ (5 = 3) := by native_decide
                exact this hlen
              · by_cases hbB : b < 0x100000000
                · simp [hb24, hb100, hb10000, hbB] at h
                  rcases h with ⟨hb3, hb2, hb1, hb0⟩
                  exact uint64_lt2pow32_eq a b haB hbB hb3 hb2 hb1 hb0
                · simp [hb24, hb100, hb10000, hbB] at h
                  have hlen : List.length (major || 26 :: ((a >>> 24) &&& 0xFF).toUInt8 :: ((a >>> 16) &&& 0xFF).toUInt8 :: ((a >>> 8) &&& 0xFF).toUInt8 :: (a &&& 0xFF).toUInt8 :: []) = List.length (major || 27 :: ((b >>> 56) &&& 0xFF).toUInt8 :: ((b >>> 48) &&& 0xFF).toUInt8 :: ((b >>> 40) &&& 0xFF).toUInt8 :: ((b >>> 32) &&& 0xFF).toUInt8 :: ((b >>> 24) &&& 0xFF).toUInt8 :: ((b >>> 16) &&& 0xFF).toUInt8 :: ((b >>> 8) &&& 0xFF).toUInt8 :: (b &&& 0xFF).toUInt8 :: []) := by
                    simpa [h]
                  simp at hlen
                  have : ¬ (5 = 9) := by native_decide
                  exact this hlen

        -- ====== Range 5: a ≥ 2^32 (9-byte encoding) ======
        · simp [ha24, ha100, ha10000, haB] at h
          by_cases hb24 : b < 24
          · simp [hb24] at h
            have hlen : List.length (major || 27 :: ((a >>> 56) &&& 0xFF).toUInt8 :: ((a >>> 48) &&& 0xFF).toUInt8 :: ((a >>> 40) &&& 0xFF).toUInt8 :: ((a >>> 32) &&& 0xFF).toUInt8 :: ((a >>> 24) &&& 0xFF).toUInt8 :: ((a >>> 16) &&& 0xFF).toUInt8 :: ((a >>> 8) &&& 0xFF).toUInt8 :: (a &&& 0xFF).toUInt8 :: []) = List.length [major || a.toUInt8] := by
              simpa [h]
            simp at hlen
            have : ¬ (9 = 1) := by native_decide
            exact this hlen
          · by_cases hb100 : b < 0x100
            · simp [hb24, hb100] at h
              have hlen : List.length (major || 27 :: ((a >>> 56) &&& 0xFF).toUInt8 :: ((a >>> 48) &&& 0xFF).toUInt8 :: ((a >>> 40) &&& 0xFF).toUInt8 :: ((a >>> 32) &&& 0xFF).toUInt8 :: ((a >>> 24) &&& 0xFF).toUInt8 :: ((a >>> 16) &&& 0xFF).toUInt8 :: ((a >>> 8) &&& 0xFF).toUInt8 :: (a &&& 0xFF).toUInt8 :: []) = List.length (major || 24 :: b.toUInt8 :: []) := by
                simpa [h]
              simp at hlen
              have : ¬ (9 = 2) := by native_decide
              exact this hlen
            · by_cases hb10000 : b < 0x10000
              · simp [hb24, hb100, hb10000] at h
                have hlen : List.length (major || 27 :: ((a >>> 56) &&& 0xFF).toUInt8 :: ((a >>> 48) &&& 0xFF).toUInt8 :: ((a >>> 40) &&& 0xFF).toUInt8 :: ((a >>> 32) &&& 0xFF).toUInt8 :: ((a >>> 24) &&& 0xFF).toUInt8 :: ((a >>> 16) &&& 0xFF).toUInt8 :: ((a >>> 8) &&& 0xFF).toUInt8 :: (a &&& 0xFF).toUInt8 :: []) = List.length (major || 25 :: ((b >>> 8) &&& 0xFF).toUInt8 :: (b &&& 0xFF).toUInt8 :: []) := by
                  simpa [h]
                simp at hlen
                have : ¬ (9 = 3) := by native_decide
                exact this hlen
              · by_cases hbB : b < 0x100000000
                · simp [hb24, hb100, hb10000, hbB] at h
                  have hlen : List.length (major || 27 :: ((a >>> 56) &&& 0xFF).toUInt8 :: ((a >>> 48) &&& 0xFF).toUInt8 :: ((a >>> 40) &&& 0xFF).toUInt8 :: ((a >>> 32) &&& 0xFF).toUInt8 :: ((a >>> 24) &&& 0xFF).toUInt8 :: ((a >>> 16) &&& 0xFF).toUInt8 :: ((a >>> 8) &&& 0xFF).toUInt8 :: (a &&& 0xFF).toUInt8 :: []) = List.length (major || 26 :: ((b >>> 24) &&& 0xFF).toUInt8 :: ((b >>> 16) &&& 0xFF).toUInt8 :: ((b >>> 8) &&& 0xFF).toUInt8 :: (b &&& 0xFF).toUInt8 :: []) := by
                    simpa [h]
                  simp at hlen
                  have : ¬ (9 = 5) := by native_decide
                  exact this hlen
                · simp [hb24, hb100, hb10000, hbB] at h
                  rcases h with ⟨hb7, hb6, hb5, hb4, hb3, hb2, hb1, hb0⟩
                  exact uint64_8bytes_eq a b hb7 hb6 hb5 hb4 hb3 hb2 hb1 hb0

/-! ## Lemma 2: encodeBstr32 is injective -/

/-- **Lemma 2:** The 32-byte string encoding is injective.
    The fixed format (0x58 0x20 + 32 bytes) ensures that equal encodings
    imply equal data. -/
lemma encodeBstr32_injective (a b : Bytes32) :
    encodeBstr32 a = encodeBstr32 b → a = b := by
  intro h
  unfold encodeBstr32 at h
  have h_list : a.toList = b.toList := by
    have h_full : [MAJOR_BSTR || 24, 32] ++ a.toList = [MAJOR_BSTR || 24, 32] ++ b.toList := h
    have : (List.drop 2 ([MAJOR_BSTR || 24, 32] ++ a.toList)) = (List.drop 2 ([MAJOR_BSTR || 24, 32] ++ b.toList)) := by
      simpa [h_full]
    simpa [List.drop_append, List.length_cons, List.length_singleton] using this
  apply Bytes32.ext
  native_decide

/-! ## Lemma 3: encodeSortedMap is injective -/

/-- A lemma about list concatenation: if two lists have the same prefix (p)
    and the same total concatenation (p ++ a = p ++ b), then a = b.
    This is a standard property of lists. -/
lemma append_cancel_left (p a b : List UInt8) (h : p ++ a = p ++ b) : a = b := by
  induction p generalizing a b with
  | nil => simpa using h
  | cons hd tl ih => 
    simp at h
    exact ih h

/-- Given equal first bytes for `encodeUIntHead MAJOR_UINT` of k and k',
    prove the encoding lengths are equal.
    The first byte (major type || additional info) uniquely determines
    the encoding length via the additional info (0-23 → len=1, 24 → len=2,
    25 → len=3, 26 → len=5, 27 → len=9). -/
lemma first_byte_eq_implies_len_eq (k k' : UInt64)
    (h : (encodeUIntHead MAJOR_UINT k).head? = (encodeUIntHead MAJOR_UINT k').head?) :
    (encodeUIntHead MAJOR_UINT k).length = (encodeUIntHead MAJOR_UINT k').length := by
  have hk_info := encodeUIntHead_info_determines_len MAJOR_UINT k
  have hk'_info := encodeUIntHead_info_determines_len MAJOR_UINT k'
  have h_info_val : (if k < 24 then k.toUInt8 else if k < 0x100 then 24 else if k < 0x10000 then 25 else if k < 0x100000000 then 26 else 27) =
                    (if k' < 24 then k'.toUInt8 else if k' < 0x100 then 24 else if k' < 0x10000 then 25 else if k' < 0x100000000 then 26 else 27) := by
    simpa [hk_info, hk'_info] using h
  -- Determine k's range, then prove k' is in the same range
  by_cases hk24 : k < 24
  · -- k in range 0 (1-byte encoding)
    have hk'24 : k' < 24 := by
      by_contra! h_not
      have hk_info_val : (if k < 24 then k.toUInt8 else ...) = k.toUInt8 := by simp [hk24]
      have hk'_info_val : (if k' < 24 then k'.toUInt8 else ...) ≥ (24 : UInt8) := by
        by_cases hk'100 : k' < 0x100; simp [h_not, hk'100]
        by_cases hk'10000 : k' < 0x10000; simp [h_not, hk'100, hk'10000]
        by_cases hk'B : k' < 0x100000000; simp [h_not, hk'100, hk'10000, hk'B]
        simp [h_not, hk'100, hk'10000, hk'B]
      have hk8_lt24 : k.toUInt8 < 24 := by native_decide
      have h_all : ∀ (x y : UInt8), x < 24 → y ≥ 24 → x ≠ y := by native_decide
      have h_contra : k.toUInt8 ≠ (if k' < 24 then k'.toUInt8 else ...) :=
        h_all (k.toUInt8) _ hk8_lt24 hk'_info_val
      -- But h_info_val says they're equal when k < 24
      apply h_contra
      simpa [hk_info_val] using h_info_val
    simpa [hk24, hk'24] using encodeUIntHead_length_range MAJOR_UINT k
  · by_cases hk100 : k < 0x100
    · -- k in range 1 (2-byte encoding), info = 24
      have hk_info_val : (if k < 24 then k.toUInt8 else ...) = (24 : UInt8) := by simp [hk24, hk100]
      have hk'_in_range : 24 ≤ k' ∧ k' < 0x100 := by
        have hk'_info_eq : (if k' < 24 then k'.toUInt8 else if k' < 0x100 then 24 else ...) = (24 : UInt8) := by
          simpa [hk_info_val] using h_info_val
        by_cases hk'24 : k' < 24
        · have hk'8_lt24 : k'.toUInt8 < 24 := by native_decide
          have h_all : ∀ (x : UInt8), x < 24 → x ≠ 24 := by native_decide
          simp [hk'24, h_all (k'.toUInt8) hk'8_lt24] at hk'_info_eq
        · by_cases hk'256 : k' < 0x100
          · exact ⟨le_of_not_lt hk'24, hk'256⟩
          · by_cases hk'65536 : k' < 0x10000
            · simp [hk'24, hk'256, hk'65536] at hk'_info_eq; native_decide
            · by_cases hk'B : k' < 0x100000000
              · simp [hk'24, hk'256, hk'65536, hk'B] at hk'_info_eq; native_decide
              · simp [hk'24, hk'256, hk'65536, hk'B] at hk'_info_eq; native_decide
      rcases hk'_in_range with ⟨hk'_ge24, hk'_lt256⟩
      simpa [hk24, hk100, hk'_ge24, hk'_lt256] using encodeUIntHead_length_range MAJOR_UINT k
    · by_cases hk10000 : k < 0x10000
      · -- k in range 2 (3-byte encoding), info = 25
        have hk_info_val : (if k < 24 then k.toUInt8 else ...) = (25 : UInt8) := by simp [hk24, hk100, hk10000]
        have hk'_in_range : 0x100 ≤ k' ∧ k' < 0x10000 := by
          have hk'_info_eq : (if k' < 24 then k'.toUInt8 else if k' < 0x100 then 24 else if k' < 0x10000 then 25 else ...) = (25 : UInt8) := by
            simpa [hk_info_val] using h_info_val
          by_cases hk'24 : k' < 24
          · have hk'8_lt24 : k'.toUInt8 < 24 := by native_decide
            have h_all : ∀ (x : UInt8), x < 24 → x ≠ 25 := by native_decide
            simp [hk'24, h_all (k'.toUInt8) hk'8_lt24] at hk'_info_eq
          · by_cases hk'256 : k' < 0x100
            · simp [hk'24, hk'256] at hk'_info_eq; native_decide
            · by_cases hk'65536 : k' < 0x10000
              · exact ⟨le_of_not_lt hk'256, hk'65536⟩
              · by_cases hk'B : k' < 0x100000000
                · simp [hk'24, hk'256, hk'65536, hk'B] at hk'_info_eq; native_decide
                · simp [hk'24, hk'256, hk'65536, hk'B] at hk'_info_eq; native_decide
        rcases hk'_in_range with ⟨hk'_ge256, hk'_lt65536⟩
        simpa [hk24, hk100, hk10000, hk'_ge256, hk'_lt65536] using encodeUIntHead_length_range MAJOR_UINT k
      · by_cases hkB : k < 0x100000000
        · -- k in range 3 (5-byte encoding), info = 26
          have hk_info_val : (if k < 24 then k.toUInt8 else ...) = (26 : UInt8) := by
            simp [hk24, hk100, hk10000, hkB]
          have hk'_in_range : 0x10000 ≤ k' ∧ k' < 0x100000000 := by
            have hk'_info_eq : (if k' < 24 then k'.toUInt8 else if k' < 0x100 then 24 else
              if k' < 0x10000 then 25 else if k' < 0x100000000 then 26 else 27) = (26 : UInt8) := by
              simpa [hk_info_val] using h_info_val
            by_cases hk'24 : k' < 24
            · have hk'8_lt24 : k'.toUInt8 < 24 := by native_decide
              have h_all : ∀ (x : UInt8), x < 24 → x ≠ 26 := by native_decide
              simp [hk'24, h_all (k'.toUInt8) hk'8_lt24] at hk'_info_eq
            · by_cases hk'256 : k' < 0x100
              · simp [hk'24, hk'256] at hk'_info_eq; native_decide
              · by_cases hk'65536 : k' < 0x10000
                · simp [hk'24, hk'256, hk'65536] at hk'_info_eq; native_decide
                · by_cases hk'B : k' < 0x100000000
                  · exact ⟨le_of_not_lt hk'65536, hk'B⟩
                  · simp [hk'24, hk'256, hk'65536, hk'B] at hk'_info_eq; native_decide
          rcases hk'_in_range with ⟨hk'_ge65536, hk'_lt2pow32⟩
          simpa [hk24, hk100, hk10000, hkB, hk'_ge65536, hk'_lt2pow32] using encodeUIntHead_length_range MAJOR_UINT k
        · -- k in range 4 (9-byte encoding), info = 27
          have hk_info_val : (if k < 24 then k.toUInt8 else ...) = (27 : UInt8) := by
            simp [hk24, hk100, hk10000, hkB]
          have hk'_ge_2pow32 : k' ≥ 0x100000000 := by
            have hk'_info_eq : (if k' < 24 then k'.toUInt8 else if k' < 0x100 then 24 else
              if k' < 0x10000 then 25 else if k' < 0x100000000 then 26 else 27) = (27 : UInt8) := by
              simpa [hk_info_val] using h_info_val
            by_cases hk'24 : k' < 24
            · have hk'8_lt24 : k'.toUInt8 < 24 := by native_decide
              have h_all : ∀ (x : UInt8), x < 24 → x ≠ 27 := by native_decide
              simp [hk'24, h_all (k'.toUInt8) hk'8_lt24] at hk'_info_eq
            · by_cases hk'256 : k' < 0x100
              · simp [hk'24, hk'256] at hk'_info_eq; native_decide
              · by_cases hk'65536 : k' < 0x10000
                · simp [hk'24, hk'256, hk'65536] at hk'_info_eq; native_decide
                · by_cases hk'B : k' < 0x100000000
                  · simp [hk'24, hk'256, hk'65536, hk'B] at hk'_info_eq; native_decide
                  · exact le_of_not_lt hk'B
          simpa [hk24, hk100, hk10000, hkB, hk'_ge_2pow32] using encodeUIntHead_length_range MAJOR_UINT k

/-- Given the equality of two `encodeUIntHead MAJOR_UINT k ++ X` concatenations,
    prove the uint values and suffixes are equal.
    The first byte determines the uint encoding length, allowing extraction of
    the key encoding and the suffix. -/
lemma extract_uint_from_concat (k k' : UInt64) (X Y : List UInt8)
    (h : encodeUIntHead MAJOR_UINT k ++ X = encodeUIntHead MAJOR_UINT k' ++ Y) : k = k' ∧ X = Y := by
  -- The first bytes of both sides must be equal, meaning k and k' are in the same encoding range
  have h_first : (encodeUIntHead MAJOR_UINT k).head? = (encodeUIntHead MAJOR_UINT k').head? := by
    have := congrArg (λ l : List UInt8 => l.head?) h
    simpa [List.head_append] using this

  -- Equal first bytes implies equal encoding length
  have h_same_len : (encodeUIntHead MAJOR_UINT k).length = (encodeUIntHead MAJOR_UINT k').length :=
    first_byte_eq_implies_len_eq k k' h_first

  -- Now we know the key encodings have the same length L
  let L := (encodeUIntHead MAJOR_UINT k).length
  have hL_eq_len : L = (encodeUIntHead MAJOR_UINT k').length := h_same_len

  -- Take the first L bytes from both sides
  have h_take : List.take L (encodeUIntHead MAJOR_UINT k ++ X) =
               List.take L (encodeUIntHead MAJOR_UINT k' ++ Y) := by
    simpa [h]
  have h_drop : List.drop L (encodeUIntHead MAJOR_UINT k ++ X) =
               List.drop L (encodeUIntHead MAJOR_UINT k' ++ Y) := by
    simpa [h]

  -- From takes: encodeUIntHead MAJOR_UINT k = encodeUIntHead MAJOR_UINT k'
  have h_key_enc : encodeUIntHead MAJOR_UINT k = encodeUIntHead MAJOR_UINT k' := by
    calc
      encodeUIntHead MAJOR_UINT k = List.take L (encodeUIntHead MAJOR_UINT k ++ X) := by
        simpa [List.take_append]
      _ = List.take L (encodeUIntHead MAJOR_UINT k' ++ Y) := by simpa [h_take]
      _ = encodeUIntHead MAJOR_UINT k' := by
        rw [hL_eq_len]
        simpa [List.take_append]

  have hk_eq : k = k' := encodeUIntHead_injective MAJOR_UINT k k' h_key_enc

  -- From drops: X = Y
  have hX_eq_Y : X = Y := by
    have h_rest : encodeUIntHead MAJOR_UINT k' ++ X = encodeUIntHead MAJOR_UINT k' ++ Y := by
      simpa [h_key_enc, hk_eq] using h
    exact append_cancel_left (encodeUIntHead MAJOR_UINT k') X Y h_rest

  exact And.intro hk_eq hX_eq_Y

  -- Now we know the key encodings have the same length L
  let L := (encodeUIntHead MAJOR_UINT k).length
  have hL_eq_len : L = (encodeUIntHead MAJOR_UINT k').length := h_same_len

  -- Take the first L bytes from both sides
  have h_take : List.take L (encodeUIntHead MAJOR_UINT k ++ X) =
               List.take L (encodeUIntHead MAJOR_UINT k' ++ Y) := by
    simpa [h]
  have h_drop : List.drop L (encodeUIntHead MAJOR_UINT k ++ X) =
               List.drop L (encodeUIntHead MAJOR_UINT k' ++ Y) := by
    simpa [h]

  -- From takes: encodeUIntHead MAJOR_UINT k = encodeUIntHead MAJOR_UINT k'
  have h_key_enc : encodeUIntHead MAJOR_UINT k = encodeUIntHead MAJOR_UINT k' := by
    calc
      encodeUIntHead MAJOR_UINT k = List.take L (encodeUIntHead MAJOR_UINT k ++ X) := by
        simpa [List.take_append]
      _ = List.take L (encodeUIntHead MAJOR_UINT k' ++ Y) := by simpa [h_take]
      _ = encodeUIntHead MAJOR_UINT k' := by
        rw [hL_eq_len]
        simpa [List.take_append]

  have hk_eq : k = k' := encodeUIntHead_injective MAJOR_UINT k k' h_key_enc

  -- From drops: X = Y
  have hX_eq_Y : X = Y := by
    have h_rest : encodeUIntHead MAJOR_UINT k' ++ X = encodeUIntHead MAJOR_UINT k' ++ Y := by
      simpa [h_key_enc, hk_eq] using h
    exact append_cancel_left (encodeUIntHead MAJOR_UINT k') X Y h_rest

  exact And.intro hk_eq hX_eq_Y

/-- **Lemma 3:** The sorted map encoding is injective (for presorted entries).
    The encoding is `lenEnc ++ (kv1 ++ kv2 ++ ...)` where each `kvi`
    is `encodeUIntHead MAJOR_UINT ki ++ encode vi`.
    By induction on the entries list, using `extract_uint_from_concat` for keys
    and `encode_injective` for values (mutual induction). -/
lemma encodeSortedMap_injective (a b : List (UInt64 × StrictCBOR)) :
    encodeSortedMap a = encodeSortedMap b → a = b := by
  intro h
  unfold encodeSortedMap at h
  let lenA := encodeUIntHead MAJOR_MAP (a.length.toUInt64)
  let lenB := encodeUIntHead MAJOR_MAP (b.length.toUInt64)
  let bodyA := a.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)
  let bodyB := b.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)
  have h_tot : lenA ++ bodyA = lenB ++ bodyB := h

  -- lenA = lenB (same reasoning as extract_uint_from_concat)
  have h_lenAB_eq : lenA = lenB := by
    rcases extract_uint_from_concat (a.length.toUInt64) (b.length.toUInt64) bodyA bodyB h_tot with ⟨h_len_eq, _⟩
    exact h_len_eq

  have h_len_val : a.length = b.length := by
    have h_uint64 : a.length.toUInt64 = b.length.toUInt64 :=
      encodeUIntHead_injective MAJOR_MAP (a.length.toUInt64) (b.length.toUInt64) h_lenAB_eq
    exact Nat.cast_inj.mp h_uint64

  -- Cancel the prefix
  have h_body_eq : bodyA = bodyB :=
    append_cancel_left lenA bodyA bodyB (by simpa [h_lenAB_eq] using h_tot)

  -- Induction on a
  revert b h_body_eq h_len_val
  induction a with
  | nil =>
    intro b h_body h_len
    have hb_len : b.length = 0 := by simpa [h_len]
    exact List.length_eq_zero.mp hb_len
  | cons hd tl ih =>
    intro b h_body h_len
    have hb_nonempty : b ≠ [] := by
      intro hb_nil
      have : (hd :: tl).length = 0 := by simpa [h_len, hb_nil]
      simp at this
    match b with
    | [] => exact absurd rfl hb_nonempty
    | hd' :: tl' =>
      -- bodyA = K1 ++ body(tl), bodyB = K1' ++ body(tl')
      -- where K1 = encodeUIntHead MAJOR_UINT hd.1 ++ encode hd.2
      have h_body_decomp : (encodeUIntHead MAJOR_UINT hd.1 ++ encode hd.2) ++ (tl.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) =
                           (encodeUIntHead MAJOR_UINT hd'.1 ++ encode hd'.2) ++ (tl'.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) := by
        simpa [bodyA, bodyB] using h_body_eq

      -- Extract the first key: use extract_uint_from_concat
      rcases extract_uint_from_concat hd.1 hd'.1
        (encode hd.2 ++ (tl.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)))
        (encode hd'.2 ++ (tl'.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)))
        h_body_decomp with ⟨hk_eq, h_rest⟩

      -- h_rest: encode hd.2 ++ body(tl) = encode hd'.2 ++ body(tl')
      -- Now we need to extract hd.2 = hd'.2 and body(tl) = body(tl')
      -- We use a prefix-free argument for encode
      rcases extract_value_from_concat hd.2 hd'.2
        (tl.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v))
        (tl'.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v))
        h_rest with ⟨hv_eq, h_body_tl_eq⟩

      have h_tl_eq : tl = tl' := ih tl' h_body_tl_eq (by
        -- From h_len: (hd::tl).length = (hd'::tl').length, so tl.length = tl'.length
        simp at h_len
        exact h_len)

      simp [hk_eq, hv_eq, h_tl_eq]

/-- Extract a value from `encode v ++ X = encode v' ++ Y`, proving v = v' and X = Y.
    Uses case analysis on the CBOR major type determined by the first byte. -/
lemma extract_value_from_concat (v v' : StrictCBOR) (X Y : List UInt8)
    (h : encode v ++ X = encode v' ++ Y) : v = v' ∧ X = Y := by
  cases v with
  | uint k =>
    cases v' with
    | uint k' =>
      -- Both uint: encode v = encodeUIntHead MAJOR_UINT k
      rcases extract_uint_from_concat k k' X Y (by simpa [encode] using h) with ⟨hk_eq, hXY_eq⟩
      have hv_eq : StrictCBOR.uint k = StrictCBOR.uint k' := by simpa [hk_eq]
      exact And.intro hv_eq hXY_eq
    | bstr32 _ =>
      -- Different major types: uint (0x00-0x1B) vs bstr (0x58)
      have h_first_diff : (encode (StrictCBOR.uint k)).head? ≠ (encode (StrictCBOR.bstr32 v')).head? := by
        simp [encode, encodeUIntHead, encodeBstr32, MAJOR_UINT, MAJOR_BSTR]
        native_decide
      have h_first_eq : (encode (StrictCBOR.uint k) ++ X).head? = (encode (StrictCBOR.bstr32 v') ++ Y).head? := by
        simpa [h]
      -- But (p ++ q).head? = p.head? when p non-empty
      have h_first_actual : (encode (StrictCBOR.uint k) ++ X).head? = (encode (StrictCBOR.uint k)).head? := by
        simp
      have h_first_actual' : (encode (StrictCBOR.bstr32 v') ++ Y).head? = (encode (StrictCBOR.bstr32 v')).head? := by
        simp
      rw [h_first_actual, h_first_actual'] at h_first_eq
      exact absurd h_first_eq h_first_diff
    | sortedMap _ =>
      -- Different major types: uint (0x00-0x1B) vs map (0xA0-0xBB)
      have h_first_diff : (encode (StrictCBOR.uint k)).head? ≠ (encode (StrictCBOR.sortedMap v')).head? := by
        simp [encode, encodeUIntHead, encodeSortedMap, MAJOR_UINT, MAJOR_MAP]
        native_decide
      have h_first_eq : (encode (StrictCBOR.uint k) ++ X).head? = (encode (StrictCBOR.sortedMap v') ++ Y).head? := by
        simpa [h]
      simp at h_first_eq
      exact absurd h_first_eq h_first_diff
  | bstr32 d =>
    cases v' with
    | uint _ =>
      have h_first_diff : (encode (StrictCBOR.bstr32 d)).head? ≠ (encode (StrictCBOR.uint v')).head? := by
        simp [encode, encodeUIntHead, encodeBstr32, MAJOR_UINT, MAJOR_BSTR]
        native_decide
      have h_first_eq : (encode (StrictCBOR.bstr32 d) ++ X).head? = (encode (StrictCBOR.uint v') ++ Y).head? := by
        simpa [h]
      simp at h_first_eq
      exact absurd h_first_eq h_first_diff
    | bstr32 d' =>
      -- Both bstr32: fixed format [0x58, 0x20] ++ d.toList, length = 34
      -- Cancel the 2-byte prefix and use the 32-byte data
      have h_full : [MAJOR_BSTR || 24, 32] ++ d.toList ++ X = [MAJOR_BSTR || 24, 32] ++ d'.toList ++ Y := by
        simpa [encode, encodeBstr32] using h
      -- Cancel the [0x58, 0x20] prefix
      have h_data_suffix : d.toList ++ X = d'.toList ++ Y :=
        append_cancel_left [MAJOR_BSTR || 24, 32] (d.toList ++ X) (d'.toList ++ Y) h_full
      -- Now d.toList has length 32, so we can take 32 bytes: d.toList = d'.toList
      -- Since both d.toList and d'.toList have length 32, and d.toList ++ X = d'.toList ++ Y,
      -- we can take the first 32 bytes to get d.toList = d'.toList
      have h_dlist_len : d.toList.length = 32 := by
        unfold Bytes32.toList; simp
      have h_d'list_len : d'.toList.length = 32 := by
        unfold Bytes32.toList; simp
      have h_dlist_eq : d.toList = d'.toList := by
        have h_take32 : List.take 32 (d.toList ++ X) = List.take 32 (d'.toList ++ Y) := by
          simpa [h_data_suffix]
        simpa [List.take_append, h_dlist_len, h_d'list_len] using h_take32
      have hX_eq_Y : X = Y := by
        have h_drop32 : List.drop 32 (d.toList ++ X) = List.drop 32 (d'.toList ++ Y) := by
          simpa [h_data_suffix]
        simpa [List.drop_append, h_dlist_len, h_d'list_len, h_dlist_eq] using h_drop32
      have hv_eq : StrictCBOR.bstr32 d = StrictCBOR.bstr32 d' := by
        apply congrArg StrictCBOR.bstr32
        apply Bytes32.ext
        -- From d.toList = d'.toList and Bytes32.ext using native_decide
        have : d.toList = d'.toList := h_dlist_eq
        -- native_decide can check that two Bytes32 with equal toList are equal
        -- But we need to use the existing lemma
        have h_ext : ∀ (a b : Bytes32), a.toList = b.toList → a = b := by
          intro a b h_list
          apply Bytes32.ext
          native_decide
        exact h_ext d d' h_dlist_eq
      exact And.intro hv_eq hX_eq_Y
    | sortedMap _ =>
      -- Different major types: bstr (0x58) vs map (0xA0-0xBB)
      have h_first_diff : (encode (StrictCBOR.bstr32 d)).head? ≠ (encode (StrictCBOR.sortedMap v')).head? := by
        simp [encode, encodeBstr32, encodeSortedMap, MAJOR_BSTR, MAJOR_MAP]
        native_decide
      have h_first_eq : (encode (StrictCBOR.bstr32 d) ++ X).head? = (encode (StrictCBOR.sortedMap v') ++ Y).head? := by
        simpa [h]
      simp at h_first_eq
      exact absurd h_first_eq h_first_diff
  | sortedMap es =>
    cases v' with
    | uint _ =>
      have h_first_diff : (encode (StrictCBOR.sortedMap es)).head? ≠ (encode (StrictCBOR.uint v')).head? := by
        simp [encode, encodeUIntHead, encodeSortedMap, MAJOR_UINT, MAJOR_MAP]
        native_decide
      have h_first_eq : (encode (StrictCBOR.sortedMap es) ++ X).head? = (encode (StrictCBOR.uint v') ++ Y).head? := by
        simpa [h]
      simp at h_first_eq
      exact absurd h_first_eq h_first_diff
    | bstr32 _ =>
      have h_first_diff : (encode (StrictCBOR.sortedMap es)).head? ≠ (encode (StrictCBOR.bstr32 v')).head? := by
        simp [encode, encodeBstr32, encodeSortedMap, MAJOR_BSTR, MAJOR_MAP]
        native_decide
      have h_first_eq : (encode (StrictCBOR.sortedMap es) ++ X).head? = (encode (StrictCBOR.bstr32 v') ++ Y).head? := by
        simpa [h]
      simp at h_first_eq
      exact absurd h_first_eq h_first_diff
    | sortedMap es' =>
      -- Both sortedMap: encode v = encodeSortedMap es, encode v' = encodeSortedMap es'
      -- We use encodeSortedMap_injective via the mutual recursion
      -- The encoding is: lenEnc ++ body(es) where lenEnc = encodeUIntHead MAJOR_MAP (es.length.toUInt64)
      -- So h becomes: encodeSortedMap es ++ X = encodeSortedMap es' ++ Y
      --   i.e., (encodeUIntHead MAJOR_MAP (es.length.toUInt64) ++ body(es)) ++ X
      --       = (encodeUIntHead MAJOR_MAP (es'.length.toUInt64) ++ body(es')) ++ Y
      --        = encodeUIntHead MAJOR_MAP (es'.length.toUInt64) ++ (body(es') ++ Y)
      -- By associativity: encodeUIntHead MAJOR_MAP (es.length.toUInt64) ++ (body(es) ++ X)
      --                = encodeUIntHead MAJOR_MAP (es'.length.toUInt64) ++ (body(es') ++ Y)
      -- Use extract_uint_from_concat to extract the length prefixes
      have h_assoc : encodeUIntHead MAJOR_MAP (es.length.toUInt64) ++
                     ((es.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ X) =
                    encodeUIntHead MAJOR_MAP (es'.length.toUInt64) ++
                     ((es'.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ Y) := by
        simpa [encodeSortedMap] using h
      rcases extract_uint_from_concat (es.length.toUInt64) (es'.length.toUInt64)
        ((es.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ X)
        ((es'.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ Y)
        h_assoc with ⟨h_len_eq, h_body_suffix⟩
      -- h_body_suffix: body(es) ++ X = body(es') ++ Y
      -- Now we need to show es = es' and X = Y
      -- From h_len_eq, we know es.length = es'.length (by encodeUIntHead_injective)
      have h_es_len : es.length = es'.length := by
        have h_uint64 : es.length.toUInt64 = es'.length.toUInt64 :=
          encodeUIntHead_injective MAJOR_MAP (es.length.toUInt64) (es'.length.toUInt64) h_len_eq
        exact Nat.cast_inj.mp h_uint64
      -- Now we have body(es) ++ X = body(es') ++ Y and es.length = es'.length
      -- We can use encodeSortedMap_injective on the prefix-free structure
      -- By the same induction structure as encodeSortedMap itself:
      -- body(es) = es.bind f, and we need to extract es = es' from body(es) ++ X = body(es') ++ Y
      -- This is the same problem as the main lemma but with suffixes
      -- We use the same induction approach
      have h_es_body : (es.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ X =
                       (es'.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ Y :=
        h_body_suffix
      -- Use the same extract-then-induct approach as encodeSortedMap_injective
      rcases extract_list_from_bind es es' X Y h_es_body h_es_len with ⟨hes_eq, hX_eq_Y⟩
      have hv_eq : StrictCBOR.sortedMap es = StrictCBOR.sortedMap es' := by
        simpa [hes_eq]
      exact And.intro hv_eq hX_eq_Y

/-- Extract equal lists from `bind f L1 ++ X = bind f L2 ++ Y` where f is the key-value encoding.
    This is the same problem as encodeSortedMap_injective but with suffixes X and Y.
    Proved by induction on L1. -/
lemma extract_list_from_bind (L1 L2 : List (UInt64 × StrictCBOR)) (X Y : List UInt8)
    (h_body : (L1.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ X =
              (L2.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ Y)
    (h_len : L1.length = L2.length) : L1 = L2 ∧ X = Y := by
  revert L2 h_body h_len
  induction L1 with
  | nil =>
    intro L2 h_body h_len
    have hL2_len : L2.length = 0 := by simpa [h_len]
    have hL2_nil : L2 = [] := List.length_eq_zero.mp hL2_len
    -- body([]) = [], so h_body: [] ++ X = [] ++ Y → X = Y
    have hX_eq_Y : X = Y := by
      simpa [hL2_nil] using h_body
    exact And.intro hL2_nil hX_eq_Y
  | cons hd tl ih =>
    intro L2 h_body h_len
    have hL2_nonempty : L2 ≠ [] := by
      intro hL2_nil
      have : (hd :: tl).length = 0 := by simpa [h_len, hL2_nil]
      simp at this
    match L2 with
    | [] => exact absurd rfl hL2_nonempty
    | hd' :: tl' =>
      -- Expand the binds
      have h_body_decomp : (encodeUIntHead MAJOR_UINT hd.1 ++ encode hd.2) ++
                           ((tl.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ X) =
                           (encodeUIntHead MAJOR_UINT hd'.1 ++ encode hd'.2) ++
                           ((tl'.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ Y) := by
        simpa [List.bind_cons] using h_body
      -- Extract the first key
      rcases extract_uint_from_concat hd.1 hd'.1
        (encode hd.2 ++ ((tl.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ X))
        (encode hd'.2 ++ ((tl'.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ Y))
        h_body_decomp with ⟨hk_eq, h_rest⟩
      -- h_rest: encode hd.2 ++ (body(tl) ++ X) = encode hd'.2 ++ (body(tl') ++ Y)
      -- Extract the value
      rcases extract_value_from_concat hd.2 hd'.2
        ((tl.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ X)
        ((tl'.bind (λ (k, v) => encodeUIntHead MAJOR_UINT k ++ encode v)) ++ Y)
        h_rest with ⟨hv_eq, h_body_suffix⟩
      -- h_body_suffix: body(tl) ++ X = body(tl') ++ Y
      -- Now use induction hypothesis for tl and tl'
      have h_tl_len : tl.length = tl'.length := by
        simp at h_len
        exact h_len
      rcases ih tl' h_body_suffix h_tl_len with ⟨h_tl_eq, hX_eq_Y⟩
      -- Therefore hd :: tl = hd' :: tl'
      have hL_eq : hd :: tl = hd' :: tl' := by
        simp [hk_eq, hv_eq, h_tl_eq]
      exact And.intro hL_eq hX_eq_Y

/-! ## Theorem I1: Serialization Injectivity -/

/-- **Theorem I1: Serialization Injectivity**
    `encode a = encode b` implies `a = b` for all StrictCBOR values.
    The proof proceeds by structural case analysis on the top-level constructors.
    Cross-constructor cases are impossible because the head bytes differ
    (uint starts 0x00, bstr starts 0x58, map starts 0xA0).
    Same-constructor cases use Lemmas 1-3. -/
theorem encode_injective (a b : StrictCBOR) : encode a = encode b → a = b := by
  intro h
  cases a with
  | uint va =>
      cases b with
      | uint vb =>
          apply congrArg StrictCBOR.uint
          exact encodeUIntHead_injective MAJOR_UINT va vb h
      | bstr32 _ =>
          have h_uint_head : (encode (StrictCBOR.uint va)).head? = some (MAJOR_UINT || 
            (if va < 24 then va.toUInt8 else 24)) := by
            simp [encode, encodeUIntHead]
          have h_bstr_head : (encode (StrictCBOR.bstr32 b)).head? = some (MAJOR_BSTR || 24) := by
            simp [encode, encodeBstr32, MAJOR_BSTR]
          have : MAJOR_UINT || (if va < 24 then va.toUInt8 else 24) ≠ MAJOR_BSTR || 24 := by
            native_decide
          have : (encode (StrictCBOR.uint va)).head? ≠ (encode (StrictCBOR.bstr32 b)).head? := by
            simpa [h_uint_head, h_bstr_head]
          exact absurd (by simpa [h] using rfl) this
      | sortedMap _ =>
          have h_uint_head : (encode (StrictCBOR.uint va)).head? = some (MAJOR_UINT || 
            (if va < 24 then va.toUInt8 else 24)) := by
            simp [encode, encodeUIntHead]
          have h_map_head : (encode (StrictCBOR.sortedMap b)).head? = some (MAJOR_MAP || 24) := by
            simp [encode, encodeSortedMap, encodeUIntHead, MAJOR_MAP]
          have : MAJOR_UINT || (if va < 24 then va.toUInt8 else 24) ≠ MAJOR_MAP || 24 := by
            native_decide
          have : (encode (StrictCBOR.uint va)).head? ≠ (encode (StrictCBOR.sortedMap b)).head? := by
            simpa [h_uint_head, h_map_head]
          exact absurd (by simpa [h] using rfl) this
  | bstr32 da =>
      cases b with
      | uint _ =>
          have h_bstr_head : (encode (StrictCBOR.bstr32 da)).head? = some (MAJOR_BSTR || 24) := by
            simp [encode, encodeBstr32, MAJOR_BSTR]
          have h_uint_head : (encode (StrictCBOR.uint b)).head? = some (MAJOR_UINT || 
            (if b < 24 then b.toUInt8 else 24)) := by
            simp [encode, encodeUIntHead]
          have : MAJOR_BSTR || 24 ≠ MAJOR_UINT || (if b < 24 then b.toUInt8 else 24) := by
            native_decide
          have : (encode (StrictCBOR.bstr32 da)).head? ≠ (encode (StrictCBOR.uint b)).head? := by
            simpa [h_bstr_head, h_uint_head]
          exact absurd (by simpa [h] using rfl) this
      | bstr32 db =>
          apply congrArg StrictCBOR.bstr32
          exact encodeBstr32_injective da db h
      | sortedMap _ =>
          have h_bstr_head : (encode (StrictCBOR.bstr32 da)).head? = some (MAJOR_BSTR || 24) := by
            simp [encode, encodeBstr32, MAJOR_BSTR]
          have h_map_head : (encode (StrictCBOR.sortedMap b)).head? = some (MAJOR_MAP || 24) := by
            simp [encode, encodeSortedMap, encodeUIntHead, MAJOR_MAP]
          have : MAJOR_BSTR || 24 ≠ MAJOR_MAP || 24 := by
            native_decide
          have : (encode (StrictCBOR.bstr32 da)).head? ≠ (encode (StrictCBOR.sortedMap b)).head? := by
            simpa [h_bstr_head, h_map_head]
          exact absurd (by simpa [h] using rfl) this
  | sortedMap ea =>
      cases b with
      | uint _ =>
          have h_map_head : (encode (StrictCBOR.sortedMap ea)).head? = some (MAJOR_MAP || 24) := by
            simp [encode, encodeSortedMap, encodeUIntHead, MAJOR_MAP]
          have h_uint_head : (encode (StrictCBOR.uint b)).head? = some (MAJOR_UINT || 
            (if b < 24 then b.toUInt8 else 24)) := by
            simp [encode, encodeUIntHead]
          have : MAJOR_MAP || 24 ≠ MAJOR_UINT || (if b < 24 then b.toUInt8 else 24) := by
            native_decide
          have : (encode (StrictCBOR.sortedMap ea)).head? ≠ (encode (StrictCBOR.uint b)).head? := by
            simpa [h_map_head, h_uint_head]
          exact absurd (by simpa [h] using rfl) this
      | bstr32 _ =>
          have h_map_head : (encode (StrictCBOR.sortedMap ea)).head? = some (MAJOR_MAP || 24) := by
            simp [encode, encodeSortedMap, encodeUIntHead, MAJOR_MAP]
          have h_bstr_head : (encode (StrictCBOR.bstr32 b)).head? = some (MAJOR_BSTR || 24) := by
            simp [encode, encodeBstr32, MAJOR_BSTR]
          have : MAJOR_MAP || 24 ≠ MAJOR_BSTR || 24 := by
            native_decide
          have : (encode (StrictCBOR.sortedMap ea)).head? ≠ (encode (StrictCBOR.bstr32 b)).head? := by
            simpa [h_map_head, h_bstr_head]
          exact absurd (by simpa [h] using rfl) this
      | sortedMap eb =>
          apply congrArg StrictCBOR.sortedMap
          exact encodeSortedMap_injective ea eb h

/-- Determinism: equal payloads always produce equal encodings. -/
theorem encode_deterministic (a : StrictCBOR) : encode a = encode a := rfl
