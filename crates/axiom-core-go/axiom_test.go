package axiom

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVersion(t *testing.T) {
	v := Version()
	if v == "" {
		t.Fatal("expected non-empty version string")
	}
	t.Logf("axiom-core version: %s", v)
}

func TestVerifyEd25519_ValidVectors(t *testing.T) {
	suite := loadSuite(t)
	pubkey, err := hex.DecodeString(suite.SigningKeyPK)
	if err != nil {
		t.Fatalf("decoding pubkey hex: %v", err)
	}

	var tested int
	for _, vec := range suite.Vectors {
		if !vec.IsValid {
			continue
		}
		if vec.SignatureAlg == "composite(-8, -39)" {
			continue
		}
		if vec.COSEHex == "" {
			continue
		}

		coseBytes, err := hex.DecodeString(vec.COSEHex)
		if err != nil {
			t.Errorf("vector %q: bad cose_hex: %v", vec.Name, err)
			continue
		}

		payload, err := VerifyEd25519(coseBytes, pubkey)
		if err != nil {
			t.Errorf("vector %q: expected PASS, got: %v", vec.Name, err)
			continue
		}
		if len(payload) == 0 {
			t.Errorf("vector %q: empty payload", vec.Name)
		}
		tested++
	}
	if tested == 0 {
		t.Fatal("no valid Ed25519 vectors tested")
	}
	t.Logf("Tested %d valid Ed25519 vectors — all PASS", tested)
}

func TestVerifyMLDsa65Only_ValidVectors(t *testing.T) {
	suite := loadSuite(t)
	var tested int
	for _, vec := range suite.Vectors {
		if !vec.IsValid || vec.SignatureAlg != "mldsa65_only" {
			continue
		}
		if vec.COSEHex == "" || vec.MLDsaPubkey == "" {
			continue
		}

		coseBytes, err := hex.DecodeString(vec.COSEHex)
		if err != nil {
			t.Errorf("vector %q: bad cose_hex: %v", vec.Name, err)
			continue
		}

		pkBytes, err := hex.DecodeString(vec.MLDsaPubkey)
		if err != nil {
			t.Errorf("vector %q: bad ml_dsa_pubkey_hex: %v", vec.Name, err)
			continue
		}

		payload, err := VerifyMLDsa65Only(coseBytes, pkBytes)
		if err != nil {
			t.Errorf("vector %q: expected PASS, got: %v", vec.Name, err)
			continue
		}
		if len(payload) == 0 {
			t.Errorf("vector %q: empty payload", vec.Name)
		}
		tested++
	}
	if tested == 0 {
		t.Log("No ML-DSA-65-only vectors found — skipping")
		return
	}
	t.Logf("Tested %d valid ML-DSA-65-only vectors — all PASS", tested)
}

func TestVerifyComposite_ValidVectors(t *testing.T) {
	suite := loadSuite(t)
	var tested int
	for _, vec := range suite.Vectors {
		if !vec.IsValid || vec.SignatureAlg != "composite(-8, -39)" {
			continue
		}
		if vec.CompositeCOSE == "" || vec.CompositePK == "" {
			continue
		}

		coseBytes, err := hex.DecodeString(vec.CompositeCOSE)
		if err != nil {
			t.Errorf("vector %q: bad composite_cose_hex: %v", vec.Name, err)
			continue
		}

		compPKBytes, err := hex.DecodeString(vec.CompositePK)
		if err != nil {
			t.Errorf("vector %q: bad composite_pk_hex: %v", vec.Name, err)
			continue
		}
		if len(compPKBytes) != 32+1952 {
			t.Errorf("vector %q: composite PK length %d, expected %d", vec.Name, len(compPKBytes), 32+1952)
			continue
		}

		payload, err := VerifyComposite(coseBytes, compPKBytes[:32], compPKBytes[32:])
		if err != nil {
			t.Errorf("vector %q: expected PASS, got: %v", vec.Name, err)
			continue
		}
		if len(payload) == 0 {
			t.Errorf("vector %q: empty payload", vec.Name)
		}
		tested++
	}
	if tested == 0 {
		t.Log("No composite vectors found — skipping")
		return
	}
	t.Logf("Tested %d valid composite vectors — all PASS", tested)
}

func TestInvalidVectors_AllFail(t *testing.T) {
	suite := loadSuite(t)
	pubkey, err := hex.DecodeString(suite.SigningKeyPK)
	if err != nil {
		t.Fatalf("decoding pubkey hex: %v", err)
	}

	var tested int
	for _, vec := range suite.Vectors {
		if vec.IsValid {
			continue
		}
		if vec.COSEHex == "" {
			continue
		}
		// Skip composite invalid vectors for now
		if vec.SignatureAlg == "composite(-8, -39)" {
			continue
		}

		coseBytes, err := hex.DecodeString(vec.COSEHex)
		if err != nil {
			t.Logf("vector %q: skipping (bad hex: %v)", vec.Name, err)
			continue
		}

		if len(coseBytes) == 0 {
			t.Logf("vector %q: skipping (empty bytes)", vec.Name)
			continue
		}

		vecPK := pubkey
		if vec.EdPubkeyHex != "" {
			pk, err := hex.DecodeString(vec.EdPubkeyHex)
			if err != nil {
				t.Errorf("vector %q: bad ed_pubkey_hex: %v", vec.Name, err)
				continue
			}
			vecPK = pk
		}

		_, err = VerifyEd25519(coseBytes, vecPK)
		if err == nil {
			t.Errorf("vector %q: expected FAIL but got PASS", vec.Name)
		} else {
			t.Logf("vector %q: correctly FAILED with: %v", vec.Name, err)
		}
		tested++
	}
	if tested == 0 {
		t.Fatal("no invalid vectors tested")
	}
	t.Logf("Tested %d invalid vectors — all correctly FAILED", tested)
}

func TestDecodePayload(t *testing.T) {
	suite := loadSuite(t)
	for _, vec := range suite.Vectors {
		if !vec.IsValid || vec.PayloadCBOR == "" {
			continue
		}
		cborBytes, err := hex.DecodeString(vec.PayloadCBOR)
		if err != nil {
			t.Errorf("vector %q: bad payload_cbor_hex: %v", vec.Name, err)
			continue
		}
		fields, err := DecodePayload(cborBytes)
		if err != nil {
			t.Errorf("vector %q: DecodePayload failed: %v", vec.Name, err)
			continue
		}
		if fields.Subject == "" {
			t.Errorf("vector %q: empty subject", vec.Name)
		}
		t.Logf("Vector %q: subject=%s predicate=%d hasObject=%v hasNonce=%v hasLineage=%v",
			vec.Name, fields.Subject, fields.Predicate, fields.HasObject, fields.HasNonce, fields.HasLineage)
		return // just test the first valid vector
	}
}

func loadSuite(t *testing.T) *ConformanceSuite {
	suitePath := findSuitePath(t)
	suite, err := LoadConformanceSuite(suitePath)
	if err != nil {
		t.Fatalf("loading conformance suite: %v", err)
	}
	return suite
}

func findSuitePath(t *testing.T) string {
	candidates := []string{
		"conformance_suite.json",
		"test_vectors.json",
		"test-vectors/vectors/conformance_suite.json",
		"test-vectors/test_vectors.json",
		"../test-vectors/vectors/conformance_suite.json",
		"../test-vectors/test_vectors.json",
		"../../test-vectors/vectors/conformance_suite.json",
		"../../test-vectors/test_vectors.json",
		"../../../test-vectors/vectors/conformance_suite.json",
	}
	for _, c := range candidates {
		p, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if fileExists(p) {
			return p
		}
	}
	t.Fatal("conformance suite not found")
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
