// Package verax provides Go bindings for the Verax Protocol.
// It wraps the verax-core-ffi C library to enable creation and verification
// of signed statements (Ed25519 and Composite Ed25519+ML-DSA-65), PII
// shredding (encrypt/decrypt/commit), payload encoding/decoding, and full
// protocol verification with trust store, CT log anchoring, and revocation
// cache support.
package verax

/*
#cgo LDFLAGS: -laxiom_core_ffi -lm -ldl
#cgo CFLAGS: -I../crates/verax-core-ffi/include

#include <stdlib.h>
#include "axiom_core.h"
*/
import "C"
import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"unsafe"
)

// Error codes matching the C-ABI (Section B of the Verax spec).
const (
	// ErrMalformedCose indicates the COSE envelope is malformed or invalid.
	ErrMalformedCose = 1
	// ErrNonCanonical indicates the encoding is not strictly canonical.
	ErrNonCanonical = 2
	// ErrInvalidSignature indicates the cryptographic signature is invalid.
	ErrInvalidSignature = 3
	// ErrBrokenLineage indicates a lineage chain is broken or inconsistent.
	ErrBrokenLineage = 4
	// ErrLineageSubject indicates a lineage subject hash mismatch.
	ErrLineageSubject = 5
	// ErrTimestampViol indicates a timestamp monotonicity violation.
	ErrTimestampViol = 6
	// ErrRevokeIssuer indicates a revoke issuer mismatch.
	ErrRevokeIssuer = 7
	// ErrInvalidLogProof indicates an invalid CT log inclusion proof.
	ErrInvalidLogProof = 8
	// ErrRevoked indicates the statement has been revoked.
	ErrRevoked = 9
	// ErrInvalidField indicates an invalid field value or length.
	ErrInvalidField = 10
	// ErrCrypto indicates a general cryptographic operation failure.
	ErrCrypto = 11
	// ErrDecode indicates a payload decode failure.
	ErrDecode = 12
	// ErrHashLength indicates an unexpected hash length.
	ErrHashLength = 13
	// ErrIo indicates an I/O operation failure.
	ErrIo = 14
	// ErrPayload indicates a payload encoding or validation error.
	ErrPayload = 15
)

var errorNames = map[int]string{
	ErrMalformedCose:    "MalformedCose",
	ErrNonCanonical:     "NonCanonicalEncoding",
	ErrInvalidSignature: "InvalidSignature",
	ErrBrokenLineage:    "BrokenLineage",
	ErrLineageSubject:   "LineageSubjectMismatch",
	ErrTimestampViol:    "TimestampMonotonicityViolation",
	ErrRevokeIssuer:     "RevokeIssuerMismatch",
	ErrInvalidLogProof:  "InvalidLogProof",
	ErrRevoked:          "Revoked",
	ErrInvalidField:     "InvalidField",
	ErrCrypto:           "Crypto",
	ErrDecode:           "Decode",
	ErrHashLength:       "HashLength",
	ErrIo:               "Io",
	ErrPayload:          "Payload",
}

// VeraxError represents an error returned by the Verax C-ABI with a
// numeric error code and a human-readable message.
type VeraxError struct {
	Code    int
	Message string
}

func (e *VeraxError) Error() string {
	name, ok := errorNames[e.Code]
	if !ok {
		name = "Unknown"
	}
	return fmt.Sprintf("Verax error %d (%s): %s", e.Code, name, e.Message)
}

// Version returns the Verax library version string.
func Version() string {
	cstr := C.axiom_version()
	return C.GoString(cstr)
}

// VerifyMLDsa65Only verifies an ML-DSA-65 only signature and returns the
// decoded payload CBOR on success.
func VerifyMLDsa65Only(coseData []byte, pubkey []byte) ([]byte, error) {
	expectedMLDsaLen := 1952
	if len(pubkey) != expectedMLDsaLen {
		return nil, &VeraxError{
			Code:    ErrInvalidField,
			Message: fmt.Sprintf("ML-DSA-65 pubkey must be %d bytes, got %d", expectedMLDsaLen, len(pubkey)),
		}
	}
	var outPayload *C.uint8_t
	var outLen C.size_t
	cosePtr := unsafe.Pointer(nil)
	if len(coseData) > 0 {
		cosePtr = unsafe.Pointer(&coseData[0])
	}
	pkPtr := unsafe.Pointer(&pubkey[0])
	ret := C.axiom_verify_mldsa65_only(
		(*C.uint8_t)(cosePtr), C.size_t(len(coseData)),
		(*C.uint8_t)(pkPtr), C.size_t(len(pubkey)),
		&outPayload, &outLen,
	)
	if ret != 0 {
		return nil, &VeraxError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	if outPayload == nil {
		return nil, &VeraxError{Code: ErrDecode, Message: "null output"}
	}
	payloadBytes := C.GoBytes(unsafe.Pointer(outPayload), C.int(outLen))
	C.axiom_free(unsafe.Pointer(outPayload))
	return payloadBytes, nil
}

// VerifyEd25519 verifies an Ed25519-signed COSE statement and returns the
// decoded payload CBOR. pubkey must be exactly 32 bytes.
func VerifyEd25519(coseData []byte, pubkey []byte) ([]byte, error) {
	if len(pubkey) != 32 {
		return nil, &VeraxError{Code: ErrInvalidField, Message: "Ed25519 pubkey must be 32 bytes"}
	}
	var outPayload *C.uint8_t
	var outLen C.size_t
	cosePtr := unsafe.Pointer(nil)
	if len(coseData) > 0 {
		cosePtr = unsafe.Pointer(&coseData[0])
	}
	pkPtr := unsafe.Pointer(&pubkey[0])
	ret := C.axiom_verify_ed25519(
		(*C.uint8_t)(cosePtr), C.size_t(len(coseData)),
		(*C.uint8_t)(pkPtr), C.size_t(len(pubkey)),
		&outPayload, &outLen,
	)
	if ret != 0 {
		return nil, &VeraxError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	if outPayload == nil {
		return nil, &VeraxError{Code: ErrDecode, Message: "null output"}
	}
	payloadBytes := C.GoBytes(unsafe.Pointer(outPayload), C.int(outLen))
	C.axiom_free(unsafe.Pointer(outPayload))
	return payloadBytes, nil
}

// VerifyComposite verifies a Composite (Ed25519 + ML-DSA-65) COSE statement
// and returns the decoded payload CBOR. edPubkey must be 32 bytes and
// mlDsaPubkey must be 1952 bytes.
func VerifyComposite(coseData []byte, edPubkey []byte, mlDsaPubkey []byte) ([]byte, error) {
	if len(edPubkey) != 32 {
		return nil, &VeraxError{Code: ErrInvalidField, Message: "Ed25519 pubkey must be 32 bytes"}
	}
	expectedMLDsaLen := 1952
	if len(mlDsaPubkey) != expectedMLDsaLen {
		return nil, &VeraxError{
			Code:    ErrInvalidField,
			Message: fmt.Sprintf("ML-DSA-65 pubkey must be %d bytes, got %d", expectedMLDsaLen, len(mlDsaPubkey)),
		}
	}
	var outPayload *C.uint8_t
	var outLen C.size_t
	cosePtr := unsafe.Pointer(nil)
	if len(coseData) > 0 {
		cosePtr = unsafe.Pointer(&coseData[0])
	}
	edPtr := unsafe.Pointer(&edPubkey[0])
	mlPtr := unsafe.Pointer(&mlDsaPubkey[0])
	ret := C.axiom_verify_composite(
		(*C.uint8_t)(cosePtr), C.size_t(len(coseData)),
		(*C.uint8_t)(edPtr), C.size_t(len(edPubkey)),
		(*C.uint8_t)(mlPtr), C.size_t(len(mlDsaPubkey)),
		&outPayload, &outLen,
	)
	if ret != 0 {
		return nil, &VeraxError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	if outPayload == nil {
		return nil, &VeraxError{Code: ErrDecode, Message: "null output"}
	}
	payloadBytes := C.GoBytes(unsafe.Pointer(outPayload), C.int(outLen))
	C.axiom_free(unsafe.Pointer(outPayload))
	return payloadBytes, nil
}

// SignEd25519 signs a payload CBOR with an Ed25519 signing key and returns
// the COSE-encoded statement. keyBytes must be exactly 32 bytes (seed).
func SignEd25519(payloadCbor []byte, keyBytes []byte) ([]byte, error) {
	var outSig *C.uint8_t
	var outSigLen C.size_t
	payloadPtr := unsafe.Pointer(nil)
	if len(payloadCbor) > 0 {
		payloadPtr = unsafe.Pointer(&payloadCbor[0])
	}
	keyPtr := unsafe.Pointer(nil)
	if len(keyBytes) > 0 {
		keyPtr = unsafe.Pointer(&keyBytes[0])
	}
	ret := C.axiom_sign_ed25519(
		(*C.uint8_t)(payloadPtr), C.size_t(len(payloadCbor)),
		(*C.uint8_t)(keyPtr), C.size_t(len(keyBytes)),
		&outSig, &outSigLen,
	)
	if ret != 0 {
		return nil, &VeraxError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	sigBytes := C.GoBytes(unsafe.Pointer(outSig), C.int(outSigLen))
	C.axiom_free(unsafe.Pointer(outSig))
	return sigBytes, nil
}

// SignComposite signs a payload CBOR with a Composite (Ed25519 + ML-DSA-65)
// key pair and returns the COSE-encoded statement. edKeyBytes must be 32
// bytes and mlSeedBytes must be 32 bytes.
func SignComposite(payloadCbor []byte, edKeyBytes []byte, mlSeedBytes []byte) ([]byte, error) {
	var outSig *C.uint8_t
	var outSigLen C.size_t
	payloadPtr := unsafe.Pointer(nil)
	if len(payloadCbor) > 0 {
		payloadPtr = unsafe.Pointer(&payloadCbor[0])
	}
	edPtr := unsafe.Pointer(nil)
	if len(edKeyBytes) > 0 {
		edPtr = unsafe.Pointer(&edKeyBytes[0])
	}
	mlPtr := unsafe.Pointer(nil)
	if len(mlSeedBytes) > 0 {
		mlPtr = unsafe.Pointer(&mlSeedBytes[0])
	}
	ret := C.axiom_sign_composite(
		(*C.uint8_t)(payloadPtr), C.size_t(len(payloadCbor)),
		(*C.uint8_t)(edPtr), C.size_t(len(edKeyBytes)),
		(*C.uint8_t)(mlPtr), C.size_t(len(mlSeedBytes)),
		&outSig, &outSigLen,
	)
	if ret != 0 {
		return nil, &VeraxError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	sigBytes := C.GoBytes(unsafe.Pointer(outSig), C.int(outSigLen))
	C.axiom_free(unsafe.Pointer(outSig))
	return sigBytes, nil
}

// EncryptPII encrypts plaintext using a ShreddingKey and returns the
// ciphertext. key must be exactly 32 bytes.
func EncryptPII(key []byte, plaintext []byte) ([]byte, error) {
	var outCt *C.uint8_t
	var outCtLen C.size_t
	keyPtr := unsafe.Pointer(nil)
	if len(key) > 0 {
		keyPtr = unsafe.Pointer(&key[0])
	}
	ptPtr := unsafe.Pointer(nil)
	if len(plaintext) > 0 {
		ptPtr = unsafe.Pointer(&plaintext[0])
	}
	ret := C.axiom_encrypt_pii(
		(*C.uint8_t)(keyPtr), C.size_t(len(key)),
		(*C.uint8_t)(ptPtr), C.size_t(len(plaintext)),
		&outCt, &outCtLen,
	)
	if ret != 0 {
		return nil, &VeraxError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	ctBytes := C.GoBytes(unsafe.Pointer(outCt), C.int(outCtLen))
	C.axiom_free(unsafe.Pointer(outCt))
	return ctBytes, nil
}

// DecryptPII decrypts ciphertext using a ShreddingKey and returns the
// plaintext. key must be exactly 32 bytes.
func DecryptPII(key []byte, ciphertext []byte) ([]byte, error) {
	var outPt *C.uint8_t
	var outPtLen C.size_t
	keyPtr := unsafe.Pointer(nil)
	if len(key) > 0 {
		keyPtr = unsafe.Pointer(&key[0])
	}
	ctPtr := unsafe.Pointer(nil)
	if len(ciphertext) > 0 {
		ctPtr = unsafe.Pointer(&ciphertext[0])
	}
	ret := C.axiom_decrypt_pii(
		(*C.uint8_t)(keyPtr), C.size_t(len(key)),
		(*C.uint8_t)(ctPtr), C.size_t(len(ciphertext)),
		&outPt, &outPtLen,
	)
	if ret != 0 {
		return nil, &VeraxError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	ptBytes := C.GoBytes(unsafe.Pointer(outPt), C.int(outPtLen))
	C.axiom_free(unsafe.Pointer(outPt))
	return ptBytes, nil
}

// ShreddingCommitResult holds the ciphertext and commitment output from
// a shredding commit operation.
type ShreddingCommitResult struct {
	Ciphertext []byte
	Commitment []byte
}

// ShreddingCommit performs encrypt-and-commit in one operation, returning
// both the ciphertext and the blinding commitment.
func ShreddingCommit(key []byte, plaintext []byte) (*ShreddingCommitResult, error) {
	var outCt *C.uint8_t
	var outCtLen C.size_t
	var outComm *C.uint8_t
	var outCommLen C.size_t
	keyPtr := unsafe.Pointer(nil)
	if len(key) > 0 {
		keyPtr = unsafe.Pointer(&key[0])
	}
	ptPtr := unsafe.Pointer(nil)
	if len(plaintext) > 0 {
		ptPtr = unsafe.Pointer(&plaintext[0])
	}
	ret := C.axiom_shredding_commit(
		(*C.uint8_t)(keyPtr), C.size_t(len(key)),
		(*C.uint8_t)(ptPtr), C.size_t(len(plaintext)),
		&outCt, &outCtLen,
		&outComm, &outCommLen,
	)
	if ret != 0 {
		return nil, &VeraxError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	ctBytes := C.GoBytes(unsafe.Pointer(outCt), C.int(outCtLen))
	C.axiom_free(unsafe.Pointer(outCt))
	commBytes := C.GoBytes(unsafe.Pointer(outComm), C.int(outCommLen))
	C.axiom_free(unsafe.Pointer(outComm))
	return &ShreddingCommitResult{Ciphertext: ctBytes, Commitment: commBytes}, nil
}

// EncodePayload creates a CBOR-encoded VeraxPayload from a 32-byte subject
// hash and a predicate value.
func EncodePayload(subject []byte, predicate uint32) ([]byte, error) {
	var outCbor *C.uint8_t
	var outCborLen C.size_t
	subjPtr := unsafe.Pointer(nil)
	if len(subject) > 0 {
		subjPtr = unsafe.Pointer(&subject[0])
	}
	ret := C.axiom_encode_payload(
		(*C.uint8_t)(subjPtr), C.size_t(len(subject)),
		C.uint32_t(predicate),
		&outCbor, &outCborLen,
	)
	if ret != 0 {
		return nil, &VeraxError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	cborBytes := C.GoBytes(unsafe.Pointer(outCbor), C.int(outCborLen))
	C.axiom_free(unsafe.Pointer(outCbor))
	return cborBytes, nil
}

// PayloadFields holds the decoded fields of an VeraxPayload.
type PayloadFields struct {
	Subject     string  `json:"subject_hex"`
	Predicate   uint32  `json:"predicate"`
	Timestamp   *uint64 `json:"timestamp,omitempty"`
	HasObject   bool    `json:"has_object"`
	Object      string  `json:"object_hex,omitempty"`
	HasNonce    bool    `json:"has_nonce"`
	Nonce       string  `json:"nonce_hex,omitempty"`
	HasLineage  bool    `json:"has_lineage"`
	Lineage     string  `json:"lineage_hex,omitempty"`
}

// DecodePayload decodes a CBOR-encoded VeraxPayload and returns the
// parsed fields including subject, predicate, timestamp, object, nonce,
// and lineage.
func DecodePayload(cborData []byte) (*PayloadFields, error) {
	var subject [32]byte
	var predicate C.uint32_t
	var timestamp C.uint64_t
	var hasObject C.uint8_t
	var object [32]byte
	var hasNonce C.uint8_t
	var nonce [32]byte
	var hasLineage C.uint8_t
	var lineage [32]byte
	cborPtr := unsafe.Pointer(nil)
	if len(cborData) > 0 {
		cborPtr = unsafe.Pointer(&cborData[0])
	}
	ret := C.axiom_payload_decode(
		(*C.uint8_t)(cborPtr), C.size_t(len(cborData)),
		(*C.uint8_t)(&subject[0]), &predicate, &timestamp,
		&hasObject, (*C.uint8_t)(&object[0]),
		&hasNonce, (*C.uint8_t)(&nonce[0]),
		&hasLineage, (*C.uint8_t)(&lineage[0]),
	)
	if ret != 0 {
		return nil, &VeraxError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	fields := &PayloadFields{
		Subject:    hex.EncodeToString(subject[:]),
		Predicate:  uint32(predicate),
		HasObject:  hasObject != 0,
		HasNonce:   hasNonce != 0,
		HasLineage: hasLineage != 0,
	}
	if hasObject != 0 {
		fields.Object = hex.EncodeToString(object[:])
	}
	if hasNonce != 0 {
		fields.Nonce = hex.EncodeToString(nonce[:])
	}
	if hasLineage != 0 {
		fields.Lineage = hex.EncodeToString(lineage[:])
	}
	if timestamp != 0 || hasObject != 0 || hasNonce != 0 || hasLineage != 0 {
		ts := uint64(timestamp)
		fields.Timestamp = &ts
	}
	return fields, nil
}

// ----- Full Verification -----

// VerificationResult holds the outcome of a full protocol verification.
type VerificationResult struct {
	Valid    bool     `json:"valid"`
	Payload  []byte   `json:"payload,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// VerifyFull performs full protocol verification including signature check,
// CT log anchoring, chain resolution, and revocation status. It returns a
// VerificationResult containing validity, payload, warnings, and errors.
func VerifyFull(coseData []byte, pubkey []byte, trustedLogKey []byte, chainStatements [][]byte, revoked []string, notRevoked []string, checkpointTimestamp uint64) (*VerificationResult, error) {
	var tlkPtr *C.uint8_t
	tlkLen := C.size_t(0)
	if len(trustedLogKey) == 32 {
		tlkPtr = (*C.uint8_t)(unsafe.Pointer(&trustedLogKey[0]))
		tlkLen = C.size_t(32)
	}

	var chainSlices []C.FfiSlice
	for _, stmt := range chainStatements {
		if len(stmt) == 0 {
			continue
		}
		chainSlices = append(chainSlices, C.FfiSlice{
			data: (*C.uint8_t)(unsafe.Pointer(&stmt[0])),
			len:  C.size_t(len(stmt)),
		})
	}
	var chainPtr *C.FfiSlice
	if len(chainSlices) > 0 {
		chainPtr = &chainSlices[0]
	}

	revokedCsv := C.CString(joinCSV(revoked))
	defer C.free(unsafe.Pointer(revokedCsv))
	notRevokedCsv := C.CString(joinCSV(notRevoked))
	defer C.free(unsafe.Pointer(notRevokedCsv))

	var result C.FfiVerifyResult
	cosePtr := unsafe.Pointer(nil)
	if len(coseData) > 0 {
		cosePtr = unsafe.Pointer(&coseData[0])
	}
	pkPtr := unsafe.Pointer(nil)
	if len(pubkey) > 0 {
		pkPtr = unsafe.Pointer(&pubkey[0])
	}

	ret := C.axiom_verify_full(
		(*C.uint8_t)(cosePtr), C.size_t(len(coseData)),
		(*C.uint8_t)(pkPtr), C.size_t(len(pubkey)),
		tlkPtr, tlkLen,
		chainPtr, C.size_t(len(chainSlices)),
		revokedCsv, notRevokedCsv,
		C.uint64_t(checkpointTimestamp),
		&result,
	)

	if ret != 0 {
		return &VerificationResult{
			Valid:    false,
			Warnings: []string{},
			Error:    fmt.Sprintf("error %d (%s)", ret, errorNames[int(ret)]),
		}, nil
	}

	var payload []byte
	if result.payload != nil {
		payload = C.GoBytes(unsafe.Pointer(result.payload), C.int(result.payload_len))
		C.axiom_free(unsafe.Pointer(result.payload))
	}
	var warnings []string
	if result.warnings != nil {
		warnStr := C.GoString((*C.char)(unsafe.Pointer(result.warnings)))
		C.axiom_free(unsafe.Pointer(result.warnings))
		if warnStr != "" {
			warnings = splitCSV(warnStr)
		}
	}

	return &VerificationResult{
		Valid:    true,
		Payload:  payload,
		Warnings: warnings,
	}, nil
}

func joinCSV(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for _, p := range parts[1:] {
		result += "," + p
	}
	return result
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	current := ""
	for _, c := range s {
		if c == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	result = append(result, current)
	return result
}

// ----- Conformance Suite -----

// TestVector represents a single test case in a conformance suite.
type TestVector struct {
	Name          string `json:"name"`
	IsValid       bool   `json:"is_valid"`
	ExpectedError int    `json:"expected_error,omitempty"`
	SignatureAlg  string `json:"signature_alg,omitempty"`
	PayloadCBOR   string `json:"payload_cbor_hex,omitempty"`
	COSEHex       string `json:"cose_hex,omitempty"`
	CompositeCOSE string `json:"composite_cose_hex,omitempty"`
	CompositePK   string `json:"composite_pk_hex,omitempty"`
	EdPubkeyHex   string `json:"ed_pubkey_hex,omitempty"`
	MLDsaPubkey   string `json:"ml_dsa_pubkey_hex,omitempty"`
}

// ConformanceSuite defines a set of test vectors for validating an
// Verax protocol implementation.
type ConformanceSuite struct {
	Version        string       `json:"version"`
	Description    string       `json:"description"`
	SigningKeySeed string       `json:"signing_key_seed_hex"`
	SigningKeyPK   string       `json:"signing_key_pubkey_hex"`
	MLDsaSeed      string       `json:"ml_dsa_seed_hex"`
	MLDsaPK        string       `json:"ml_dsa_pubkey_hex"`
	Vectors        []TestVector `json:"vectors"`
}

// LoadConformanceSuite reads and parses a JSON conformance suite file
// from the given path.
func LoadConformanceSuite(path string) (*ConformanceSuite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading conformance suite: %w", err)
	}
	var suite ConformanceSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		return nil, fmt.Errorf("parsing conformance suite: %w", err)
	}
	return &suite, nil
}
