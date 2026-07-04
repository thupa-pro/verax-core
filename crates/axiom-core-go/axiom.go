package axiom

/*
#cgo LDFLAGS: -laxiom_core_ffi -lm -ldl
#cgo CFLAGS: -I../crates/axiom-core-ffi/include

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

// Error codes matching the C-ABI
const (
	ErrMalformedCose    = 1
	ErrNonCanonical     = 2
	ErrInvalidSignature = 3
	ErrBrokenLineage    = 4
	ErrLineageSubject   = 5
	ErrTimestampViol    = 6
	ErrRevokeIssuer     = 7
	ErrInvalidLogProof  = 8
	ErrRevoked          = 9
	ErrInvalidField     = 10
	ErrCrypto           = 11
	ErrDecode           = 12
	ErrHashLength       = 13
	ErrIo               = 14
	ErrPayload          = 15
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

type AxiomError struct {
	Code    int
	Message string
}

func (e *AxiomError) Error() string {
	name, ok := errorNames[e.Code]
	if !ok {
		name = "Unknown"
	}
	return fmt.Sprintf("Axiom error %d (%s): %s", e.Code, name, e.Message)
}

// ----- Version -----

func Version() string {
	cstr := C.axiom_version()
	return C.GoString(cstr)
}

// ----- Verification (basic) -----

func VerifyMLDsa65Only(coseData []byte, pubkey []byte) ([]byte, error) {
	expectedMLDsaLen := 1952
	if len(pubkey) != expectedMLDsaLen {
		return nil, &AxiomError{
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
		return nil, &AxiomError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	if outPayload == nil {
		return nil, &AxiomError{Code: ErrDecode, Message: "null output"}
	}
	payloadBytes := C.GoBytes(unsafe.Pointer(outPayload), C.int(outLen))
	C.axiom_free(unsafe.Pointer(outPayload))
	return payloadBytes, nil
}

func VerifyEd25519(coseData []byte, pubkey []byte) ([]byte, error) {
	if len(pubkey) != 32 {
		return nil, &AxiomError{Code: ErrInvalidField, Message: "Ed25519 pubkey must be 32 bytes"}
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
		return nil, &AxiomError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	if outPayload == nil {
		return nil, &AxiomError{Code: ErrDecode, Message: "null output"}
	}
	payloadBytes := C.GoBytes(unsafe.Pointer(outPayload), C.int(outLen))
	C.axiom_free(unsafe.Pointer(outPayload))
	return payloadBytes, nil
}

func VerifyComposite(coseData []byte, edPubkey []byte, mlDsaPubkey []byte) ([]byte, error) {
	if len(edPubkey) != 32 {
		return nil, &AxiomError{Code: ErrInvalidField, Message: "Ed25519 pubkey must be 32 bytes"}
	}
	expectedMLDsaLen := 1952
	if len(mlDsaPubkey) != expectedMLDsaLen {
		return nil, &AxiomError{
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
		return nil, &AxiomError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	if outPayload == nil {
		return nil, &AxiomError{Code: ErrDecode, Message: "null output"}
	}
	payloadBytes := C.GoBytes(unsafe.Pointer(outPayload), C.int(outLen))
	C.axiom_free(unsafe.Pointer(outPayload))
	return payloadBytes, nil
}

// ----- Signing -----

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
		return nil, &AxiomError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	sigBytes := C.GoBytes(unsafe.Pointer(outSig), C.int(outSigLen))
	C.axiom_free(unsafe.Pointer(outSig))
	return sigBytes, nil
}

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
		return nil, &AxiomError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	sigBytes := C.GoBytes(unsafe.Pointer(outSig), C.int(outSigLen))
	C.axiom_free(unsafe.Pointer(outSig))
	return sigBytes, nil
}

// ----- PII Shredding -----

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
		return nil, &AxiomError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	ctBytes := C.GoBytes(unsafe.Pointer(outCt), C.int(outCtLen))
	C.axiom_free(unsafe.Pointer(outCt))
	return ctBytes, nil
}

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
		return nil, &AxiomError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	ptBytes := C.GoBytes(unsafe.Pointer(outPt), C.int(outPtLen))
	C.axiom_free(unsafe.Pointer(outPt))
	return ptBytes, nil
}

type ShreddingCommitResult struct {
	Ciphertext []byte
	Commitment []byte
}

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
		return nil, &AxiomError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	ctBytes := C.GoBytes(unsafe.Pointer(outCt), C.int(outCtLen))
	C.axiom_free(unsafe.Pointer(outCt))
	commBytes := C.GoBytes(unsafe.Pointer(outComm), C.int(outCommLen))
	C.axiom_free(unsafe.Pointer(outComm))
	return &ShreddingCommitResult{Ciphertext: ctBytes, Commitment: commBytes}, nil
}

// ----- Payload -----

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
		return nil, &AxiomError{Code: int(ret), Message: errorNames[int(ret)]}
	}
	cborBytes := C.GoBytes(unsafe.Pointer(outCbor), C.int(outCborLen))
	C.axiom_free(unsafe.Pointer(outCbor))
	return cborBytes, nil
}

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
		return nil, &AxiomError{Code: int(ret), Message: errorNames[int(ret)]}
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

type VerificationResult struct {
	Valid    bool     `json:"valid"`
	Payload  []byte   `json:"payload,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Error    string   `json:"error,omitempty"`
}

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

type ConformanceSuite struct {
	Version        string       `json:"version"`
	Description    string       `json:"description"`
	SigningKeySeed string       `json:"signing_key_seed_hex"`
	SigningKeyPK   string       `json:"signing_key_pubkey_hex"`
	MLDsaSeed      string       `json:"ml_dsa_seed_hex"`
	MLDsaPK        string       `json:"ml_dsa_pubkey_hex"`
	Vectors        []TestVector `json:"vectors"`
}

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
