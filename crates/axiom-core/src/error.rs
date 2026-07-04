use alloc::string::String;
use alloc::string::ToString;
use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    MalformedCose(String),
    NonCanonicalEncoding,
    InvalidSignature,
    BrokenLineage(String),
    LineageSubjectMismatch,
    TimestampMonotonicityViolation,
    RevokeIssuerMismatch,
    InvalidLogProof(String),
    Revoked,
    InvalidField(&'static str),
    Crypto(String),
    Decode(String),
    HashLength { expected: usize, actual: usize },
    Io(String),
    Payload(String),
    RecoveryPolicyViolation(String),
    AnchorHashMismatch,
    LineageDepthExceeded,
    /// CBOR encoding failure (FFI error code 16).
    Encode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MalformedCose(msg) => write!(f, "malformed COSE: {msg}"),
            Error::NonCanonicalEncoding => write!(f, "non-canonical CBOR encoding"),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::BrokenLineage(msg) => write!(f, "broken lineage: {msg}"),
            Error::LineageSubjectMismatch => write!(f, "lineage subject mismatch"),
            Error::TimestampMonotonicityViolation => write!(f, "timestamp monotonicity violation"),
            Error::RevokeIssuerMismatch => write!(f, "REVOKES issuer does not match revoked statement issuer"),
            Error::InvalidLogProof(msg) => write!(f, "invalid log proof: {msg}"),
            Error::Revoked => write!(f, "statement has been revoked"),
            Error::InvalidField(name) => write!(f, "invalid field: {name}"),
            Error::Crypto(msg) => write!(f, "crypto error: {msg}"),
            Error::Decode(msg) => write!(f, "decode error: {msg}"),
            Error::HashLength { expected, actual } => {
                write!(f, "hash length: expected {expected}, got {actual}")
            }
            Error::Io(msg) => write!(f, "I/O error: {msg}"),
            Error::Payload(msg) => write!(f, "payload error: {msg}"),
            Error::RecoveryPolicyViolation(msg) => write!(f, "recovery policy violation: {msg}"),
            Error::AnchorHashMismatch => write!(f, "anchor hash mismatch"),
            Error::LineageDepthExceeded => write!(f, "lineage traversal depth exceeded"),
            Error::Encode(msg) => write!(f, "encode error: {msg}"),
        }
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(e: ed25519_dalek::ed25519::Error) -> Self {
        Error::Crypto(e.to_string())
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(_: core::array::TryFromSliceError) -> Self {
        Error::HashLength { expected: 32, actual: 0 }
    }
}
