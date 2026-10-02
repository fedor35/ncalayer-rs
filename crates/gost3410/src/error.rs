use core::fmt;

/// Errors produced by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// `p` or `q` is even/zero, or the generator does not lie on the curve.
    InvalidCurveParams,
    /// A point was supplied that does not satisfy the curve equation.
    PointNotOnCurve,
    /// A secret scalar `d` is outside `[1, q-1]`.
    InvalidSecretKey,
    /// A signature component is outside `[1, q-1]`.
    InvalidSignature,
    /// A byte string has the wrong length for the curve.
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// A hex string could not be parsed.
    InvalidHex,
    /// The random number generator kept producing unusable values.
    RngExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidCurveParams => f.write_str("invalid elliptic curve parameters"),
            Error::PointNotOnCurve => f.write_str("point is not on the curve"),
            Error::InvalidSecretKey => f.write_str("secret key is not in [1, q-1]"),
            Error::InvalidSignature => f.write_str("signature components are not in [1, q-1]"),
            Error::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {expected} bytes, got {actual}")
            }
            Error::InvalidHex => f.write_str("invalid hexadecimal string"),
            Error::RngExhausted => f.write_str("random number generator produced no usable value"),
        }
    }
}

impl std::error::Error for Error {}
