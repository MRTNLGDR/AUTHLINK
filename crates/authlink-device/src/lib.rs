use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const DEVICE_PROOF_VERSION: u8 = 1;
pub const DEVICE_KEY_ALG: &str = "ECDSA-P256-SHA256";
pub const CHALLENGE_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct P256PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceChallengeAction {
    Enroll,
    BindSession,
}

impl DeviceChallengeAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::BindSession => "bind-session",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChallengeContext<'a> {
    pub challenge_id: Uuid,
    pub session_id: Uuid,
    pub identity_id: Uuid,
    pub action: DeviceChallengeAction,
    pub nonce: &'a [u8],
}

#[derive(Debug, Error)]
pub enum DeviceProofError {
    #[error("unsupported device key type")]
    UnsupportedKeyType,
    #[error("unsupported device curve")]
    UnsupportedCurve,
    #[error("invalid base64url field: {0}")]
    InvalidBase64(&'static str),
    #[error("P-256 coordinate {field} must be 32 bytes, got {actual}")]
    InvalidCoordinateLength { field: &'static str, actual: usize },
    #[error("invalid P-256 public key")]
    InvalidPublicKey,
    #[error("device signature must be 64 raw bytes, got {0}")]
    InvalidSignatureLength(usize),
    #[error("device signature is invalid")]
    InvalidSignature,
    #[error("challenge nonce must be {CHALLENGE_BYTES} bytes, got {0}")]
    InvalidChallengeLength(usize),
}

pub fn challenge_message(context: &ChallengeContext<'_>) -> Result<Vec<u8>, DeviceProofError> {
    if context.nonce.len() != CHALLENGE_BYTES {
        return Err(DeviceProofError::InvalidChallengeLength(context.nonce.len()));
    }
    Ok(format!(
        "authlink-device:v{DEVICE_PROOF_VERSION}:{}:{}:{}:{}:{}",
        context.challenge_id,
        context.session_id,
        context.identity_id,
        context.action.as_str(),
        URL_SAFE_NO_PAD.encode(context.nonce)
    )
    .into_bytes())
}

pub fn challenge_message_b64(context: &ChallengeContext<'_>) -> Result<String, DeviceProofError> {
    Ok(URL_SAFE_NO_PAD.encode(challenge_message(context)?))
}

pub fn fingerprint(jwk: &P256PublicJwk) -> Result<String, DeviceProofError> {
    let sec1 = sec1_bytes(jwk)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(sec1)))
}

pub fn verify_b64_signature(
    jwk: &P256PublicJwk,
    message_b64: &str,
    signature_b64: &str,
) -> Result<(), DeviceProofError> {
    let message = URL_SAFE_NO_PAD
        .decode(message_b64)
        .map_err(|_| DeviceProofError::InvalidBase64("message"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| DeviceProofError::InvalidBase64("signature"))?;
    verify_signature(jwk, &message, &signature)
}

pub fn verify_signature(
    jwk: &P256PublicJwk,
    message: &[u8],
    signature: &[u8],
) -> Result<(), DeviceProofError> {
    let verifying_key = verifying_key(jwk)?;
    if signature.len() != SIGNATURE_BYTES {
        return Err(DeviceProofError::InvalidSignatureLength(signature.len()));
    }
    let signature = Signature::from_slice(signature)
        .map_err(|_| DeviceProofError::InvalidSignature)?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| DeviceProofError::InvalidSignature)
}

fn verifying_key(jwk: &P256PublicJwk) -> Result<VerifyingKey, DeviceProofError> {
    let sec1 = sec1_bytes(jwk)?;
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| DeviceProofError::InvalidPublicKey)
}

fn sec1_bytes(jwk: &P256PublicJwk) -> Result<Vec<u8>, DeviceProofError> {
    if jwk.kty != "EC" {
        return Err(DeviceProofError::UnsupportedKeyType);
    }
    if jwk.crv != "P-256" {
        return Err(DeviceProofError::UnsupportedCurve);
    }
    let x = decode_coordinate("x", &jwk.x)?;
    let y = decode_coordinate("y", &jwk.y)?;
    let point = EncodedPoint::from_affine_coordinates(
        p256::FieldBytes::from_slice(&x),
        p256::FieldBytes::from_slice(&y),
        false,
    );
    Ok(point.as_bytes().to_vec())
}

fn decode_coordinate(field: &'static str, value: &str) -> Result<[u8; 32], DeviceProofError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| DeviceProofError::InvalidBase64(field))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| DeviceProofError::InvalidCoordinateLength {
            field,
            actual: bytes.len(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    fn fixture_key() -> (SigningKey, P256PublicJwk) {
        let signing = SigningKey::from_bytes((&[7_u8; 32]).into()).expect("valid fixture scalar");
        let point = signing.verifying_key().to_encoded_point(false);
        let x = point.x().expect("x coordinate");
        let y = point.y().expect("y coordinate");
        let jwk = P256PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
        };
        (signing, jwk)
    }

    #[test]
    fn verifies_webcrypto_style_raw_signature() {
        let (signing, jwk) = fixture_key();
        let message = b"authlink-device-test";
        let signature: Signature = signing.sign(message);
        verify_signature(&jwk, message, signature.to_bytes().as_slice()).unwrap();
    }

    #[test]
    fn challenge_binds_session_identity_and_action() {
        let nonce = [3_u8; CHALLENGE_BYTES];
        let context = ChallengeContext {
            challenge_id: Uuid::now_v7(),
            session_id: Uuid::new_v4(),
            identity_id: Uuid::now_v7(),
            action: DeviceChallengeAction::Enroll,
            nonce: &nonce,
        };
        let first = challenge_message(&context).unwrap();
        let second = challenge_message(&ChallengeContext {
            action: DeviceChallengeAction::BindSession,
            ..context
        })
        .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn fingerprint_is_stable_and_key_specific() {
        let (_, jwk) = fixture_key();
        let first = fingerprint(&jwk).unwrap();
        let second = fingerprint(&jwk).unwrap();
        assert_eq!(first, second);
        assert!(!first.contains('='));
    }

    #[test]
    fn rejects_wrong_curve_and_tampering() {
        let (signing, mut jwk) = fixture_key();
        jwk.crv = "P-384".into();
        assert!(matches!(fingerprint(&jwk), Err(DeviceProofError::UnsupportedCurve)));

        let (_, jwk) = fixture_key();
        let signature: Signature = signing.sign(b"correct");
        assert!(matches!(
            verify_signature(&jwk, b"wrong", signature.to_bytes().as_slice()),
            Err(DeviceProofError::InvalidSignature)
        ));
    }
}
