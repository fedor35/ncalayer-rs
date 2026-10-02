//! Wire-level types of the NCALayer JSON protocol spoken over `wss://127.0.0.1:13579`.
//!
//! Three API families coexist and sites still use all of them:
//! * `kz.gov.pki.knca.commonUtils` — positional `args`, reply `{code, message, responseObject}`;
//! * `kz.gov.pki.knca.basics` — named `args`, reply `{status, code, message, body}`;
//! * `kz.gov.pki.knca.applet.Applet` — legacy, the default when `module` is absent.
//!
//! This crate contains no I/O and no cryptography: it only parses requests and renders
//! responses byte-compatible with the Java implementation.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MODULE_COMMON_UTILS: &str = "kz.gov.pki.knca.commonUtils";
pub const MODULE_BASICS: &str = "kz.gov.pki.knca.basics";
pub const MODULE_APPLET: &str = "kz.gov.pki.knca.applet.Applet";
pub const MODULE_ACCESSORY: &str = "kz.gov.pki.ncalayerservices.accessory";

/// Version string reported in the greeting; sites compare it with the one they expect.
pub const NCALAYER_VERSION: &str = "1.4";
pub const HEARTBEAT: &str = "--heartbeat--";

/// Greeting sent right after the WebSocket is open: `{"result":{"version":"1.4"}}`.
pub fn greeting() -> Value {
    json!({ "result": { "version": NCALAYER_VERSION } })
}

/// A parsed incoming request. `module` defaults to the legacy applet, as in Java.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    #[serde(default = "default_module")]
    pub module: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub args: Value,
    /// Echoed back verbatim by commonUtils / applet if present.
    #[serde(default)]
    pub uuid: Option<Value>,
}

fn default_module() -> String {
    MODULE_APPLET.to_string()
}

impl Request {
    pub fn parse(text: &str) -> Result<Self, ProtocolError> {
        serde_json::from_str(text).map_err(|e| ProtocolError::BadJson(e.to_string()))
    }

    /// Positional argument `n` as a string (commonUtils / applet style).
    pub fn arg_str(&self, n: usize) -> Option<&str> {
        self.args.get(n).and_then(Value::as_str)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("malformed JSON: {0}")]
    BadJson(String),
}

/// Reply for a `module` nobody registered — exactly what Felix-based NCALayer sends.
pub fn module_not_found() -> Value {
    json!({ "success": false, "errorCode": "MODULE_NOT_FOUND" })
}

/// `commonUtils` response envelope.
#[derive(Debug, Clone, Serialize)]
pub struct CommonResponse {
    pub code: String,
    pub message: String,
    #[serde(rename = "responseObject", skip_serializing_if = "Value::is_null")]
    pub response_object: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<Value>,
}

impl CommonResponse {
    pub fn ok(response_object: Value, uuid: Option<Value>) -> Self {
        Self { code: "200".into(), message: String::new(), response_object, uuid }
    }
    pub fn error(message: impl Into<String>, uuid: Option<Value>) -> Self {
        Self { code: "500".into(), message: message.into(), response_object: Value::Null, uuid }
    }
    /// The user closed the key dialog: Java answers `500` + `action.canceled`.
    pub fn canceled(uuid: Option<Value>) -> Self {
        Self::error("action.canceled", uuid)
    }
}

/// `basics` (apiVersion 2) response envelope.
#[derive(Debug, Clone, Serialize)]
pub struct BasicsResponse {
    pub status: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

impl BasicsResponse {
    pub fn ok(result: Value) -> Self {
        Self { status: true, code: None, message: None, details: None, body: Some(json!({ "result": result })) }
    }
    /// User cancelled: `status:true` with an empty body (that is how ncalayer-client.js detects it).
    pub fn canceled() -> Self {
        Self { status: true, code: None, message: None, details: None, body: Some(json!({})) }
    }
    pub fn error(code: BasicsFailure, message: impl Into<String>) -> Self {
        Self { status: false, code: Some(code.as_str().into()), message: Some(message.into()), details: None, body: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicsFailure {
    InvalidSigningParams,
    SigningFailure,
    CsrGeneratingFailure,
    CertificateImportingFailure,
    InvalidImportingCertificate,
    GeneralError,
    InvocationError,
}

impl BasicsFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSigningParams => "INVALID_SIGNING_PARAMS",
            Self::SigningFailure => "SIGNING_FAILURE",
            Self::CsrGeneratingFailure => "CSR_GENERATING_FAILURE",
            Self::CertificateImportingFailure => "CERTIFICATE_IMPORTING_FAILURE",
            Self::InvalidImportingCertificate => "INVALID_IMPORTING_CERTIFICATE",
            Self::GeneralError => "GENERAL_ERROR",
            Self::InvocationError => "INVOCATION_ERROR",
        }
    }
}

/// Legacy applet envelope `{result, secondResult, errorCode}`.
pub fn applet_error(error_code: impl Into<String>, uuid: Option<Value>) -> Value {
    let mut v = json!({ "errorCode": error_code.into() });
    if let Some(u) = uuid {
        v["uuid"] = u;
    }
    v
}

/// Key usage selector shared by all APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    #[serde(rename = "AUTHENTICATION")]
    Authentication,
    #[serde(rename = "SIGNATURE")]
    Signature,
}

impl KeyType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "AUTHENTICATION" | "AUTH" => Some(Self::Authentication),
            "SIGNATURE" | "SIGN" => Some(Self::Signature),
            _ => None,
        }
    }
}

/// `responseObject` of `commonUtils.getKeyInfo`, field names and order as in Java `KeyInfo`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub alias: String,
    pub key_id: String,
    pub algorithm: String,
    pub subject_cn: String,
    pub subject_dn: String,
    pub issuer_cn: String,
    pub issuer_dn: String,
    pub serial_number: String,
    /// `dd.MM.yyyy HH:mm:ss`, Asia/Almaty.
    pub cert_not_after: String,
    pub cert_not_before: String,
    pub authority_key_identifier: String,
    pub pem: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_defaults_to_legacy_applet() {
        let r = Request::parse(r#"{"method":"signXml","args":["PKCS12","/k.p12","pw","<a/>"]}"#).unwrap();
        assert_eq!(r.module, MODULE_APPLET);
        assert_eq!(r.arg_str(0), Some("PKCS12"));
        assert_eq!(r.arg_str(3), Some("<a/>"));
    }

    #[test]
    fn common_response_shapes() {
        let ok = serde_json::to_value(CommonResponse::ok(json!(["PKCS12"]), Some(json!("u1")))).unwrap();
        assert_eq!(ok, json!({"code":"200","message":"","responseObject":["PKCS12"],"uuid":"u1"}));
        let cancel = serde_json::to_value(CommonResponse::canceled(None)).unwrap();
        assert_eq!(cancel, json!({"code":"500","message":"action.canceled"}));
    }

    #[test]
    fn basics_response_shapes() {
        let ok = serde_json::to_value(BasicsResponse::ok(json!({"signatures":["x"]}))).unwrap();
        assert_eq!(ok, json!({"status":true,"body":{"result":{"signatures":["x"]}}}));
        let err = serde_json::to_value(BasicsResponse::error(BasicsFailure::InvocationError, "no such method")).unwrap();
        assert_eq!(err["code"], "INVOCATION_ERROR");
        assert_eq!(err["status"], false);
    }

    #[test]
    fn module_not_found_shape() {
        assert_eq!(module_not_found(), json!({"success":false,"errorCode":"MODULE_NOT_FOUND"}));
    }
}
