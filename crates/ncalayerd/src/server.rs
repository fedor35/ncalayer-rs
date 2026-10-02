//! TLS listener on 127.0.0.1:<port>: WebSocket endpoint plus a small status page.

use crate::ca::ServerCerts;
use crate::cms_api::{self, CmsRequest};
use crate::keys::{self, Selection};
use nca_protocol::KeyType;
use crate::ui::Ui;
use std::path::PathBuf;
use anyhow::Result;
use axum::{
    extract::{
        ws::{rejection::WebSocketUpgradeRejection, Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    http::HeaderMap,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use nca_protocol::{self as proto, BasicsFailure, BasicsResponse, CommonResponse, Request};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    inner: Arc<Shared>,
}

struct Shared {
    port: u16,
    ui: Arc<dyn Ui>,
    settings_path: PathBuf,
}

pub async fn run(port: u16, certs: ServerCerts, ui: Arc<dyn Ui>, settings_path: PathBuf) -> Result<()> {
    let tls = RustlsConfig::from_pem(certs.cert_chain_pem, certs.key_pem).await?;
    let state = AppState { inner: Arc::new(Shared { port, ui, settings_path }) };
    let app = Router::new()
        .route("/", get(root))
        .fallback(get(root))
        .with_state(state);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("listening on wss://{addr}/");
    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

/// Same path serves both: a WebSocket upgrade for sites, a status page for humans.
async fn root(
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> axum::response::Response {
    // Java: `if (!"127.0.0.1".equals(http-client-ip)) "You shall not pass!"`.
    if !peer.ip().is_loopback() {
        return (axum::http::StatusCode::FORBIDDEN, "You shall not pass!").into_response();
    }
    let origin = headers.get("origin").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    match ws {
        Ok(ws) => ws.on_upgrade(move |socket| session(socket, origin, state.inner.clone())),
        Err(_) => Html(status_page(state.inner.port)).into_response(),
    }
}

async fn session(mut socket: WebSocket, origin: String, shared: Arc<Shared>) {
    tracing::info!(%origin, "connection opened");
    if socket.send(Message::Text(proto::greeting().to_string().into())).await.is_err() {
        return;
    }
    while let Some(Ok(msg)) = socket.recv().await {
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Close(_) => break,
            _ => continue,
        };
        if text == proto::HEARTBEAT {
            if socket.send(Message::Text(proto::HEARTBEAT.into())).await.is_err() {
                break;
            }
            continue;
        }
        let reply = dispatch(&text, &origin, &shared).await;
        if socket.send(Message::Text(reply.to_string().into())).await.is_err() {
            break;
        }
    }
    tracing::info!(%origin, "connection closed");
}

async fn dispatch(text: &str, origin: &str, shared: &Shared) -> Value {
    let req = match Request::parse(text) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(%origin, "bad request: {e}");
            return json!({ "success": false, "code": "COMMON_JSON_WRAPPING_EXCEPTION" });
        }
    };
    tracing::info!(%origin, module = %req.module, method = %req.method, "request");
    tracing::debug!(args = %redact(&req.args), "request args");
    let reply = match req.module.as_str() {
        proto::MODULE_COMMON_UTILS => common_utils(&req, shared).await,
        proto::MODULE_BASICS => basics(&req, shared).await,
        proto::MODULE_ACCESSORY => accessory(&req),
        proto::MODULE_APPLET => proto::applet_error(format!("Method not implemented. Method:{}", req.method), req.uuid.clone()),
        other => {
            // Third-party NCALayer bundles (КНП, ЭСФ, Госзакуп…) are Java and cannot be loaded;
            // tell the user which one the site asked for so a shim can be requested (PLAN §5).
            shared.ui.notify("Модуль не поддерживается", &format!("{origin} запросил модуль {other}")).await;
            proto::module_not_found()
        }
    };
    tracing::info!(
        code = %reply.get("code").map(|v| v.to_string()).unwrap_or_default(),
        status = %reply.get("status").map(|v| v.to_string()).unwrap_or_default(),
        message = %reply.get("message").and_then(serde_json::Value::as_str).unwrap_or(""),
        "reply"
    );
    tracing::debug!(reply = %redact(&reply), "reply body");
    // Full copies for offline diagnosis: <data dir>/last-request.json and last-reply.json.
    let _ = std::fs::write(shared.settings_path.with_file_name("last-request.json"), text);
    let _ = std::fs::write(shared.settings_path.with_file_name("last-reply.json"), reply.to_string());
    reply
}

/// JSON for logs: long strings (documents, signatures, PEM) are replaced by their length.
fn redact(v: &Value) -> Value {
    match v {
        Value::String(s) if s.len() > 120 => Value::String(format!("<{} chars: {}…>", s.len(), &s[..40.min(s.len())])),
        Value::Array(a) => Value::Array(a.iter().map(redact).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), redact(v))).collect()),
        other => other.clone(),
    }
}

async fn common_utils(req: &Request, shared: &Shared) -> Value {
    let uuid = req.uuid.clone();
    let resp = match req.method.as_str() {
        // Hardware tokens only; PKCS12 files are never listed here, as in Java.
        "getActiveTokens" => CommonResponse::ok(json!([]), uuid),
        "changeLocale" => CommonResponse::ok(Value::Null, uuid),
        // (ext, currentDir) → absolute path or action.canceled
        "showFileChooser" => {
            let ext = req.arg_str(0).unwrap_or("ALL");
            let dir = req.arg_str(1).filter(|d| !d.is_empty()).map(std::path::Path::new);
            match shared.ui.choose_file(ext, dir).await {
                Some(p) => CommonResponse::ok(Value::String(p.display().to_string()), uuid),
                None => CommonResponse::canceled(uuid),
            }
        }
        "getKeyInfo" => {
            let storage = req.arg_str(0).unwrap_or("PKCS12");
            match keys::select_entry(shared.ui.as_ref(), &shared.settings_path, storage, None).await {
                Ok(Selection::Chosen(entry)) => match keys::key_info(&entry) {
                    Ok(info) => CommonResponse::ok(serde_json::to_value(info).expect("serializable"), uuid),
                    Err(e) => CommonResponse::error(e.to_string(), uuid),
                },
                Ok(Selection::Cancelled) => CommonResponse::canceled(uuid),
                Err(e) => CommonResponse::error(e.to_string(), uuid),
            }
        }
        // (storageName, keyType, base64, attach) — CAdES-T in Java.
        "createCMSSignatureFromBase64" => cms_common(req, shared, CmsKind::Data { attached: flag(req, 3), timestamp: true }).await,
        "createCAdESFromBase64" => cms_common(req, shared, CmsKind::Data { attached: flag(req, 3), timestamp: false }).await,
        "createCAdESFromBase64Hash" => cms_common(req, shared, CmsKind::Hash).await,
        // (storageName, keyType, filePath, attach)
        "createCMSSignatureFromFile" => cms_common(req, shared, CmsKind::File { attached: flag(req, 3), timestamp: true }).await,
        "createCAdESFromFile" => cms_common(req, shared, CmsKind::File { attached: flag(req, 3), timestamp: false }).await,
        // (storageName, keyType, xml, tbsElementXPath?, signatureParentElementXPath?)
        "signXml" => xml_common(req, shared, false).await,
        // (storageName, keyType, [xml…], tbsElementXPath?, signatureParentElementXPath?)
        "signXmls" => xml_common(req, shared, true).await,
        // (storageName, keyType, base64 cms)
        "applyCAdEST" => {
            let cms = req.arg_str(2).unwrap_or("").to_string();
            match tokio::task::spawn_blocking(move || cms_api::apply_cades_t_blocking(&cms)).await {
                Ok(Ok(b64)) => CommonResponse::ok(Value::String(b64), uuid),
                Ok(Err(e)) => CommonResponse::error(e.to_string(), uuid),
                Err(e) => CommonResponse::error(e.to_string(), uuid),
            }
        }
        other => CommonResponse::error(format!("Method {other} is not implemented yet"), uuid),
    };
    serde_json::to_value(resp).expect("serializable")
}

/// `signXml` / `signXmls`: enveloped signature, or detached-by-Id when XPaths are given.
async fn xml_common(req: &Request, shared: &Shared, many: bool) -> CommonResponse {
    let uuid = req.uuid.clone();
    let storage = req.arg_str(0).unwrap_or("PKCS12");
    let key_type = req.arg_str(1).and_then(KeyType::parse);
    let xmls: Vec<String> = if many {
        match req.args.get(2) {
            Some(Value::Array(v)) => v.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
            _ => return CommonResponse::error("xmls must be an array", uuid),
        }
    } else {
        vec![req.arg_str(2).unwrap_or("").to_string()]
    };
    let tbs = req.arg_str(3).filter(|s| !s.is_empty()).map(str::to_string);
    let parent = req.arg_str(4).filter(|s| !s.is_empty()).map(str::to_string);
    let entry = match keys::select_entry(shared.ui.as_ref(), &shared.settings_path, storage, key_type).await {
        Ok(Selection::Chosen(e)) => e,
        Ok(Selection::Cancelled) => return CommonResponse::canceled(uuid),
        Err(e) => return CommonResponse::error(e.to_string(), uuid),
    };
    let r = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
        let mut rng = rand::rng();
        xmls.iter()
            .map(|x| match (&tbs, &parent) {
                (Some(t), Some(p)) => Ok(kz_xmldsig::sign_by_id(&entry, x, t, p, &mut rng)?),
                _ => Ok(kz_xmldsig::sign_enveloped(&entry, x, &mut rng)?),
            })
            .collect()
    })
    .await;
    match r {
        Ok(Ok(mut out)) => CommonResponse::ok(if many { json!(out) } else { Value::String(out.remove(0)) }, uuid),
        Ok(Err(e)) => CommonResponse::error(e.to_string(), uuid),
        Err(e) => CommonResponse::error(e.to_string(), uuid),
    }
}

#[derive(Clone, Copy)]
enum CmsKind {
    Data { attached: bool, timestamp: bool },
    File { attached: bool, timestamp: bool },
    Hash,
}

fn flag(req: &Request, n: usize) -> bool {
    match req.args.get(n) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// Shared body of the commonUtils CMS family: args = (storageName, keyType, payload, flag?).
async fn cms_common(req: &Request, shared: &Shared, kind: CmsKind) -> CommonResponse {
    let uuid = req.uuid.clone();
    let storage = req.arg_str(0).unwrap_or("PKCS12");
    let key_type = req.arg_str(1).and_then(KeyType::parse);
    let payload = req.arg_str(2).unwrap_or("").to_string();
    let data = match kind {
        CmsKind::Data { .. } | CmsKind::Hash => match cms_api::decode_b64(&payload) {
            Ok(d) => d,
            Err(e) => return CommonResponse::error(e.to_string(), uuid),
        },
        CmsKind::File { .. } => match tokio::fs::read(&payload).await {
            Ok(d) => d,
            Err(e) => return CommonResponse::error(format!("{payload}: {e}"), uuid),
        },
    };
    let entry = match keys::select_entry(shared.ui.as_ref(), &shared.settings_path, storage, key_type).await {
        Ok(Selection::Chosen(e)) => e,
        Ok(Selection::Cancelled) => return CommonResponse::canceled(uuid),
        Err(e) => return CommonResponse::error(e.to_string(), uuid),
    };
    let (attached, timestamp, digested) = match kind {
        CmsKind::Data { attached, timestamp } | CmsKind::File { attached, timestamp } => (attached, timestamp, false),
        CmsKind::Hash => (false, false, true),
    };
    let r = tokio::task::spawn_blocking(move || {
        cms_api::sign_blocking(&entry, &CmsRequest { data: &data, attached, digested, timestamp })
    })
    .await;
    match r {
        Ok(Ok(b64)) => CommonResponse::ok(Value::String(b64), uuid),
        Ok(Err(e)) => CommonResponse::error(e.to_string(), uuid),
        Err(e) => CommonResponse::error(e.to_string(), uuid),
    }
}

async fn basics(req: &Request, shared: &Shared) -> Value {
    let resp = match req.method.as_str() {
        "sign" => basics_sign(req, shared).await,
        "generateCsr" | "importCertificate" => {
            BasicsResponse::error(BasicsFailure::GeneralError, format!("{} is not implemented yet", req.method))
        }
        _ => BasicsResponse::error(BasicsFailure::InvocationError, "unknown method"),
    };
    serde_json::to_value(resp).expect("serializable")
}

/// `basics.sign` (apiVersion 2), CMS only for now; `format: "xml"` arrives with stage 5.
async fn basics_sign(req: &Request, shared: &Shared) -> BasicsResponse {
    let a = &req.args;
    let format = a.get("format").and_then(Value::as_str).unwrap_or("cms");
    if format != "cms" && format != "xml" {
        return BasicsResponse::error(BasicsFailure::InvalidSigningParams, format!("format {format} is not supported"));
    }
    let is_xml = format == "xml";
    let sp = a.get("signingParams").cloned().unwrap_or(Value::Null);
    let decode = sp.get("decode").and_then(Value::as_bool).unwrap_or(false);
    let attached = sp.get("encapsulate").and_then(Value::as_bool).unwrap_or(false);
    let digested = sp.get("digested").and_then(Value::as_bool).unwrap_or(false);
    let timestamp = sp.get("tsaProfile").map(|v| !v.is_null()).unwrap_or(false);
    // Java: SigningResponse{result: String | String[]}; only with outputCert → RawSigningResult{signatures[], certificate}.
    let output_cert = sp.get("outputCert").and_then(Value::as_bool).unwrap_or(false);
    let items: Vec<String> = match a.get("data") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(v)) => v.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => return BasicsResponse::error(BasicsFailure::InvalidSigningParams, "data is required"),
    };
    // Key usage from signerParams.extKeyUsageOids: clientAuth → AUTHENTICATION, else SIGNATURE.
    let key_type = a
        .get("signerParams")
        .and_then(|s| s.get("extKeyUsageOids"))
        .and_then(Value::as_array)
        .map(|v| if v.iter().any(|o| o.as_str() == Some("1.3.6.1.5.5.7.3.2")) { KeyType::Authentication } else { KeyType::Signature });
    let entry = match keys::select_entry(shared.ui.as_ref(), &shared.settings_path, "PKCS12", key_type).await {
        Ok(Selection::Chosen(e)) => e,
        Ok(Selection::Cancelled) => return BasicsResponse::canceled(),
        Err(e) => return BasicsResponse::error(BasicsFailure::SigningFailure, e.to_string()),
    };
    let cert_pem = entry.cert.pem().unwrap_or_default();
    let r = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
        let mut out = Vec::new();
        if is_xml {
            let mut rng = rand::rng();
            for item in items {
                // Some portals send the XML base64-encoded with `decode: true`.
                let xml = if decode { String::from_utf8(cms_api::decode_b64(&item)?)? } else { item };
                // basics emits a whitespace-free signature (egov.kz re-serializes before verifying).
                out.push(kz_xmldsig::sign_enveloped_with_layout(&entry, &xml, kz_xmldsig::Layout::Compact, &mut rng)?);
            }
            return Ok(out);
        }
        for item in items {
            // Base64 input is the wire format; `decode` means "sign the decoded bytes", otherwise the text itself.
            let data = if decode || digested { cms_api::decode_b64(&item)? } else { item.into_bytes() };
            out.push(cms_api::sign_blocking(&entry, &CmsRequest { data: &data, attached, digested, timestamp })?);
        }
        Ok(out)
    })
    .await;
    match r {
        // Captured from NCALayer 1.4: `body.result` is an array even for a single `data` string.
        Ok(Ok(sigs)) => {
            if output_cert {
                BasicsResponse::ok(json!({ "signatures": sigs, "certificate": cert_pem }))
            } else {
                BasicsResponse::ok(json!(sigs))
            }
        }
        Ok(Err(e)) => BasicsResponse::error(BasicsFailure::SigningFailure, e.to_string()),
        Err(e) => BasicsResponse::error(BasicsFailure::GeneralError, e.to_string()),
    }
}

fn accessory(req: &Request) -> Value {
    match req.method.as_str() {
        "getBundles" | "getServices" => json!({ "code": "200", "responseObject": [] }),
        _ => json!({ "code": "500", "message": "not supported" }),
    }
}

fn status_page(port: u16) -> String {
    include_str!("../assets/status.html")
        .replace("{{version}}", env!("CARGO_PKG_VERSION"))
        .replace("{{port}}", &port.to_string())
}
