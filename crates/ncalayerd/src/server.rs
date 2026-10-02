//! TLS listener on 127.0.0.1:<port>: WebSocket endpoint plus a small status page.

use crate::ca::ServerCerts;
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
}

pub async fn run(port: u16, certs: ServerCerts) -> Result<()> {
    let tls = RustlsConfig::from_pem(certs.cert_chain_pem, certs.key_pem).await?;
    let state = AppState { inner: Arc::new(Shared { port }) };
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
        Ok(ws) => ws.on_upgrade(move |socket| session(socket, origin)),
        Err(_) => Html(status_page(state.inner.port)).into_response(),
    }
}

async fn session(mut socket: WebSocket, origin: String) {
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
        let reply = dispatch(&text, &origin).await;
        if socket.send(Message::Text(reply.to_string().into())).await.is_err() {
            break;
        }
    }
    tracing::info!(%origin, "connection closed");
}

async fn dispatch(text: &str, origin: &str) -> Value {
    let req = match Request::parse(text) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(%origin, "bad request: {e}");
            return json!({ "success": false, "code": "COMMON_JSON_WRAPPING_EXCEPTION" });
        }
    };
    tracing::info!(%origin, module = %req.module, method = %req.method, "request");
    match req.module.as_str() {
        proto::MODULE_COMMON_UTILS => common_utils(&req),
        proto::MODULE_BASICS => basics(&req),
        proto::MODULE_ACCESSORY => accessory(&req),
        proto::MODULE_APPLET => proto::applet_error(format!("Method not implemented. Method:{}", req.method), req.uuid.clone()),
        _ => proto::module_not_found(),
    }
}

fn common_utils(req: &Request) -> Value {
    let uuid = req.uuid.clone();
    let resp = match req.method.as_str() {
        // Hardware tokens only; PKCS12 files are never listed here, as in Java.
        "getActiveTokens" => CommonResponse::ok(json!([]), uuid),
        "changeLocale" => CommonResponse::ok(Value::Null, uuid),
        other => CommonResponse::error(format!("Method {other} is not implemented yet"), uuid),
    };
    serde_json::to_value(resp).expect("serializable")
}

fn basics(req: &Request) -> Value {
    let resp = match req.method.as_str() {
        "sign" | "generateCsr" | "importCertificate" => {
            BasicsResponse::error(BasicsFailure::GeneralError, format!("{} is not implemented yet", req.method))
        }
        _ => BasicsResponse::error(BasicsFailure::InvocationError, "unknown method"),
    };
    serde_json::to_value(resp).expect("serializable")
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
