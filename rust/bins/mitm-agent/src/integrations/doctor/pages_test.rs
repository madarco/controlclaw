//! What the page tests share: W3's access stood in, and the ingress served on loopback.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use http::HeaderMap;
use serde_json::{Map, Value, json};

use crate::contracts::{PageAccess, PagePerson};

pub const ORIGIN: &str = "https://firewall.example.com";

#[derive(Default)]
pub struct Access {
    pub person: Mutex<Option<PagePerson>>,
    pub inactive: AtomicBool,
    /// The `next` each authorize was asked for.
    pub asked: Mutex<Vec<String>>,
}

impl PageAccess for Access {
    fn origin(&self) -> Option<String> {
        Some(ORIGIN.into())
    }
    fn authorize(&self, _: &HeaderMap, _: String, next: &str) -> cc_http::BoxFuture<Option<PagePerson>> {
        self.asked.lock().expect("lock").push(next.into());
        // Single use, like an intent's jti.
        let p = self.person.lock().expect("lock").take();
        Box::pin(async move { p })
    }
    fn device_active(&self, _: &HeaderMap, _: &str, _: &str, _: &str, _: Option<&str>) -> bool {
        !self.inactive.load(Ordering::SeqCst)
    }
}

pub fn person(can_write: bool, extra: Value) -> PagePerson {
    let mut m = Map::new();
    m.extend(crate::integrations::as_map(extra));
    PagePerson {
        user_id: "owner".into(),
        device_id: "device".into(),
        email: None,
        can_write,
        extra: m,
    }
}

/// The ingress with what `route` puts on it, on a loopback port: its base URL.
pub async fn serve(add: impl FnOnce(&mut crate::app::Registry)) -> String {
    let mut ingress = cc_http::Router::new(crate::stages::INGRESS);
    ingress.fallback(cc_http::empty_not_found);
    let mut up = cc_http::Router::new(&[crate::stages::INGRESS_UPGRADE]);
    up.fallback(|| cc_http::empty(403));
    ingress.upgrades(up);
    let mut reg = crate::app::Registry {
        plain: cc_http::Router::new(crate::stages::PLAIN),
        tls: cc_http::Router::new(crate::stages::TLS),
        ingress,
        commands: crate::commands::Commands::default(),
    };
    add(&mut reg);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", l.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(l, Arc::new(reg.ingress)));
    base
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
}

pub async fn open(base: &str, path: &str, origin: &str) -> reqwest::Response {
    client()
        .post(format!("{base}{path}"))
        .header("origin", origin)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("intent=x")
        .send()
        .await
        .expect("send")
}

pub fn cookie_of(r: &reqwest::Response) -> String {
    r.headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .to_string()
}

pub fn _unused() -> Value {
    json!(null)
}
