//! The control plane and the backup store, inspected (owner decision, 2026-10-28; addon.py
//! `is_control_plane`, `is_backup_request`, `backup_refusal`, ported from main #564 and #599).
//!
//! - **Control plane** (`MITM_CONTROL_PLANE_HOST`): a box's own requests (`/api/vm-agent/…` and a
//!   ready-pool box's `/api/internal/ready-pool/…`, over https on 443, plain paths only) are allowed
//!   for every box, also under the kill switch: no rule, check or swap, the answer streamed, and a
//!   record with the rule `control_plane`. Any other path on that host is an ordinary site.
//! - **Backup store** (`MITM_BACKUP_HOST`, the bucket's virtual-hosted name; or `MITM_BACKUP_BUCKET`
//!   for a store that is not AWS, path-style on that host): only this bucket, only this
//!   organisation's archives (`<org id>/…`, the org from `org.json`), only presigned GET, PUT and
//!   HEAD, over https on 443. Decided from the head, before any body moves; bodies are streamed both
//!   ways, never held. A refusal is recorded (rule `backup_store`) and the connection closed.
//!
//! A box the firewall agent has not marked `cp_inspect` has both passed through by name instead
//! (`splice::tls_passthrough`), during the roll-out.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;

use super::upstream::StreamError;
use super::{
    ClientBody, Conn, Counted, Finish, Killed, Mode, answer, check_destination, raw_host, raw_uri_authority,
    strip_hop_by_hop, to_client,
};
use crate::flow::Flow;
use crate::log::record;
use crate::net::destination::wire_name;

/// The record rules, as the addon names them.
pub const CONTROL_PLANE_RULE: &str = "control_plane";
pub const BACKUP_RULE: &str = "backup_store";

/// What a box calls on the control plane: the vm-agent's channel, the disk reports and cc-perm, and
/// a ready-pool box's claim.
const CONTROL_PLANE_PREFIXES: [&str; 2] = ["/api/vm-agent/", "/api/internal/ready-pool/"];

/// The query a presigned (SigV4) URL carries, and nothing else.
const PRESIGNED: [&str; 6] = [
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-SignedHeaders",
    "X-Amz-Signature",
];

/// The host a request names, in wire form, from its URI authority or else its Host header.
fn named_host<B>(req: &Request<B>) -> Option<String> {
    raw_uri_authority(req)
        .or_else(|| raw_host(req))
        .and_then(|h| wire_name(&h))
}

/// A path nothing could read as another one: no dot segments, no encoded dot, slash or backslash,
/// no backslash, and (with `no_double`) no empty segment. addon.py's
/// `(^|/)\.{1,2}(/|$)|%2e|%2f|\\` (and `//` for the control plane).
fn plain(path: &str, no_double: bool) -> bool {
    let lower = path.to_ascii_lowercase();
    !lower.contains("%2e")
        && !lower.contains("%2f")
        && !path.contains('\\')
        && !(no_double && path.contains("//"))
        && path.split('/').all(|seg| seg != "." && seg != "..")
}

/// The bucket and the host it is named in the path on: from `MITM_BACKUP_BUCKET` (path-style on
/// the backup host itself), else read off a virtual-hosted name (`<bucket>.s3.<region>.amazonaws.com`,
/// path-style on the regional endpoint). None when neither names one.
pub fn bucket(backup_host: Option<&str>, backup_bucket: Option<&str>) -> Option<(String, String)> {
    let host = backup_host?;
    if let Some(vhost) = virtual_hosted(host) {
        let bucket = backup_bucket.map_or_else(|| vhost.0.to_owned(), str::to_owned);
        return Some((bucket, vhost.1.to_owned()));
    }
    backup_bucket.map(|b| (b.to_owned(), host.to_owned()))
}

/// addon.py `_backup_vhost`: `<bucket>.<endpoint>`, the bucket 3 to 63 of `[a-z0-9.-]` (starting
/// and ending alphanumeric), the endpoint `s3.` or `s3-`, at most one more label, `amazonaws.com`.
/// The longest bucket wins, as the addon's greedy match.
fn virtual_hosted(host: &str) -> Option<(&str, &str)> {
    let endpoint_ok = |e: &str| {
        let Some(rest) = e.strip_prefix("s3.").or_else(|| e.strip_prefix("s3-")) else {
            return false;
        };
        let Some(mid) = rest.strip_suffix("amazonaws.com") else {
            return false;
        };
        mid.is_empty()
            || mid.strip_suffix('.').is_some_and(|l| {
                !l.is_empty()
                    && l.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
    };
    let bucket_ok = |b: &str| {
        let bytes = b.as_bytes();
        (3..=63).contains(&b.len())
            && bytes
                .iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'.' || *c == b'-')
            && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
    };
    host.rmatch_indices('.')
        .map(|(i, _)| (&host[..i], &host[i + 1..]))
        .find(|(b, e)| bucket_ok(b) && endpoint_ok(e))
}

/// The first path segment (without the query).
fn first_segment(path: &str) -> &str {
    let bare = path.split_once('?').map_or(path, |(p, _)| p);
    bare.trim_start_matches('/').split('/').next().unwrap_or("")
}

/// addon.py `is_backup_request`: the bucket's own host, or its name first in the path on the host
/// it is named in the path on. Over TLS on 443 only.
pub fn is_backup_request(conn: &Conn, req: &Request<Incoming>) -> bool {
    if conn.mode != Mode::Tls || conn.connect.port != 443 {
        return false;
    }
    let cfg = &conn.shared.ctx.config;
    let Some(host) = named_host(req) else { return false };
    if cfg.backup_host.as_deref() == Some(host.as_str()) {
        return true;
    }
    let path = req.uri().path_and_query().map_or("/", |p| p.as_str());
    bucket(cfg.backup_host.as_deref(), cfg.backup_bucket.as_deref())
        .is_some_and(|(b, on)| host == on && first_segment(path) == b)
}

/// addon.py `backup_refusal`: why this is not a request a box makes for its backups, or None. A box
/// only uploads and downloads archives with the URLs the control plane presigned for it.
fn backup_refusal(conn: &Conn, flow: &Flow, host: &str, req: &Request<Bytes>) -> Option<String> {
    let ctx = &conn.shared.ctx;
    if ctx.locked(flow.vm_id.as_deref()) {
        return Some("this agent is stopped; backups wait until it is released".into());
    }
    let method = req.method().as_str().to_ascii_uppercase();
    if !matches!(method.as_str(), "GET" | "PUT" | "HEAD") {
        return Some(format!(
            "{} is not a backup upload or download",
            method.chars().take(10).collect::<String>()
        ));
    }
    // A host the bucket cannot be read from (a regional endpoint with no MITM_BACKUP_BUCKET): any
    // path on it names a bucket, so nothing on it can be checked as ours.
    let Some((bucket, path_host)) = bucket(ctx.config.backup_host.as_deref(), ctx.config.backup_bucket.as_deref())
    else {
        return Some("the backup bucket is not configured on this firewall".into());
    };
    let pq = req.uri().path_and_query().map_or("/", |p| p.as_str());
    let (mut path, query) = pq.split_once('?').unwrap_or((pq, ""));
    // Path-style: the first segment is the bucket, and it must be ours; then the key follows.
    if host == path_host {
        if path.split('/').nth(1) != Some(bucket.as_str()) {
            return Some("not the backup bucket".into());
        }
        path = &path[bucket.len() + 1..];
    }
    if !path.starts_with('/') || path.len() < 2 || !plain(path, false) {
        return Some("not a backup archive".into());
    }
    // Keys are `<org id>/<backup id>/<kind>.cc`: another organisation's presigned URL is valid for
    // this bucket too, so the first segment must be this firewall's organisation.
    let org = ctx.org_id();
    if org.is_none() || path.split('/').nth(1) != org.as_deref() {
        return Some("not an archive of this organisation".into());
    }
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes()).into_owned().collect();
    let keys: std::collections::BTreeSet<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
    if keys != PRESIGNED.into_iter().collect()
        || pairs.len() != PRESIGNED.len()
        || req.headers().contains_key(http::header::AUTHORIZATION)
    {
        return Some("not a presigned backup URL".into());
    }
    if !pairs
        .iter()
        .any(|(k, v)| k == "X-Amz-Algorithm" && v == "AWS4-HMAC-SHA256")
    {
        return Some("not a presigned backup URL".into());
    }
    None
}

/// addon.py `is_control_plane`: a box's own request to the control plane (its host over https on
/// 443, under one of the prefixes, a plain path). Another port, plain http, or another path on
/// that name gets no allowance and is judged like any site.
pub fn is_control_plane(conn: &Conn, flow: &Flow) -> bool {
    let cfg = &conn.shared.ctx.config;
    let Some(d) = flow.destination() else { return false };
    if conn.mode != Mode::Tls || d.port != 443 || cfg.control_plane_host.as_deref() != Some(d.name.as_str()) {
        return false;
    }
    let path = flow.request.as_ref().map_or("/", |r| r.uri().path());
    plain(path, true) && CONTROL_PLANE_PREFIXES.iter().any(|p| path.starts_with(p))
}

fn boxed(r: Response<Bytes>, version: http::Version, head_only: bool) -> Response<ClientBody> {
    to_client(r, version, head_only).map(|b| b.map_err(|never| match never {}).boxed())
}

/// A backup request: checked like any intercepted request and by [`backup_refusal`] (a refusal
/// recorded, the connection closed), then sent on with its body streamed and the answer streamed
/// back, its record written when the answer ends.
pub async fn stream(conn: &Arc<Conn>, req: Request<Incoming>) -> Result<Response<ClientBody>, Killed> {
    let version = req.version();
    let head_only = req.method() == http::Method::HEAD;
    let (parts, body) = req.into_parts();
    // A head-only copy for the checks; the body stays unread.
    let mut head = Request::new(Bytes::new());
    *head.method_mut() = parts.method.clone();
    *head.uri_mut() = parts.uri.clone();
    *head.version_mut() = parts.version;
    *head.headers_mut() = parts.headers.clone();
    let mut flow = conn.new_flow();
    flow.request = Some(head);
    let ctx = &conn.shared.ctx;
    let d = match check_destination(conn, &flow).await {
        Ok(d) => d,
        // Another name than the tunnel's, over the bucket's (addon.py `requestheaders`: the
        // `_one_destination` refusal is a backup refusal): recorded and closed, never answered.
        Err(super::Early::Misdirected { reason, .. }) => return Err(refuse(conn, &mut flow, &reason)),
        Err(early) => return Ok(boxed(early.into_response(conn, &mut flow), version, head_only)),
    };
    flow.set_destination(d.clone());
    flow.meta.insert("rule", BACKUP_RULE.into());
    let refused = flow
        .request
        .as_ref()
        .and_then(|r| backup_refusal(conn, &flow, &d.name, r));
    if let Some(why) = refused {
        return Err(refuse(conn, &mut flow, &why));
    }
    flow.meta.insert("effect", "allow".into());
    let tls = conn.mode == Mode::Tls || parts.uri.scheme_str() == Some("https");
    let sent = Arc::new(AtomicU64::new(0));
    let body = Counted::new(body.map_err(Into::into), sent.clone(), None).boxed_unsync();
    let mut req = Request::from_parts(parts, body);
    let authority = super::authority_of_head(req.headers(), req.uri(), &d);
    super::to_origin_h1(&mut req, &authority);
    flow.extensions.insert(record::UploadCount(sent.clone()));
    match conn.pool.stream_once(&d, tls, req).await {
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();
            strip_hop_by_hop(&mut parts.headers);
            parts.version = version;
            let mut rec = record::allow_record(ctx, &flow);
            rec.status = cc_contracts::Maybe::Value(u64::from(parts.status.as_u16()).into());
            let done = Finish {
                ctx: ctx.clone(),
                rec,
                started: flow.started,
                up: Some(sent),
            };
            let counted = Counted::new(body.map_err(Into::into), Arc::new(AtomicU64::new(0)), Some(done));
            let bodiless =
                head_only || parts.status == StatusCode::NO_CONTENT || parts.status == StatusCode::NOT_MODIFIED;
            Ok(Response::from_parts(parts, super::to_agent(counted, bodiless)))
        }
        // No connection to the site: mitmproxy's 502, recorded (addon.py `error`); a dial the
        // address check refused has its own block record.
        Err(StreamError::Connect(e)) => {
            let msg = match &e {
                super::upstream::UpstreamError::Refused(why) => super::record_refused(conn, &flow, &d, why),
                super::upstream::UpstreamError::Failed(m) => {
                    super::record_builtin(conn, &mut flow, None, Some(m));
                    m.clone()
                }
            };
            Ok(boxed(
                answer::mitmproxy_error(StatusCode::BAD_GATEWAY, &msg, version),
                version,
                head_only,
            ))
        }
        // Failed while the body was going up (the agent stopped sending, or the site went away):
        // recorded, and the agent's connection closed.
        Err(StreamError::Sent(e)) => {
            super::record_builtin(conn, &mut flow, None, Some(&e));
            Err(Killed(e))
        }
    }
}

/// A backup refusal: recorded (rule `backup_store`, the reason in `error`) and the connection
/// closed, so a refused upload is not read either.
fn refuse(conn: &Conn, flow: &mut Flow, why: &str) -> Killed {
    let ctx = &conn.shared.ctx;
    flow.meta.insert("effect", "block".into());
    flow.meta.insert("rule", BACKUP_RULE.into());
    let mut rec = record::http_record(ctx, flow, "block");
    rec.extra
        .insert("error".into(), crate::net::target::truncate(why, 200).into());
    record::log_once(ctx, flow, &rec);
    let host = flow
        .destination()
        .map_or_else(|| record::record_host(flow), |d| d.name.clone());
    tracing::warn!("[mitm] refused backup request to {host}: {why}");
    Killed(why.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bucket_is_read_off_the_configured_host() {
        let aws = Some("controlclaw-backups.s3.eu-west-1.amazonaws.com");
        assert_eq!(
            bucket(aws, None),
            Some(("controlclaw-backups".into(), "s3.eu-west-1.amazonaws.com".into()))
        );
        assert_eq!(
            bucket(Some("my.dotted.bucket.s3-eu-west-1.amazonaws.com"), None),
            Some(("my.dotted.bucket".into(), "s3-eu-west-1.amazonaws.com".into()))
        );
        assert_eq!(
            bucket(Some("b12.s3.amazonaws.com"), None),
            Some(("b12".into(), "s3.amazonaws.com".into()))
        );
        // A store that is not AWS: its bucket named, path-style on its own host.
        assert_eq!(
            bucket(Some("store.example"), Some("ccb-dev")),
            Some(("ccb-dev".into(), "store.example".into()))
        );
        // A regional endpoint, or any other host, with no bucket named: none.
        assert_eq!(bucket(Some("s3.eu-west-1.amazonaws.com"), None), None);
        assert_eq!(bucket(Some("backups.example.com"), None), None);
        assert_eq!(bucket(None, Some("x")), None);
    }

    #[test]
    fn plain_paths_only() {
        for p in ["/org1/b1/workspace.cc", "/api/vm-agent/config"] {
            assert!(plain(p, true), "{p}");
        }
        for p in [
            "/org1/../org2/x",
            "/org1%2F..%2Forg2/x",
            "/a/%2e%2e/b",
            "/a\\b",
            "/a/./b",
            "/api/vm-agent/..",
        ] {
            assert!(!plain(p, false), "{p}");
        }
        assert!(plain("/a//b", false));
        assert!(!plain("/api/vm-agent//x", true));
    }
}
