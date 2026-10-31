//! `screen-thumb.test.ts`: one picture per 30 s, one capture at a time, a failure backed off.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

fn counting(fail: bool) -> (Capture, Arc<AtomicUsize>) {
    let n = Arc::new(AtomicUsize::new(0));
    let c = n.clone();
    let cap: Capture = Arc::new(move || {
        let c = c.clone();
        async move {
            c.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if fail {
                Err(unavailable("The agent's screen is not running.", "no-screen"))
            } else {
                Ok(Bytes::from_static(b"\xff\xd8jpeg"))
            }
        }
        .boxed()
    });
    (cap, n)
}

#[test]
fn the_pipe_is_four_programs_under_nice() {
    assert_eq!(
        capture_commands(":1"),
        vec![
            vec!["-n", "10", "xwd", "-root", "-silent", "-display", ":1"],
            vec!["-n", "10", "xwdtopnm", "-quiet"],
            vec!["-n", "10", "pamscale", "-quiet", "-width", "320"],
            vec!["-n", "10", "pnmtojpeg", "-quiet", "-quality=50"],
        ]
    );
}

#[tokio::test]
async fn one_capture_for_callers_at_once_and_the_picture_reused() {
    let (cap, n) = counting(false);
    let t = ScreenThumbs::new(cap);
    let (a, b) = tokio::join!(t.get(), t.get());
    assert_eq!(a, b);
    assert_eq!(n.load(Ordering::SeqCst), 1);
    assert!(t.get().await.is_ok());
    assert_eq!(n.load(Ordering::SeqCst), 1, "younger than 30 s: from memory");
}

#[tokio::test]
async fn a_failure_is_not_retried_on_every_request() {
    let (cap, n) = counting(true);
    let t = ScreenThumbs::new(cap);
    assert_eq!(t.get().await.expect_err("no screen").code, "no-screen");
    assert_eq!(t.get().await.expect_err("backed off").code, "no-screen");
    assert_eq!(n.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_route_answers_a_picture_or_why_not() {
    let (cap, _) = counting(false);
    let r = handle(&ScreenThumbs::new(cap)).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "image/jpeg");
    assert!(r.headers().contains_key("x-captured-at"));
    let (cap, _) = counting(true);
    assert_eq!(handle(&ScreenThumbs::new(cap)).await.status(), 503);
}

#[tokio::test]
async fn a_capture_its_caller_left_is_still_kept() {
    let (cap, n) = counting(false);
    let t = ScreenThumbs::new(cap);
    {
        let gone = t.get();
        tokio::pin!(gone);
        assert!(futures_util::poll!(&mut gone).is_pending());
    }
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;
    assert!(t.get().await.is_ok());
    assert_eq!(
        n.load(Ordering::SeqCst),
        1,
        "the picture from the capture nobody waited for"
    );
}
