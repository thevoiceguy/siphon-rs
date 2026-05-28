// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Regression test for the "Received BYE for unknown dialog" failure
// observed when a UAS application built its 2xx INVITE response with
// `UserAgentServer::create_ok` and sent it via the transaction handle
// directly. That path bypassed dialog registration, so the next BYE
// dispatched as "unknown dialog" and the call leaked.
//
// `IntegratedUAS::accept_invite` is the canonical helper that does the
// full thing — build, auto-fill, send, register dialog. This test
// exercises the dispatch round-trip:
//
//     INVITE  ─►  on_invite ─► IntegratedUAS::accept_invite
//                                                 │
//                                                 ▼
//                                    dialog inserted into manager
//
//     BYE     ─►  dispatch finds dialog
//                                                 │
//                                                 ▼
//                                    on_bye(request, handle, &dialog)

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use sip_core::Request;
use sip_dialog::{Dialog, DialogManager};
use sip_parse::parse_request;
use sip_transaction::{
    ServerTransactionHandle, TransactionManager, TransportContext, TransportDispatcher,
    TransportKind,
};
use sip_uas::integrated::{IntegratedUAS, UasRequestHandler};
use tokio::sync::Mutex;

// ─── Test plumbing ──────────────────────────────────────────────────────

/// Captures every datagram the transaction layer asks the transport to
/// send. The integration test inspects these to recover the To-tag the
/// UAS stamped on the 200 OK so it can build a matching BYE.
#[derive(Default)]
struct CapturingDispatcher {
    sent: Mutex<Vec<Bytes>>,
}

#[async_trait]
impl TransportDispatcher for CapturingDispatcher {
    async fn dispatch(&self, _ctx: &TransportContext, payload: Bytes) -> Result<()> {
        self.sent.lock().await.push(payload);
        Ok(())
    }
}

impl CapturingDispatcher {
    async fn snapshot(&self) -> Vec<Bytes> {
        self.sent.lock().await.clone()
    }
}

/// UAS application: on INVITE accepts via the canonical helper and
/// records the dialog it received; on BYE records the call-id of the
/// dialog dispatch handed it (proving dispatch *found* the dialog) and
/// sends 200 OK.
struct RecordingHandler {
    uas: Mutex<Option<Arc<IntegratedUAS>>>,
    accepted: Mutex<Option<Dialog>>,
    bye_seen_for: Mutex<Vec<String>>,
}

impl RecordingHandler {
    fn new() -> Self {
        Self {
            uas: Mutex::new(None),
            accepted: Mutex::new(None),
            bye_seen_for: Mutex::new(Vec::new()),
        }
    }

    async fn install(&self, uas: Arc<IntegratedUAS>) {
        *self.uas.lock().await = Some(uas);
    }
}

#[async_trait]
impl UasRequestHandler for RecordingHandler {
    async fn on_invite(
        &self,
        request: &Request,
        handle: ServerTransactionHandle,
        ctx: &TransportContext,
        _dialog: Option<&Dialog>,
    ) -> Result<()> {
        let uas =
            self.uas.lock().await.clone().expect(
                "test must install IntegratedUAS handle on RecordingHandler before dispatch",
            );
        let dialog = uas.accept_invite(request, &handle, ctx, None).await?;
        *self.accepted.lock().await = Some(dialog);
        Ok(())
    }

    async fn on_bye(
        &self,
        _request: &Request,
        handle: ServerTransactionHandle,
        _ctx: &TransportContext,
        dialog: &Dialog,
    ) -> Result<()> {
        self.bye_seen_for
            .lock()
            .await
            .push(dialog.id().call_id().to_string());
        // Reply 200 OK; build via UserAgentServer helpers would couple
        // the test to lib internals — emit a minimal Response inline.
        use sip_uas::UserAgentServer;
        let response = UserAgentServer::create_response(_request, 200, "OK");
        handle.send_final(response).await;
        Ok(())
    }
}

// ─── Fixtures ───────────────────────────────────────────────────────────

const CALL_ID: &str = "regression-bye-after-200@127.0.0.1";
const FROM_TAG: &str = "sipp-call-tag-1";

fn make_invite() -> Request {
    let raw = format!(
        "INVITE sip:5000@127.0.0.1:5070 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5080;branch=z9hG4bK-invite-branch\r\n\
         From: \"sipp\" <sip:sipp@127.0.0.1:5080>;tag={tag}\r\n\
         To: <sip:5000@127.0.0.1:5070>\r\n\
         Call-ID: {cid}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:sipp@127.0.0.1:5080>\r\n\
         Max-Forwards: 70\r\n\
         Content-Length: 0\r\n\r\n",
        tag = FROM_TAG,
        cid = CALL_ID,
    );
    parse_request(&Bytes::from(raw.into_bytes())).expect("INVITE parses")
}

fn make_bye(to_tag: &str) -> Request {
    let raw = format!(
        "BYE sip:5000@127.0.0.1:5070 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5080;branch=z9hG4bK-bye-branch\r\n\
         From: \"sipp\" <sip:sipp@127.0.0.1:5080>;tag={tag}\r\n\
         To: <sip:5000@127.0.0.1:5070>;tag={to_tag}\r\n\
         Call-ID: {cid}\r\n\
         CSeq: 2 BYE\r\n\
         Max-Forwards: 70\r\n\
         Content-Length: 0\r\n\r\n",
        tag = FROM_TAG,
        to_tag = to_tag,
        cid = CALL_ID,
    );
    parse_request(&Bytes::from(raw.into_bytes())).expect("BYE parses")
}

/// Pull the To-tag the UAS stamped on the 200 OK out of the captured
/// transport payload, so we can construct a BYE that matches the
/// confirmed dialog identifier.
fn extract_to_tag(payload: &[u8]) -> String {
    let text = std::str::from_utf8(payload).expect("response bytes are UTF-8");
    for line in text.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("to:") || lower.starts_with("t:") {
            // Find ;tag=...
            if let Some(idx) = lower.find(";tag=") {
                let after = &line[idx + 5..];
                let end = after
                    .find(|c: char| c == ';' || c == '>' || c.is_whitespace())
                    .unwrap_or(after.len());
                return after[..end].to_string();
            }
        }
    }
    panic!(
        "no To-tag found in 200 OK; payload was:\n{}",
        std::str::from_utf8(payload).unwrap_or("<non-utf8>")
    );
}

fn ctx() -> TransportContext {
    let peer: SocketAddr = "127.0.0.1:5080".parse().unwrap();
    TransportContext::new(TransportKind::Udp, peer, None)
}

// ─── The regression test ────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn accept_invite_registers_dialog_so_bye_dispatches() {
    let dispatcher = Arc::new(CapturingDispatcher::default());
    let txm = Arc::new(TransactionManager::new(dispatcher.clone()));

    let handler = Arc::new(RecordingHandler::new());

    let uas = Arc::new(
        IntegratedUAS::builder()
            .local_uri("sip:5000@127.0.0.1:5070")
            .contact_uri("sip:5000@127.0.0.1:5070")
            .local_addr("127.0.0.1:5070")
            .expect("local_addr")
            .transaction_manager(Arc::clone(&txm))
            .dispatcher(dispatcher.clone() as Arc<dyn TransportDispatcher>)
            .request_handler(handler.clone() as Arc<dyn UasRequestHandler>)
            .build()
            .expect("builder"),
    );
    handler.install(Arc::clone(&uas)).await;

    // ─── INVITE → 200 OK via accept_invite ─────────────────────────
    let invite = make_invite();
    let invite_handle = txm.receive_request(invite.clone(), ctx()).await;
    uas.dispatch(&invite, invite_handle, &ctx())
        .await
        .expect("dispatch INVITE");

    // The dialog manager must now contain the confirmed dialog.
    let dlg_mgr: Arc<DialogManager> = uas.dialog_manager();
    assert!(
        handler.accepted.lock().await.is_some(),
        "accept_invite returned a Dialog to the handler",
    );
    assert_eq!(
        dlg_mgr.count(),
        1,
        "exactly one active dialog after accept_invite",
    );

    // ─── BYE → must dispatch to on_bye, NOT 'unknown dialog' ───────
    let sent = dispatcher.snapshot().await;
    let two_hundred = sent
        .last()
        .expect("at least one transport-layer send for the 200 OK");
    let to_tag = extract_to_tag(two_hundred);

    let bye = make_bye(&to_tag);
    let bye_handle = txm.receive_request(bye.clone(), ctx()).await;
    uas.dispatch(&bye, bye_handle, &ctx())
        .await
        .expect("dispatch BYE");

    let bye_seen = handler.bye_seen_for.lock().await;
    assert_eq!(
        bye_seen.len(),
        1,
        "on_bye must fire exactly once on the matched dialog",
    );
    assert_eq!(
        &bye_seen[0], CALL_ID,
        "on_bye received the dialog whose call-id matches the INVITE",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn create_ok_path_demonstrates_old_bug_for_documentation() {
    // This test pins the old (broken) flow so future readers can see
    // exactly what `accept_invite` saves them from. We deliberately do
    // NOT call `accept_invite`; we mirror what siphon-ai used to do —
    // build a 2xx with `create_ok` and send it via the handle. The
    // dialog manager stays empty and the BYE comes back as "unknown".

    use sip_uas::UserAgentServer;

    struct ManualHandler {
        helper: Mutex<Option<Arc<Mutex<UserAgentServer>>>>,
        bye_was_unknown: Mutex<bool>,
    }
    #[async_trait]
    impl UasRequestHandler for ManualHandler {
        async fn on_invite(
            &self,
            request: &Request,
            handle: ServerTransactionHandle,
            _ctx: &TransportContext,
            _dialog: Option<&Dialog>,
        ) -> Result<()> {
            let helper_mu = self.helper.lock().await.clone().expect("helper installed");
            let helper = helper_mu.lock().await;
            let response = helper
                .create_ok(request, None)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            drop(helper);
            handle.send_final(response).await;
            Ok(())
        }
        async fn on_bye(
            &self,
            request: &Request,
            handle: ServerTransactionHandle,
            _ctx: &TransportContext,
            _dialog: &Dialog,
        ) -> Result<()> {
            // If we get here it means dispatch did find a dialog — the
            // bug is absent. Flip a flag the test can read.
            *self.bye_was_unknown.lock().await = false;
            let response = UserAgentServer::create_response(request, 200, "OK");
            handle.send_final(response).await;
            Ok(())
        }
    }

    let dispatcher = Arc::new(CapturingDispatcher::default());
    let txm = Arc::new(TransactionManager::new(dispatcher.clone()));

    let handler = Arc::new(ManualHandler {
        helper: Mutex::new(None),
        bye_was_unknown: Mutex::new(true), // assume unknown until on_bye flips it
    });
    let uas = Arc::new(
        IntegratedUAS::builder()
            .local_uri("sip:5000@127.0.0.1:5070")
            .contact_uri("sip:5000@127.0.0.1:5070")
            .local_addr("127.0.0.1:5070")
            .expect("local_addr")
            .transaction_manager(Arc::clone(&txm))
            .dispatcher(dispatcher.clone() as Arc<dyn TransportDispatcher>)
            .request_handler(handler.clone() as Arc<dyn UasRequestHandler>)
            .build()
            .expect("builder"),
    );
    *handler.helper.lock().await = Some(uas.helper());

    // Drive INVITE through dispatch using the manual on_invite that
    // bypasses dialog tracking.
    let invite = make_invite();
    let invite_handle = txm.receive_request(invite.clone(), ctx()).await;
    uas.dispatch(&invite, invite_handle, &ctx())
        .await
        .expect("dispatch INVITE");

    // Manual path stored nothing.
    assert_eq!(
        uas.dialog_manager().count(),
        0,
        "create_ok + send_final does NOT register the dialog",
    );

    // BYE arrives and dispatch can't find it. The default on_bye in
    // dispatch sends 481; our custom on_bye is never called. The flag
    // stays at its default `true`.
    let sent = dispatcher.snapshot().await;
    let two_hundred = sent.last().unwrap();
    let to_tag = extract_to_tag(two_hundred);
    let bye = make_bye(&to_tag);
    let bye_handle = txm.receive_request(bye.clone(), ctx()).await;
    uas.dispatch(&bye, bye_handle, &ctx())
        .await
        .expect("dispatch BYE");

    assert!(
        *handler.bye_was_unknown.lock().await,
        "on_bye was never called: dispatch logged 'unknown dialog' and replied 481",
    );

    // Sanity: a 481 response should have been sent on the wire.
    let final_sent = dispatcher.snapshot().await;
    let last = final_sent.last().unwrap();
    let txt = std::str::from_utf8(last).unwrap();
    assert!(
        txt.starts_with("SIP/2.0 481"),
        "expected dispatch's fallback 481, got first line: {:?}",
        txt.lines().next(),
    );

    let _ = invite; // keep request alive across awaits for clarity
}

/// RFC 3261 §20.41 / §20.50: responses identify the UAS via the
/// `Server` header; `User-Agent` is the *request* counterpart. The
/// integrated dispatch path historically stamped `User-Agent` on
/// every response, which carriers tolerated but was technically
/// wrong. This test drives a real INVITE through dispatch and
/// asserts the captured 200 OK wire bytes carry `Server:` and not
/// `User-Agent:`.
///
/// It also asserts that the 200 OK carries an `Allow` header per
/// §13.2.1, so the calling peer learns what mid-dialog methods we
/// answer for (re-INVITE / UPDATE / REFER / INFO) without having
/// to follow up with an OPTIONS probe.
#[tokio::test(flavor = "current_thread")]
async fn invite_2xx_uses_server_header_and_advertises_allow() {
    let dispatcher = Arc::new(CapturingDispatcher::default());
    let txm = Arc::new(TransactionManager::new(dispatcher.clone()));
    let handler = Arc::new(RecordingHandler::new());

    let uas = Arc::new(
        IntegratedUAS::builder()
            .local_uri("sip:5000@127.0.0.1:5070")
            .contact_uri("sip:5000@127.0.0.1:5070")
            .local_addr("127.0.0.1:5070")
            .expect("local_addr")
            .transaction_manager(Arc::clone(&txm))
            .dispatcher(dispatcher.clone() as Arc<dyn TransportDispatcher>)
            .request_handler(handler.clone() as Arc<dyn UasRequestHandler>)
            .build()
            .expect("builder"),
    );
    handler.install(Arc::clone(&uas)).await;

    let invite = make_invite();
    let invite_handle = txm.receive_request(invite.clone(), ctx()).await;
    uas.dispatch(&invite, invite_handle, &ctx())
        .await
        .expect("dispatch INVITE");

    // Last captured datagram is the 200 OK. (A 100 Trying may have
    // been emitted first depending on config — we pick the final
    // response by looking for the 2xx status line.)
    let sent = dispatcher.snapshot().await;
    let two_hundred = sent
        .iter()
        .map(|b| std::str::from_utf8(b).expect("response is UTF-8"))
        .find(|s| s.starts_with("SIP/2.0 200"))
        .expect("dispatch must have emitted a 200 OK");

    // ── Server vs User-Agent (§20.41 / §20.50) ──
    let header_names: Vec<&str> = two_hundred
        .split("\r\n")
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .collect();
    assert!(
        header_names.iter().any(|n| n.eq_ignore_ascii_case("Server")),
        "200 OK to INVITE must carry `Server:` (responses use Server, not User-Agent)\n{two_hundred}",
    );
    assert!(
        !header_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case("User-Agent")),
        "200 OK to INVITE must NOT carry `User-Agent:` (that's the request-side header)\n{two_hundred}",
    );

    // ── Allow advertised per §13.2.1 ──
    let allow_line = two_hundred
        .split("\r\n")
        .find(|line| line.to_ascii_lowercase().starts_with("allow:"))
        .expect("200 OK to INVITE must include an Allow header (RFC 3261 §13.2.1)");
    for required in &["INVITE", "ACK", "BYE", "CANCEL", "OPTIONS"] {
        assert!(
            allow_line.contains(required),
            "Allow header must list {required} (got {allow_line:?})",
        );
    }
}
