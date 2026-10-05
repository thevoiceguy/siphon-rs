// siphon-rs - The Siphon SIP Stack
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! siphond as a running process, driven over UDP with hand-written SIP:
//! the registrar's expiry bounds, the proxy's CANCEL (RFC 3261 §16.10) and
//! the B2BUA's transport to the callee.

use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Siphond {
    child: Child,
    addr: SocketAddr,
}

impl Drop for Siphond {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn siphond(mode: &str, extra: &[&str]) -> Siphond {
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let child = Command::new(env!("CARGO_BIN_EXE_siphond"))
        .args(["--mode", mode, "--udp-bind", &bind, "--tcp-bind", &bind])
        .args(["--sips-bind", &format!("127.0.0.1:{}", free_port())])
        .args(["--local-uri", &format!("sip:siphond@{bind}")])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("siphond starts");
    let addr: SocketAddr = bind.parse().unwrap();
    // Until it answers OPTIONS.
    let probe = Phone::new("probe");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let options = probe.request("OPTIONS", &format!("sip:{addr}"), "probe-opt", 1, "", &[]);
        probe.send(&options, addr);
        if probe
            .recv_until(Duration::from_millis(300), |m| m.starts_with("SIP/2.0"))
            .is_some()
        {
            break;
        }
        assert!(Instant::now() < deadline, "siphond did not come up");
    }
    Siphond { child, addr }
}

/// A UDP SIP endpoint writing its messages by hand.
struct Phone {
    socket: UdpSocket,
    user: String,
}

impl Phone {
    fn new(user: &str) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        Self {
            socket,
            user: user.to_string(),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    fn request(
        &self,
        method: &str,
        uri: &str,
        call_id: &str,
        cseq: u32,
        branch: &str,
        extra: &[&str],
    ) -> String {
        let branch = if branch.is_empty() {
            format!("z9hG4bK{call_id}{cseq}{method}")
        } else {
            branch.to_string()
        };
        let mut msg = format!(
            "{method} {uri} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {addr};branch={branch}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:{user}@127.0.0.1>;tag={user}-tag\r\n\
             To: {to}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:{user}@{addr}>\r\n",
            addr = self.addr(),
            user = self.user,
            to = if method == "REGISTER" {
                format!("<sip:{}@127.0.0.1>", self.user)
            } else {
                format!("<{uri}>")
            },
        );
        for header in extra {
            msg.push_str(header);
            msg.push_str("\r\n");
        }
        msg.push_str("Content-Length: 0\r\n\r\n");
        msg
    }

    fn send(&self, msg: &str, to: SocketAddr) {
        self.socket.send_to(msg.as_bytes(), to).unwrap();
    }

    /// The first message `want` takes within `within`.
    fn recv_until(&self, within: Duration, want: impl Fn(&str) -> bool) -> Option<String> {
        let deadline = Instant::now() + within;
        let mut buf = [0u8; 65536];
        while Instant::now() < deadline {
            if let Ok((n, _)) = self.socket.recv_from(&mut buf) {
                let msg = String::from_utf8_lossy(&buf[..n]).into_owned();
                if want(&msg) {
                    return Some(msg);
                }
            }
        }
        None
    }

    fn register(&self, server: SocketAddr, expires: u32) -> String {
        let msg = self.request(
            "REGISTER",
            &format!("sip:{server}"),
            &format!("reg-{}-{expires}", self.user),
            1,
            "",
            &[&format!("Expires: {expires}")],
        );
        self.send(&msg, server);
        self.recv_until(Duration::from_secs(3), |m| {
            m.starts_with("SIP/2.0") && !m.starts_with("SIP/2.0 100")
        })
        .expect("REGISTER is answered")
    }
}

fn header<'a>(msg: &'a str, name: &str) -> Option<&'a str> {
    msg.lines().find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[test]
fn the_registrar_takes_its_configured_floor_and_shortens_a_long_ask() {
    let server = siphond(
        "registrar",
        &["--reg-min-expiry", "5", "--reg-max-expiry", "1000"],
    );
    let phone = Phone::new("alice");

    // Ten seconds, above the configured five: taken. (It used to be dropped
    // unanswered: the binding itself refused anything under a minute.)
    let answer = phone.register(server.addr, 10);
    assert!(answer.starts_with("SIP/2.0 200"), "{answer}");

    // Below the floor: 423 with the floor.
    let answer = phone.register(server.addr, 2);
    assert!(answer.starts_with("SIP/2.0 423"), "{answer}");
    assert_eq!(header(&answer, "Min-Expires"), Some("5"));

    // Longer than the ceiling: granted the ceiling, not refused.
    let answer = phone.register(server.addr, 99_999);
    assert!(answer.starts_with("SIP/2.0 200"), "{answer}");
    let contact = header(&answer, "Contact").unwrap_or_default();
    let granted: u32 = contact
        .split(';')
        .find_map(|p| p.trim().strip_prefix("expires="))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("an expires on {contact}"));
    assert!(granted <= 1000, "{answer}");
}

#[test]
fn the_proxy_cancels_down_the_branch_it_forwarded() {
    let server = siphond("proxy", &[]);
    let (alice, bob) = (Phone::new("alice"), Phone::new("bob"));
    assert!(bob.register(server.addr, 3600).starts_with("SIP/2.0 200"));

    let uri = "sip:bob@127.0.0.1";
    let invite = alice.request("INVITE", uri, "cancel-1", 1, "z9hG4bKalice1", &[]);
    alice.send(&invite, server.addr);
    let forwarded = bob
        .recv_until(Duration::from_secs(3), |m| m.starts_with("INVITE "))
        .expect("the INVITE reaches Bob");
    let forwarded_via = header(&forwarded, "Via").unwrap().to_string();

    // Alice gives up: the proxy answers her CANCEL and cancels Bob's leg
    // with the Via it sent him the INVITE with.
    let cancel = alice.request("CANCEL", uri, "cancel-1", 1, "z9hG4bKalice1", &[]);
    alice.send(&cancel, server.addr);
    let answered = alice
        .recv_until(Duration::from_secs(3), |m| {
            m.starts_with("SIP/2.0") && header(m, "CSeq").is_some_and(|c| c.ends_with("CANCEL"))
        })
        .expect("Alice's CANCEL is answered");
    assert!(answered.starts_with("SIP/2.0 200"), "{answered}");
    let cancelled = bob
        .recv_until(Duration::from_secs(3), |m| m.starts_with("CANCEL "))
        .expect("the CANCEL reaches Bob");
    assert_eq!(header(&cancelled, "Via"), Some(forwarded_via.as_str()));
    assert_eq!(header(&cancelled, "CSeq"), Some("1 CANCEL"));
    assert_eq!(header(&cancelled, "Call-ID"), Some("cancel-1"));

    // A CANCEL for nothing the proxy forwarded: 481.
    let stray = alice.request("CANCEL", uri, "cancel-2", 1, "z9hG4bKnothing", &[]);
    alice.send(&stray, server.addr);
    let answered = alice
        .recv_until(Duration::from_secs(3), |m| {
            m.starts_with("SIP/2.0") && header(m, "Call-ID") == Some("cancel-2")
        })
        .expect("the stray CANCEL is answered");
    assert!(answered.starts_with("SIP/2.0 481"), "{answered}");
}

#[test]
fn the_b2bua_reaches_a_callee_over_the_transport_it_registered_with() {
    let server = siphond("b2bua", &[]);
    let (alice, bob) = (Phone::new("alice"), Phone::new("bob"));
    assert!(bob.register(server.addr, 3600).starts_with("SIP/2.0 200"));

    // Bob registered over UDP: the B2BUA's INVITE to him comes over UDP
    // (it used to open a TCP connection to him, and never read it).
    let invite = alice.request("INVITE", "sip:bob@127.0.0.1", "b2b-1", 1, "", &[]);
    alice.send(&invite, server.addr);
    let reached = bob
        .recv_until(Duration::from_secs(3), |m| m.starts_with("INVITE "))
        .expect("the INVITE reaches Bob over UDP");
    assert!(
        header(&reached, "Via").is_some_and(|v| v.contains("SIP/2.0/UDP")),
        "{reached}"
    );
}
