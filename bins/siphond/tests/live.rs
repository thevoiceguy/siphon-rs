// siphon-rs - The Siphon SIP Stack
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! siphond as a running process, driven over UDP with hand-written SIP:
//! the registrar's expiry bounds, the proxy's CANCEL (RFC 3261 §16.10), its
//! TCP leg to a callee, and the B2BUA's transport to the callee.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
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
        self.recv_from_until(within, want).map(|(msg, _)| msg)
    }

    /// The first message `want` takes within `within`, and where it came from.
    fn recv_from_until(
        &self,
        within: Duration,
        want: impl Fn(&str) -> bool,
    ) -> Option<(String, SocketAddr)> {
        let deadline = Instant::now() + within;
        let mut buf = [0u8; 65536];
        while Instant::now() < deadline {
            if let Ok((n, from)) = self.socket.recv_from(&mut buf) {
                let msg = String::from_utf8_lossy(&buf[..n]).into_owned();
                if want(&msg) {
                    return Some((msg, from));
                }
            }
        }
        None
    }

    /// A response to `request`, sent back to where it came from.
    fn respond(&self, request: &str, code: u16, reason: &str, to: SocketAddr) {
        self.send(&self.response(request, code, reason), to);
    }

    /// A response to `request`: every Via, From, To (tagged), Call-ID and
    /// CSeq copied from it, and this phone's Contact.
    fn response(&self, request: &str, code: u16, reason: &str) -> String {
        let mut msg = format!(
            "SIP/2.0 {code} {reason}\r\nContact: <sip:{}@{}>\r\n",
            self.user,
            self.addr()
        );
        for line in request.lines() {
            let name = line.split(':').next().unwrap_or("").trim();
            if ["Via", "From", "Call-ID", "CSeq"]
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name))
            {
                msg.push_str(line);
                msg.push_str("\r\n");
            } else if name.eq_ignore_ascii_case("To") {
                msg.push_str(&format!("{line};tag={}-tag\r\n", self.user));
            }
        }
        msg.push_str("Content-Length: 0\r\n\r\n");
        msg
    }

    fn register(&self, server: SocketAddr, expires: u32) -> String {
        let contact = format!("<sip:{}@{}>", self.user, self.addr());
        self.register_contact(server, expires, &contact)
    }

    /// REGISTER (over UDP) a contact of its choosing.
    fn register_contact(&self, server: SocketAddr, expires: u32, contact: &str) -> String {
        let msg = self
            .request(
                "REGISTER",
                &format!("sip:{server}"),
                &format!("reg-{}-{expires}", self.user),
                1,
                "",
                &[&format!("Expires: {expires}")],
            )
            .replace(
                &format!("Contact: <sip:{}@{}>", self.user, self.addr()),
                &format!("Contact: {contact}"),
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

    // Bob does as a UAS does: 200 to the CANCEL, then 487 to the INVITE.
    // The 200 is the proxy's own hop (it answered Alice already); the 487
    // is Alice's, and is what ends her INVITE.
    bob.respond(&cancelled, 200, "OK", server.addr);
    bob.respond(&forwarded, 487, "Request Terminated", server.addr);
    let ended = alice
        .recv_until(Duration::from_secs(3), |m| {
            m.starts_with("SIP/2.0")
                && header(m, "Call-ID") == Some("cancel-1")
                && !m.starts_with("SIP/2.0 100")
        })
        .expect("the 487 reaches Alice");
    assert!(ended.starts_with("SIP/2.0 487"), "{ended}");
    assert_eq!(header(&ended, "CSeq"), Some("1 INVITE"));
    assert_eq!(
        header(&ended, "Via").map(|v| v.contains("z9hG4bKalice1")),
        Some(true),
        "{ended}"
    );

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

/// One end of a TCP connection, reading SIP messages off it.
struct Stream {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Stream {
    fn new(stream: TcpStream) -> Self {
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        Self {
            stream,
            buf: Vec::new(),
        }
    }

    fn send(&mut self, msg: &str) {
        self.stream.write_all(msg.as_bytes()).unwrap();
    }

    /// The next message on the connection within `within`.
    fn recv(&mut self, within: Duration) -> Option<String> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&self.buf[..end + 4]).into_owned();
                let body: usize = header(&head, "Content-Length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                if self.buf.len() >= end + 4 + body {
                    let msg: Vec<u8> = self.buf.drain(..end + 4 + body).collect();
                    return Some(String::from_utf8_lossy(&msg).into_owned());
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            let mut chunk = [0u8; 65536];
            match self.stream.read(&mut chunk) {
                Ok(0) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(_) => {}
            }
        }
    }
}

#[test]
fn the_proxy_reads_what_comes_back_on_its_tcp_leg() {
    let server = siphond("proxy", &[]);
    let (alice, bob) = (Phone::new("alice"), Phone::new("bob"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let contact = format!("<sip:bob@{};transport=tcp>", listener.local_addr().unwrap());
    assert!(bob
        .register_contact(server.addr, 3600, &contact)
        .starts_with("SIP/2.0 200"));

    // Bob registered over TCP: the INVITE comes to him on a connection the
    // proxy reads (it used to be an ad hoc one whose replies were lost).
    let uri = "sip:bob@127.0.0.1";
    let invite = alice.request("INVITE", uri, "tcp-1", 1, "z9hG4bKalicetcp", &[]);
    alice.send(&invite, server.addr);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut leg = loop {
        if let Ok((stream, _)) = listener.accept() {
            stream.set_nonblocking(false).unwrap();
            break Stream::new(stream);
        }
        assert!(Instant::now() < deadline, "the proxy connects to Bob");
        std::thread::sleep(Duration::from_millis(10));
    };
    let forwarded = leg
        .recv(Duration::from_secs(3))
        .expect("the INVITE reaches Bob over TCP");
    assert!(forwarded.starts_with("INVITE "), "{forwarded}");

    // Bob rings on that connection: Alice hears it.
    leg.send(&bob.response(&forwarded, 180, "Ringing"));
    let ringing = alice
        .recv_until(Duration::from_secs(3), |m| m.starts_with("SIP/2.0 180"))
        .expect("the 180 reaches Alice");
    assert_eq!(header(&ringing, "Call-ID"), Some("tcp-1"));

    // Alice gives up: the CANCEL comes down the same connection, and Bob's
    // 487 on it ends her INVITE.
    let cancel = alice.request("CANCEL", uri, "tcp-1", 1, "z9hG4bKalicetcp", &[]);
    alice.send(&cancel, server.addr);
    let cancelled = leg
        .recv(Duration::from_secs(3))
        .expect("the CANCEL reaches Bob on the INVITE's connection");
    assert!(cancelled.starts_with("CANCEL "), "{cancelled}");
    leg.send(&bob.response(&cancelled, 200, "OK"));
    leg.send(&bob.response(&forwarded, 487, "Request Terminated"));
    let ended = alice
        .recv_until(Duration::from_secs(3), |m| {
            m.starts_with("SIP/2.0 487") && header(m, "Call-ID") == Some("tcp-1")
        })
        .expect("the 487 reaches Alice");
    assert_eq!(header(&ended, "CSeq"), Some("1 INVITE"));
}

#[test]
fn the_b2bua_reaches_a_callee_over_the_transport_it_registered_with() {
    let server = siphond("b2bua", &[]);
    let (alice, bob) = (Phone::new("alice"), Phone::new("bob"));
    assert!(bob.register(server.addr, 3600).starts_with("SIP/2.0 200"));

    // Bob registered over UDP: the B2BUA's INVITE to him comes over UDP
    // (it used to open a TCP connection to him, and never read it).
    let uri = "sip:bob@127.0.0.1";
    let invite = alice.request("INVITE", uri, "b2b-1", 1, "", &[]);
    alice.send(&invite, server.addr);
    let reached = bob
        .recv_until(Duration::from_secs(3), |m| m.starts_with("INVITE "))
        .expect("the INVITE reaches Bob over UDP");
    assert!(
        header(&reached, "Via").is_some_and(|v| v.contains("SIP/2.0/UDP")),
        "{reached}"
    );

    // Bob answers, Alice ACKs: the ACK reaches Bob over UDP too, from
    // siphond's socket (it used to go over TCP and never arrive, and Bob
    // retransmitted his 200 until he gave up on the call).
    bob.respond(&reached, 200, "OK", server.addr);
    answered(&alice, "b2b-1", "INVITE");
    alice.send(&alice.request("ACK", uri, "b2b-1", 1, "", &[]), server.addr);
    let (ack, from) = bob
        .recv_from_until(Duration::from_secs(3), |m| m.starts_with("ACK "))
        .expect("the ACK reaches Bob over UDP");
    assert_eq!(from, server.addr);
    assert!(
        header(&ack, "Via").is_some_and(|v| v.contains("SIP/2.0/UDP")),
        "{ack}"
    );

    // Alice re-INVITEs (hold, say): bridged to Bob over UDP.
    let reinvite = alice
        .request("INVITE", uri, "b2b-1", 3, "", &[])
        .replace(&format!("To: <{uri}>"), &format!("To: <{uri}>;tag=bob-tag"));
    alice.send(&reinvite, server.addr);
    answered(&alice, "b2b-1", "INVITE");
    let (bridged, from) = bob
        .recv_from_until(Duration::from_secs(3), |m| m.starts_with("INVITE "))
        .expect("the re-INVITE reaches Bob over UDP");
    assert_eq!(from, server.addr);
    assert!(
        header(&bridged, "To").is_some_and(|t| t.contains("tag=")),
        "{bridged}"
    );

    // Alice hangs up: her BYE is answered and bridged to Bob over UDP.
    alice.send(&alice.request("BYE", uri, "b2b-1", 2, "", &[]), server.addr);
    answered(&alice, "b2b-1", "BYE");
    let (bye, from) = bob
        .recv_from_until(Duration::from_secs(3), |m| m.starts_with("BYE "))
        .expect("the BYE reaches Bob over UDP");
    assert_eq!(from, server.addr);
    assert!(
        header(&bye, "Via").is_some_and(|v| v.contains("SIP/2.0/UDP")),
        "{bye}"
    );
    bob.respond(&bye, 200, "OK", server.addr);

    // A second call, and Bob hangs up: the BYE reaches Alice from siphond's
    // own socket (it used to come from a throwaway one).
    alice.send(
        &alice.request("INVITE", uri, "b2b-2", 1, "", &[]),
        server.addr,
    );
    let reached = bob
        .recv_until(Duration::from_secs(3), |m| {
            m.starts_with("INVITE ") && !m.contains("b2b-1")
        })
        .expect("the second INVITE reaches Bob");
    bob.respond(&reached, 200, "OK", server.addr);
    answered(&alice, "b2b-2", "INVITE");
    alice.send(&alice.request("ACK", uri, "b2b-2", 1, "", &[]), server.addr);
    let outgoing_call_id = header(&reached, "Call-ID").unwrap();
    bob.send(
        &bob.request(
            "BYE",
            &format!("sip:siphond@{}", server.addr),
            outgoing_call_id,
            2,
            "z9hG4bKbobbye",
            &[],
        ),
        server.addr,
    );
    answered(&bob, outgoing_call_id, "BYE");
    let (bye, from) = alice
        .recv_from_until(Duration::from_secs(3), |m| m.starts_with("BYE "))
        .expect("the BYE reaches Alice over UDP");
    assert_eq!(from, server.addr);
    assert_eq!(header(&bye, "Call-ID"), Some("b2b-2"));
    assert!(
        header(&bye, "Via").is_some_and(|v| v.contains("SIP/2.0/UDP")),
        "{bye}"
    );
}

/// Waits for the 200 to `method` on `call_id`.
fn answered(phone: &Phone, call_id: &str, method: &str) {
    let answer = phone
        .recv_until(Duration::from_secs(3), |m| {
            m.starts_with("SIP/2.0")
                && !m.starts_with("SIP/2.0 1")
                && header(m, "Call-ID") == Some(call_id)
                && header(m, "CSeq").is_some_and(|c| c.ends_with(method))
        })
        .unwrap_or_else(|| panic!("the {method} on {call_id} is answered"));
    assert!(answer.starts_with("SIP/2.0 200"), "{answer}");
}
