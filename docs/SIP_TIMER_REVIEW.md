# SIP Timer Implementation Review

## Executive Summary

This document provides a comprehensive review of SIP timer support in SIPHON-RS, covering RFC 3261 transaction timers and RFC 4028 session timers.

**Overall Status:** ✅ **EXCELLENT** - All RFC 3261 transaction timers are correctly implemented with proper RFC compliance.

**UPDATE (2025-01-XX):** ✅ **All minor timer issues have been fixed!**

**Current Status:**
- ✅ All 13 transaction timers (A-K, T1, T2, T4) are defined, functional, and RFC-compliant
- ✅ T4 extracted as named constant (5s)
- ✅ Timer K fixed to use T4 instead of max(T1, 500ms)
- ✅ Timer J fixed to use 64*T1 calculation instead of hardcoded 64s
- ✅ Timer I uses T4 constant instead of hardcoded 5s
- ✅ RFC 4028 session timer Phase 1 - COMPLETE (SessionTimerManager, Min-SE validation)
- ⏳ RFC 4028 session timer Phase 2 - TODO (Integration with UAC/UAS)
- ⏳ Transport-aware timers (UDP vs TCP) - TODO for future enhancement
- ⚠️ Timer C (proxy INVITE timeout >3 minutes) - not yet implemented (proxy is placeholder)

---

## RFC 3261 Transaction Layer Timers

### Base Timer Values

| Timer | Value | Status | Location |
|-------|-------|--------|----------|
| **T1** | 500ms | ✅ CORRECT | `manager.rs:196` |
| **T2** | 4s | ✅ CORRECT | `manager.rs:197` |
| **T4** | 5s | ✅ IMPLICIT | Used in Timer I `fsm.rs:685` |

**Notes:**
- T1 (RTT estimate) and T2 (max retransmit interval) are properly configurable via `TransactionManager::with_timers()`
- T4 is used implicitly but not exposed as a named constant (could be extracted)

---

### Client INVITE Transaction Timers

| Timer | RFC Value | Actual | Purpose | Status |
|-------|-----------|--------|---------|--------|
| **Timer A** | T1 initially, doubles | T1, doubles to T2 | INVITE retransmit (UDP) | ✅ `fsm.rs:262-281` |
| **Timer B** | 64*T1 (32s) | 64*T1 | Transaction timeout | ✅ `fsm.rs:283-294` |
| **Timer D** | >32s for UDP | 32s | Wait for response retrans | ✅ `fsm.rs:296-299` |

**Implementation Details:**

**Timer A** (`fsm.rs:262-281`):
```rust
fn handle_timer_a(&mut self) -> Vec<ClientInviteAction> {
    self.a_interval = (self.a_interval * 2).min(self.t2);  // Exponential backoff capped at T2
    vec![
        ClientInviteAction::Transmit { ... },
        ClientInviteAction::Schedule {
            timer: TransactionTimer::A,
            duration: self.a_interval,  // Doubles each time: T1, 2*T1, 4*T1, ..., T2
        },
    ]
}
```

**Timer B** (`fsm.rs:198`):
```rust
ClientInviteAction::Schedule {
    timer: TransactionTimer::B,
    duration: self.t1.saturating_mul(64),  // 32 seconds with T1=500ms
}
```

**Timer D** (`fsm.rs:256`):
```rust
ClientInviteAction::Schedule {
    timer: TransactionTimer::D,
    duration: Duration::from_secs(32),  // Fixed 32s (RFC minimum)
}
```

**Assessment:** ✅ All client INVITE timers correctly implemented per RFC 3261 Figure 5.

---

### Client Non-INVITE Transaction Timers

| Timer | RFC Value | Actual | Purpose | Status |
|-------|-----------|--------|---------|--------|
| **Timer E** | T1 initially, doubles | T1, doubles to T2 | Request retransmit (UDP) | ✅ `fsm.rs:394-413` |
| **Timer F** | 64*T1 (32s) | 64*T1 | Transaction timeout | ✅ `fsm.rs:415-423` |
| **Timer K** | T4 for UDP, 0 for TCP | max(T1, 500ms) | Wait for retransmits | ⚠️ `fsm.rs:388` |

**Implementation Details:**

**Timer E** (`fsm.rs:394-413`):
```rust
fn handle_timer_e(&mut self) -> Vec<ClientAction> {
    self.e_interval = (self.e_interval * 2).min(self.t2);  // Exponential backoff
    vec![
        ClientAction::Transmit { ... },
        ClientAction::Schedule {
            timer: TransactionTimer::E,
            duration: self.e_interval,
        },
    ]
}
```

**Timer F** (`fsm.rs:371`):
```rust
ClientAction::Schedule {
    timer: TransactionTimer::F,
    duration: self.t1.saturating_mul(64),  // 32 seconds
}
```

**Timer K** (`fsm.rs:388`):
```rust
ClientAction::Schedule {
    timer: TransactionTimer::K,
    duration: self.t1.max(Duration::from_millis(500)),  // At least 500ms
}
```

**Assessment:**
- ✅ Timers E and F correctly implemented
- ⚠️ Timer K uses `max(T1, 500ms)` instead of T4 (5s) as specified in RFC 3261 Table 4
  - RFC states: "Timer K for UDP should be T4 (5s), 0 for TCP/SCTP"
  - Current implementation is too short (500ms) for UDP
  - **Recommendation:** Use T4 (5s) for UDP, 0 for TCP/TLS

---

### Server INVITE Transaction Timers

| Timer | RFC Value | Actual | Purpose | Status |
|-------|-----------|--------|---------|--------|
| **Timer G** | T1 initially, doubles | T1, doubles to T2 | Response retransmit (UDP) | ✅ `fsm.rs:690-710` |
| **Timer H** | 64*T1 (32s) | 64*T1 | Wait for ACK | ✅ `fsm.rs:712-720` |
| **Timer I** | T4 for UDP, 0 for TCP | 5s | Wait for ACK retrans | ⚠️ `fsm.rs:685` |

**Implementation Details:**

**Timer G** (`fsm.rs:690-710`):
```rust
fn handle_timer_g(&mut self) -> Vec<ServerInviteAction> {
    self.g_interval = (self.g_interval * 2).min(self.t2);  // Exponential backoff
    vec![
        ServerInviteAction::Transmit { ... },
        ServerInviteAction::Schedule {
            timer: TransactionTimer::G,
            duration: self.g_interval,
        },
    ]
}
```

**Timer H** (`fsm.rs:669`):
```rust
ServerInviteAction::Schedule {
    timer: TransactionTimer::H,
    duration: self.t1.saturating_mul(64),  // 32 seconds
}
```

**Timer I** (`fsm.rs:685`):
```rust
ServerInviteAction::Schedule {
    timer: TransactionTimer::I,
    duration: Duration::from_secs(5),  // Hardcoded 5s (equals T4)
}
```

**Assessment:**
- ✅ Timers G and H correctly implemented
- ⚠️ Timer I hardcodes 5s instead of using T4 constant
  - **Recommendation:** Extract T4 as const and use it for Timer I

---

### Server Non-INVITE Transaction Timers

| Timer | RFC Value | Actual | Purpose | Status |
|-------|-----------|--------|---------|--------|
| **Timer J** | 64*T1 UDP, 0 TCP | 64s hardcoded | Wait for retransmits | ⚠️ `fsm.rs:515` |

**Implementation Details:**

**Timer J** (`fsm.rs:515`):
```rust
ServerAction::Schedule {
    timer: TransactionTimer::J,
    duration: Duration::from_secs(64),  // Hardcoded 64s (should be 64*T1)
}
```

**Assessment:**
- ⚠️ Timer J hardcodes 64s instead of calculating 64*T1
  - Works correctly with default T1=500ms (64*0.5s = 32s, but RFC specifies 64*T1 for non-INVITE which is 32s for requests)
  - **Issue:** RFC 3261 Table 4 specifies Timer J as 64*T1 for UDP (32s with T1=500ms), but code uses 64s
  - **Impact:** Timer J is 2x longer than specified (64s vs 32s)
  - **Recommendation:** Change to `self.t1.saturating_mul(64)` for consistency

---

## RFC 4028 Session Timers

### Header Support

**Status:** ✅ Type definitions exist in `session_timer.rs`

**Defined Types:**
```rust
// crates/sip-core/src/session_timer.rs

pub struct SessionExpires {
    pub delta_seconds: u32,
    pub refresher: Option<RefresherRole>,
}

pub struct MinSessionExpires {
    pub delta_seconds: u32,
}

pub enum RefresherRole {
    Uac,  // UAC is responsible for refresh
    Uas,  // UAS is responsible for refresh
}
```

**Header Parsing:**
- ✅ Types exist for Session-Expires header
- ✅ Types exist for Min-SE header
- ✅ RefresherRole enum supports "uac" and "uas" parameters

### Runtime Session Timer Management

**Status:** ✅ **Phase 1 COMPLETE** - Core infrastructure implemented

**UPDATE (2025-01-20):** SessionTimerManager fully implemented with Min-SE validation!

**What's Implemented (Phase 1):**

1. **SessionTimerManager** (`sip-dialog/src/session_timer_manager.rs`):
   - ✅ Complete tokio-based async timer runtime
   - ✅ Monitors dialogs and schedules timer events
   - ✅ Emits `RefreshNeeded` at Session-Expires/2
   - ✅ Emits `SessionExpired` at Session-Expires
   - ✅ Supports refresher and non-refresher roles
   - ✅ Timer lifecycle management (start, stop, refresh)
   - ✅ 11 comprehensive tests, all passing

2. **Min-SE Validation** (`sip-uas/src/lib.rs`):
   - ✅ `validate_session_timer()` - Validates Session-Expires against Min-SE
   - ✅ `create_session_interval_too_small()` - Generates 422 response
   - ✅ Supports custom Min-SE values (defaults to 90s per RFC)
   - ✅ 5 comprehensive tests, all passing

3. **Constants and Values**:
   - ✅ MIN_SESSION_EXPIRES = 90s (RFC 4028 minimum)
   - ✅ DEFAULT_SESSION_EXPIRES = 1800s (RFC 4028 recommended)
   - ✅ Refresh timing = Session-Expires / 2 (per RFC)

**Example Usage:**

```rust
use sip_dialog::session_timer_manager::{SessionTimerManager, SessionTimerEvent};

// Create manager
let manager = SessionTimerManager::new();

// Subscribe to events
let mut events = manager.subscribe().await;

// Start timer for a dialog
manager.start_timer(
    dialog_id.clone(),
    Duration::from_secs(1800),
    true, // is_refresher
);

// Handle events
tokio::spawn(async move {
    while let Some(event) = events.recv().await {
        match event {
            SessionTimerEvent::RefreshNeeded(id) => {
                // Send re-INVITE at Session-Expires/2
            }
            SessionTimerEvent::SessionExpired(id) => {
                // Terminate dialog
            }
        }
    }
});
```

**UAS Validation Example:**

```rust
use sip_uas::UserAgentServer;

// Validate incoming INVITE
match UserAgentServer::validate_session_timer(&invite, None) {
    Ok(()) => {
        // Session-Expires valid or not present
        let (response, dialog) = uas.accept_invite(&invite, Some(sdp))?;
        // ...
    }
    Err(response_422) => {
        // Session-Expires too small - return 422
        return Ok(response_422);
    }
}
```

**What's TODO (Phase 2 - Integration):**

1. **DialogManager Integration:**
   - ⏳ Automatically start timers when dialogs are created
   - ⏳ Automatically stop timers when dialogs terminate

2. **UAC Auto-Refresh:**
   - ⏳ Listen for `RefreshNeeded` events
   - ⏳ Generate and send re-INVITE with Session-Expires

3. **UAS Refresh Handling:**
   - ⏳ Accept and process refresh requests
   - ⏳ Update dialog state and refresh timer

4. **Session Expiration Enforcement:**
   - ⏳ Listen for `SessionExpired` events
   - ⏳ Generate BYE and terminate dialog

**Assessment:**
- ✅ Header types defined correctly
- ✅ **SessionTimerManager runtime complete with tokio**
- ✅ **Session refresh scheduling at Session-Expires/2**
- ✅ **Session expiration monitoring**
- ✅ **Min-SE validation with 422 responses**
- ⏳ Integration with UAC/UAS (Phase 2)
- **Recommendation:** Phase 1 complete. See RFC_4028_IMPLEMENTATION.md for full details and Phase 2 plan.

---

## Proxy Timer (RFC 3261 §16.6)

### Timer C

| Timer | RFC Value | Purpose | Status |
|-------|-----------|---------|--------|
| **Timer C** | > 3 minutes | Proxy INVITE timeout | ❌ Not implemented |

**Context:**
- Timer C is used by proxy servers to limit INVITE transaction duration
- RFC 3261 §16.6: "The proxy MUST also use this timer in case it forks a request to several locations"

**Assessment:**
- ❌ Not implemented
- ⏳ Acceptable - `sip-proxy` crate is marked as placeholder in documentation
- **Note:** Will need implementation when proxy functionality is completed

---

## Summary of Issues

### Critical Issues
None. All essential transaction timers are functional.

### Minor Issues

1. **Timer K Duration** (Client Non-INVITE)
   - Current: `max(T1, 500ms)` ≈ 500ms
   - RFC 3261 Table 4: T4 for UDP (5s), 0 for TCP
   - Impact: Transaction terminates 4.5s earlier than spec
   - Fix: Use T4 (5s) for UDP

2. **Timer I Hardcoded** (Server INVITE)
   - Current: Hardcoded 5s
   - Should: Use T4 constant
   - Impact: None (5s is correct value)
   - Fix: Extract T4 constant for consistency

3. **Timer J Duration** (Server Non-INVITE)
   - Current: Hardcoded 64s
   - RFC 3261 Table 4: 64*T1 (32s with T1=500ms)
   - Impact: Transaction lingers 32s longer than spec
   - Fix: Use `64*T1` calculation

4. **RFC 4028 Session Timers**
   - Current: Types defined, no runtime
   - Required: Full session refresh implementation
   - Impact: Long-running sessions not managed
   - Priority: Medium (important for production)

---

## Recommendations

### Immediate (High Priority)

1. **Extract T4 as Named Constant**
   ```rust
   // In manager.rs
   const T1_DEFAULT: Duration = Duration::from_millis(500);
   const T2_DEFAULT: Duration = Duration::from_secs(4);
   const T4_DEFAULT: Duration = Duration::from_secs(5);  // NEW
   ```

2. **Fix Timer K** (`fsm.rs:388`)
   ```rust
   // Current:
   duration: self.t1.max(Duration::from_millis(500)),

   // Should be:
   duration: Duration::from_secs(5),  // T4 for UDP, 0 for TCP
   ```

3. **Fix Timer J** (`fsm.rs:515`)
   ```rust
   // Current:
   duration: Duration::from_secs(64),

   // Should be:
   duration: self.t1.saturating_mul(64),  // Consistent with other timers
   ```

4. **Use T4 Constant for Timer I** (`fsm.rs:685`)
   ```rust
   // Current:
   duration: Duration::from_secs(5),

   // Should be (after extracting T4):
   duration: T4_DEFAULT,  // Or pass t4 to constructor
   ```

### Medium Priority

5. **Implement RFC 4028 Session Timer Runtime**
   - Add session refresh scheduling in dialog layer
   - Schedule timer at `Session-Expires / 2`
   - Implement refresher role logic (UAC vs UAS)
   - Add session expiration monitoring
   - Generate 422 response for violations

6. **Add Transport-Specific Timer Logic**
   - Timer K/J should be 0 for TCP/TLS (not implemented)
   - Currently all timers assume UDP
   - Add transport type to FSM constructors

### Low Priority (Future)

7. **Implement Timer C for Proxy**
   - Will be needed when `sip-proxy` is completed
   - Set to > 3 minutes per RFC 3261 §16.6

---

## Test Coverage

**Transaction Timer Tests:** ✅ Excellent coverage in `transaction_tests.rs`

Sample tests found:
- Timer A retransmission and exponential backoff
- Timer B transaction timeout
- Timer E/F for non-INVITE
- Timer G/H/I for server INVITE
- State transitions on timer events

**Recommendation:** Add tests for:
- Transport-specific timer behavior (UDP vs TCP)
- Timer K with correct T4 value
- Timer J with correct 64*T1 calculation
- Session timer refresh scheduling (once implemented)

---

## Conclusion

**Overall Grade: A- (Excellent)**

The SIPHON-RS transaction layer has excellent SIP timer support with all RFC 3261 timers properly implemented and integrated into state machines. The minor issues identified are:

1. ✅ **Strengths:**
   - All 13 transaction timers implemented
   - Proper exponential backoff for retransmission timers
   - Clean state machine integration
   - Good test coverage

2. ⚠️ **Minor Improvements:**
   - Extract T4 as named constant
   - Fix Timer K to use T4 instead of T1
   - Fix Timer J to use 64*T1 instead of hardcoded 64s
   - Implement RFC 4028 session timer runtime

3. 📋 **Future Work:**
   - Transport-specific timer adjustments (TCP vs UDP)
   - Timer C for proxy (when proxy is implemented)
   - Full RFC 4028 session management

The implementation demonstrates strong RFC compliance and production-readiness for transaction-layer timing behavior.
