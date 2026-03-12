//! STUN transaction state machine (Sans-IO)
//!
//! Manages retransmission timing per RFC 5389 Section 7.2.1:
//! - Initial RTO: 500ms
//! - Doubles after each retransmit
//! - Max 7 retransmissions (total ~39.5s)
//!
//! This is Sans-IO: the caller drives the state machine by polling
//! for retransmits and feeding in responses. No sockets or async.

use std::time::{Duration, Instant};

use super::message::{StunMessage, TransactionId};

/// Maximum number of retransmissions before timeout
const MAX_RETRANSMITS: u8 = 7;

/// Initial retransmission timeout
const INITIAL_RTO: Duration = Duration::from_millis(500);

/// Result of polling the transaction
#[derive(Debug)]
pub enum PollResult<'a> {
    /// Retransmit these bytes now (borrows from transaction)
    Retransmit(&'a [u8]),
    /// No action needed; wait until next_deadline()
    Wait,
    /// Transaction timed out after all retransmissions
    TimedOut,
    /// Transaction completed successfully
    Complete,
}

/// Transaction state
#[derive(Debug, Clone, PartialEq, Eq)]
enum TxnState {
    /// Waiting for response
    Waiting,
    /// Received a valid response
    Completed,
    /// Timed out
    TimedOut,
}

/// Sans-IO STUN transaction with retransmit logic
pub struct StunTransaction {
    /// Transaction ID for matching responses
    id: TransactionId,
    /// Serialized request bytes (cached for retransmit)
    request_bytes: Vec<u8>,
    /// Current state
    state: TxnState,
    /// When the transaction was created
    created_at: Instant,
    /// When the next retransmit should happen
    retransmit_at: Instant,
    /// Number of retransmissions so far
    retransmit_count: u8,
    /// Current RTO (doubles each retransmit)
    rto: Duration,
    /// The response message (if completed)
    response: Option<StunMessage>,
}

impl StunTransaction {
    /// Create a new transaction from a request message.
    /// The request is serialized immediately and cached.
    pub fn new(request: &StunMessage, now: Instant) -> Self {
        let request_bytes = request.marshal();
        Self {
            id: request.transaction_id,
            request_bytes,
            state: TxnState::Waiting,
            created_at: now,
            retransmit_at: now + INITIAL_RTO,
            retransmit_count: 0,
            rto: INITIAL_RTO,
            response: None,
        }
    }

    /// Get the transaction ID
    pub fn id(&self) -> &TransactionId {
        &self.id
    }

    /// Get the initial request bytes (for the first send)
    pub fn request_bytes(&self) -> &[u8] {
        &self.request_bytes
    }

    /// Feed a response into this transaction.
    /// Returns true if the response matched and was consumed.
    pub fn receive_response(&mut self, msg: StunMessage) -> bool {
        if self.state != TxnState::Waiting {
            return false;
        }
        if msg.transaction_id != self.id {
            return false;
        }
        self.state = TxnState::Completed;
        self.response = Some(msg);
        true
    }

    /// Poll for retransmit at the given time.
    /// Call this when `now >= next_deadline()`.
    pub fn poll(&mut self, now: Instant) -> PollResult<'_> {
        match self.state {
            TxnState::Completed => PollResult::Complete,
            TxnState::TimedOut => PollResult::TimedOut,
            TxnState::Waiting => {
                if now < self.retransmit_at {
                    return PollResult::Wait;
                }

                if self.retransmit_count >= MAX_RETRANSMITS {
                    self.state = TxnState::TimedOut;
                    return PollResult::TimedOut;
                }

                // Time to retransmit
                self.retransmit_count += 1;
                self.rto = self.rto * 2; // double RTO
                self.retransmit_at = now + self.rto;
                PollResult::Retransmit(&self.request_bytes)
            }
        }
    }

    /// Next deadline the caller should wake up for
    pub fn next_deadline(&self) -> Option<Instant> {
        match self.state {
            TxnState::Waiting => Some(self.retransmit_at),
            _ => None,
        }
    }

    /// Is this transaction complete (success or timeout)?
    pub fn is_done(&self) -> bool {
        self.state != TxnState::Waiting
    }

    /// Is this transaction completed successfully?
    pub fn is_complete(&self) -> bool {
        self.state == TxnState::Completed
    }

    /// Is this transaction timed out?
    pub fn is_timed_out(&self) -> bool {
        self.state == TxnState::TimedOut
    }

    /// Get the response message (if completed)
    pub fn response(&self) -> Option<&StunMessage> {
        self.response.as_ref()
    }

    /// How long this transaction has been alive
    pub fn elapsed(&self, now: Instant) -> Duration {
        now.duration_since(self.created_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::message::BINDING_SUCCESS;
    use super::super::attributes::StunAttribute;
    use std::net::SocketAddr;

    fn make_request() -> StunMessage {
        StunMessage::new_binding_request()
    }

    fn make_success_response(txn_id: TransactionId) -> StunMessage {
        let addr: SocketAddr = "203.0.113.50:32853".parse().unwrap();
        StunMessage {
            msg_type: BINDING_SUCCESS,
            transaction_id: txn_id,
            attributes: vec![StunAttribute::XorMappedAddress(addr)],
        }
    }

    #[test]
    fn test_initial_state() {
        let request = make_request();
        let now = Instant::now();
        let txn = StunTransaction::new(&request, now);

        assert!(!txn.is_done());
        assert!(!txn.is_complete());
        assert!(!txn.is_timed_out());
        assert!(txn.next_deadline().is_some());
        assert!(txn.response().is_none());
    }

    #[test]
    fn test_successful_response() {
        let request = make_request();
        let txn_id = request.transaction_id;
        let now = Instant::now();
        let mut txn = StunTransaction::new(&request, now);

        let response = make_success_response(txn_id);
        assert!(txn.receive_response(response));

        assert!(txn.is_done());
        assert!(txn.is_complete());
        assert!(!txn.is_timed_out());
        assert!(txn.response().is_some());
        assert_eq!(txn.next_deadline(), None);
    }

    #[test]
    fn test_wrong_transaction_id() {
        let request = make_request();
        let now = Instant::now();
        let mut txn = StunTransaction::new(&request, now);

        let wrong_response = make_success_response([0xFF; 12]);
        assert!(!txn.receive_response(wrong_response));
        assert!(!txn.is_done());
    }

    #[test]
    fn test_retransmit_schedule() {
        let request = make_request();
        let now = Instant::now();
        let mut txn = StunTransaction::new(&request, now);

        // Before deadline — should wait
        let result = txn.poll(now);
        assert!(matches!(result, PollResult::Wait));

        // At 500ms — first retransmit
        let t1 = now + Duration::from_millis(500);
        let result = txn.poll(t1);
        assert!(matches!(result, PollResult::Retransmit(_)));

        // At 1500ms (500 + 1000) — second retransmit
        let t2 = now + Duration::from_millis(1500);
        let result = txn.poll(t2);
        assert!(matches!(result, PollResult::Retransmit(_)));

        // At 3500ms (500 + 1000 + 2000) — third retransmit
        let t3 = now + Duration::from_millis(3500);
        let result = txn.poll(t3);
        assert!(matches!(result, PollResult::Retransmit(_)));
    }

    #[test]
    fn test_timeout_after_max_retransmits() {
        let request = make_request();
        let now = Instant::now();
        let mut txn = StunTransaction::new(&request, now);

        // Exhaust all retransmissions
        let mut t;
        for _ in 0..MAX_RETRANSMITS {
            t = txn.next_deadline().unwrap();
            txn.poll(t);
        }

        // Next poll should timeout
        t = txn.next_deadline().unwrap();
        let result = txn.poll(t);
        assert!(matches!(result, PollResult::TimedOut));
        assert!(txn.is_timed_out());
        assert!(txn.is_done());
    }

    #[test]
    fn test_response_after_retransmit() {
        let request = make_request();
        let txn_id = request.transaction_id;
        let now = Instant::now();
        let mut txn = StunTransaction::new(&request, now);

        // Trigger one retransmit
        let t1 = now + Duration::from_millis(500);
        txn.poll(t1);
        assert!(!txn.is_done());

        // Then receive response
        let response = make_success_response(txn_id);
        assert!(txn.receive_response(response));
        assert!(txn.is_complete());
    }

    #[test]
    fn test_poll_after_complete_returns_complete() {
        let request = make_request();
        let txn_id = request.transaction_id;
        let now = Instant::now();
        let mut txn = StunTransaction::new(&request, now);

        txn.receive_response(make_success_response(txn_id));
        let result = txn.poll(now + Duration::from_secs(100));
        assert!(matches!(result, PollResult::Complete));
    }

    #[test]
    fn test_no_double_response() {
        let request = make_request();
        let txn_id = request.transaction_id;
        let now = Instant::now();
        let mut txn = StunTransaction::new(&request, now);

        assert!(txn.receive_response(make_success_response(txn_id)));
        // Second response should be rejected
        assert!(!txn.receive_response(make_success_response(txn_id)));
    }
}
