use smol_str::SmolStr;

/// Represents the Event (and Allow-Events) header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventHeader {
    pub package: SmolStr,
    pub id: Option<SmolStr>,
    pub params: Vec<(SmolStr, Option<SmolStr>)>,
}

/// Represents Subscription-State header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionStateHeader {
    pub state: SubscriptionState,
    pub params: Vec<(SmolStr, Option<SmolStr>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionState {
    Active,
    Pending,
    Terminated,
    Unknown(SmolStr),
}

impl SubscriptionState {
    pub fn as_str(&self) -> &str {
        match self {
            SubscriptionState::Active => "active",
            SubscriptionState::Pending => "pending",
            SubscriptionState::Terminated => "terminated",
            SubscriptionState::Unknown(value) => value.as_str(),
        }
    }
}
