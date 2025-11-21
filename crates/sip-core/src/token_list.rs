use smol_str::SmolStr;

/// Represents comma-separated token header values (Allow/Supported/etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenList(pub Vec<SmolStr>);

impl TokenList {
    pub fn tokens(&self) -> &[SmolStr] {
        &self.0
    }
}

pub type AllowHeader = TokenList;
pub type SupportedHeader = TokenList;
