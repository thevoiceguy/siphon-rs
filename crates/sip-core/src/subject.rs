use smol_str::SmolStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectHeader {
    pub value: SmolStr,
}
