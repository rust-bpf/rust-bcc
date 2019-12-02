use std::hash::{Hash, Hasher};

#[derive(Debug)]
pub struct RawTracepoint {}

impl PartialEq for RawTracepoint {
    fn eq(&self, _: &RawTracepoint) -> bool {
        true
    }
}

impl Eq for RawTracepoint {}

impl Hash for RawTracepoint {
    fn hash<H: Hasher>(&self, _: &mut H) {}
}
