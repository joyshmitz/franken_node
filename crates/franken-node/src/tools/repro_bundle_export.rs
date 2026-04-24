/// Reference to an evidence artifact captured in a repro bundle.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvidenceRef {
    /// Evidence entry ID.
    pub evidence_id: String,
    /// Decision kind label.
    pub decision_kind: String,
    /// Epoch at capture time.
    pub epoch_id: u64,
    /// Relative path within bundle.
    pub relative_path: String,
}

impl EvidenceRef {
    /// Validate portability: no absolute paths, no Windows separators, no NULs, no traversal.
    #[must_use]
    pub fn is_portable(&self) -> bool {
        !self.relative_path.starts_with('/')
            && !self.relative_path.contains(":\\")
            && !self.relative_path.contains('\\')
            && !self.relative_path.contains('\0')
            && !self.relative_path.split('/').any(|seg| seg == "..")
    }
}

#[cfg(test)]
mod tests {
    use super::EvidenceRef;

    fn evidence_ref(relative_path: &str) -> EvidenceRef {
        EvidenceRef {
            evidence_id: "evidence-1".to_string(),
            decision_kind: "admit".to_string(),
            epoch_id: 7,
            relative_path: relative_path.to_string(),
        }
    }

    #[test]
    fn evidence_ref_rejects_nul_byte_relative_path() {
        assert!(!evidence_ref("logs/evidence\0.json").is_portable());
    }

    #[test]
    fn evidence_ref_accepts_plain_relative_path() {
        assert!(evidence_ref("logs/evidence.json").is_portable());
    }
}
