#[derive(Debug, PartialEq)]
pub enum StepStatus {
    Pass,
    Fail(String),
    Skip(String),
}

#[derive(Debug)]
pub struct StepResult {
    pub name: &'static str,
    pub status: StepStatus,
}

pub struct VerificationReport {
    pub steps: Vec<StepResult>,
    pub operator_key_id: Option<String>,
    pub infra_key_id: Option<String>,
}

impl VerificationReport {
    pub fn passed(&self) -> bool {
        self.steps
            .iter()
            .all(|s| matches!(s.status, StepStatus::Pass | StepStatus::Skip(_)))
            && self.steps.iter().any(|s| matches!(s.status, StepStatus::Pass))
    }

    pub fn error_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| matches!(s.status, StepStatus::Fail(_)))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_result_types_exist() {
        let r = StepResult {
            name: "test",
            status: StepStatus::Pass,
        };
        assert_eq!(r.status, StepStatus::Pass);

        let r2 = StepResult {
            name: "test",
            status: StepStatus::Fail("bad".into()),
        };
        assert!(matches!(r2.status, StepStatus::Fail(_)));

        let r3 = StepResult {
            name: "test",
            status: StepStatus::Skip("upstream failed".into()),
        };
        assert!(matches!(r3.status, StepStatus::Skip(_)));
    }

    #[test]
    fn report_passed_logic() {
        let report = VerificationReport {
            steps: vec![
                StepResult {
                    name: "a",
                    status: StepStatus::Pass,
                },
                StepResult {
                    name: "b",
                    status: StepStatus::Pass,
                },
            ],
            operator_key_id: None,
            infra_key_id: None,
        };
        assert!(report.passed());
        assert_eq!(report.error_count(), 0);
    }

    #[test]
    fn report_with_failure() {
        let report = VerificationReport {
            steps: vec![
                StepResult {
                    name: "a",
                    status: StepStatus::Pass,
                },
                StepResult {
                    name: "b",
                    status: StepStatus::Fail("mismatch".into()),
                },
                StepResult {
                    name: "c",
                    status: StepStatus::Skip("b failed".into()),
                },
            ],
            operator_key_id: None,
            infra_key_id: None,
        };
        assert!(!report.passed());
        assert_eq!(report.error_count(), 1);
    }

    #[test]
    fn report_all_skipped_is_not_passed() {
        let report = VerificationReport {
            steps: vec![StepResult {
                name: "a",
                status: StepStatus::Skip("no input".into()),
            }],
            operator_key_id: None,
            infra_key_id: None,
        };
        assert!(!report.passed());
    }
}
