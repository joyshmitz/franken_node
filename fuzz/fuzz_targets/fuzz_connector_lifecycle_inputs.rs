#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::connector::activation_pipeline::{
    ActivationInput, ActivationStage, DefaultExecutor, StageError, StageExecutor, activate,
};
use libfuzzer_sys::fuzz_target;

const MAX_STRING_CHARS: usize = 512;
const MAX_ITEMS: usize = 64;

#[derive(Debug, Arbitrary)]
struct ConnectorLifecycleCase {
    connector_id: String,
    sandbox_config: String,
    secret_refs: Vec<String>,
    capabilities: Vec<String>,
    trace_id: String,
    timestamp: String,
    executor: FuzzExecutorMode,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzExecutorMode {
    Default,
    SandboxFails,
    SecretMountFails,
    CapabilityFails,
    HealthFails,
    PartialSecretMount,
}

fuzz_target!(|case: ConnectorLifecycleCase| {
    fuzz_connector_lifecycle_inputs(case);
});

fn fuzz_connector_lifecycle_inputs(case: ConnectorLifecycleCase) {
    let input = ActivationInput {
        connector_id: bounded_string(case.connector_id),
        sandbox_config: bounded_string(case.sandbox_config),
        secret_refs: bounded_strings(case.secret_refs),
        capabilities: bounded_strings(case.capabilities),
        trace_id: bounded_string(case.trace_id),
        timestamp: bounded_string(case.timestamp),
    };

    let _ = serde_json::from_str::<serde_json::Value>(&input.sandbox_config);

    match case.executor {
        FuzzExecutorMode::Default => {
            let first = activate(&input, &DefaultExecutor);
            let second = activate(&input, &DefaultExecutor);
            assert_transcript_invariants(&first);
            assert_transcript_invariants(&second);
            assert_same_transcript_shape(&first, &second);
        }
        mode => {
            let executor = ScriptedExecutor { mode };
            let first = activate(&input, &executor);
            let second = activate(&input, &executor);
            assert_transcript_invariants(&first);
            assert_transcript_invariants(&second);
            assert_same_transcript_shape(&first, &second);
        }
    }
}

struct ScriptedExecutor {
    mode: FuzzExecutorMode,
}

impl StageExecutor for ScriptedExecutor {
    fn create_sandbox(&self, _config: &str) -> Result<(), String> {
        match self.mode {
            FuzzExecutorMode::SandboxFails => Err("sandbox failed by fuzz script".to_string()),
            _ => Ok(()),
        }
    }

    fn mount_secrets(&self, refs: &[String]) -> Result<Vec<String>, String> {
        match self.mode {
            FuzzExecutorMode::SecretMountFails => {
                Err("secret mount failed by fuzz script".to_string())
            }
            FuzzExecutorMode::PartialSecretMount => {
                let keep = refs.len().saturating_sub(1);
                Ok(refs.iter().take(keep).cloned().collect())
            }
            _ => Ok(refs.to_vec()),
        }
    }

    fn issue_capabilities(&self, _caps: &[String]) -> Result<(), String> {
        match self.mode {
            FuzzExecutorMode::CapabilityFails => {
                Err("capability issue failed by fuzz script".to_string())
            }
            _ => Ok(()),
        }
    }

    fn health_check(&self) -> Result<(), String> {
        match self.mode {
            FuzzExecutorMode::HealthFails => Err("health failed by fuzz script".to_string()),
            _ => Ok(()),
        }
    }
}

fn assert_transcript_invariants(transcript: &frankenengine_node::connector::activation_pipeline::ActivationTranscript) {
    assert!(transcript.stages.len() <= ActivationStage::sequence().len());
    for (index, stage) in transcript.stages.iter().enumerate() {
        assert_eq!(
            stage.stage,
            ActivationStage::sequence()[index],
            "activation stage order must remain a fixed prefix"
        );
        if let Some(error) = &stage.error {
            assert!(!error.code().is_empty());
        }
    }
    if transcript.completed {
        assert_eq!(transcript.stages.len(), ActivationStage::sequence().len());
        assert!(transcript.stages.iter().all(|stage| stage.success));
        assert!(transcript.stages.iter().all(|stage| stage.error.is_none()));
    } else if let Some(last) = transcript.stages.last() {
        assert!(
            last.success || last.error.is_some(),
            "failed lifecycle stage must carry a typed error"
        );
    }
}

fn assert_same_transcript_shape(
    left: &frankenengine_node::connector::activation_pipeline::ActivationTranscript,
    right: &frankenengine_node::connector::activation_pipeline::ActivationTranscript,
) {
    assert_eq!(left.connector_id, right.connector_id);
    assert_eq!(left.trace_id, right.trace_id);
    assert_eq!(left.completed, right.completed);
    assert_eq!(left.stages.len(), right.stages.len());
    for (left_stage, right_stage) in left.stages.iter().zip(&right.stages) {
        assert_eq!(left_stage.stage, right_stage.stage);
        assert_eq!(left_stage.success, right_stage.success);
        assert_eq!(error_code(left_stage.error.as_ref()), error_code(right_stage.error.as_ref()));
    }
}

fn error_code(error: Option<&StageError>) -> Option<&'static str> {
    error.map(StageError::code)
}

fn bounded_strings(values: Vec<String>) -> Vec<String> {
    values.into_iter().take(MAX_ITEMS).map(bounded_string).collect()
}

fn bounded_string(value: String) -> String {
    value.chars().take(MAX_STRING_CHARS).collect()
}
