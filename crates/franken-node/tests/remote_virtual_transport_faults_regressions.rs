use frankenengine_node::remote::virtual_transport_faults::{
    FaultClass, FaultConfig, FaultSchedule, ScheduledFault, VirtualTransportFaultHarness,
};

#[test]
fn process_message_applies_unsorted_manual_schedule() {
    let mut harness = VirtualTransportFaultHarness::new(1);
    let schedule = FaultSchedule {
        seed: 1,
        faults: vec![
            ScheduledFault {
                message_index: 2,
                fault: FaultClass::Drop,
            },
            ScheduledFault {
                message_index: 0,
                fault: FaultClass::Corrupt {
                    bit_positions: vec![0],
                },
            },
        ],
        total_messages: 3,
    };

    let result = harness.process_message(&schedule, 0, 1, &[0], "t-unsorted");

    assert_eq!(result, Some(vec![1]));
    assert_eq!(harness.fault_count(), 1);
    assert_eq!(harness.fault_log()[0].fault_class, "Corrupt");
}

#[test]
fn fault_config_rejects_cumulative_probability_above_one() {
    let invalid = FaultConfig {
        drop_probability: 0.6,
        reorder_probability: 0.3,
        reorder_max_depth: 1,
        corrupt_probability: 0.2,
        corrupt_bit_count: 1,
        max_faults: 10,
    };

    assert_eq!(
        invalid.validate(),
        Err("fault probabilities must sum to <= 1".to_string())
    );
}
