use frankenengine_node::connector::trust_object_id::{
    DomainPrefix, TrustObjectId, TrustObjectInput, derive_trust_object_id_events,
};

#[test]
fn derives_events_from_caller_supplied_trust_objects() {
    let content_input =
        TrustObjectInput::content_addressed(DomainPrefix::Extension, b"extension-manifest-v1");
    let context_input =
        TrustObjectInput::context_addressed(DomainPrefix::Receipt, 42, 7, b"receipt-payload-v1");

    let events = derive_trust_object_id_events(&[content_input.clone(), context_input.clone()]);

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].domain, "extension");
    assert_eq!(events[0].derivation_mode, "content_addressed");
    assert_eq!(
        events[0].short_id,
        TrustObjectId::derive_content_addressed(
            content_input.domain,
            content_input.data.as_slice()
        )
        .short_form()
    );
    assert_eq!(events[1].domain, "receipt");
    assert_eq!(events[1].derivation_mode, "context_addressed");
    let context = context_input.context.expect("context");
    assert_eq!(
        events[1].short_id,
        TrustObjectId::derive_context_addressed(
            context_input.domain,
            context.epoch,
            context.sequence,
            context_input.data.as_slice(),
        )
        .short_form()
    );
    assert!(
        events
            .iter()
            .all(|event| event.detail.contains("caller-supplied"))
    );
}

#[test]
fn event_derivation_has_no_sample_payload_dependency() {
    let one = TrustObjectInput::content_addressed(DomainPrefix::VerifierClaim, b"claim-one");
    let two = TrustObjectInput::content_addressed(DomainPrefix::VerifierClaim, b"claim-two");

    let one_event = derive_trust_object_id_events(&[one]);
    let two_event = derive_trust_object_id_events(&[two]);

    assert_ne!(one_event[0].short_id, two_event[0].short_id);
    assert!(!one_event[0].detail.contains("sample"));
    assert!(!two_event[0].detail.contains("sample"));
}
