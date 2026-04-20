use assert_cmd::Command;

#[test]
fn doctor_verbose_human_output_is_routed_through_frankentui_surface() {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assert = command
        .args([
            "doctor",
            "--verbose",
            "--trace-id",
            "trace-frankentui-operator-surface",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is utf8");
    assert!(stdout.contains("franken-node doctor:"));
    assert!(stdout.contains("trace_id=trace-frankentui-operator-surface"));
    assert!(stdout.contains("structured logs:"));

    let main_source = include_str!("../src/main.rs");
    assert!(
        main_source.contains("fn render_operator_surface_with_frankentui"),
        "doctor output must pass through the FrankenTUI surface helper"
    );
    assert!(
        main_source.contains("frankentui::Buffer::new"),
        "the operator surface helper must call the FrankenTUI buffer surface"
    );
    assert!(
        main_source.contains("emit_operator_surface_output(\n                    \"doctor\""),
        "doctor human output must emit via the FrankenTUI surface path"
    );
    assert!(
        !main_source
            .contains("println!(\"{}\", render_doctor_report_human(&report, args.verbose))"),
        "doctor human output must not bypass FrankenTUI with a direct println"
    );
}
