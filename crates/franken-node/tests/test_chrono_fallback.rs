#[test]
fn test_chrono_limits() {
    let secs = 10_000_000_000_000u64; // 10 trillion seconds
    let res = chrono::DateTime::from_timestamp(secs as i64, 0);
    println!(
        "from_timestamp(10T) is {:?}",
        res.map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    );
    assert!(res.is_none());
}
