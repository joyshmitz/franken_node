#[test]
fn test_u64_max_cast() {
    let secs = u64::MAX;
    let val = secs as i64;
    let res = chrono::DateTime::from_timestamp(val, 0);
    println!("u64::MAX as i64 is {}", val);
    println!(
        "from_timestamp is {:?}",
        res.map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    );
    assert!(res.is_some());
}

#[test]
fn test_i64_max() {
    let secs = i64::MAX;
    let res = chrono::DateTime::from_timestamp(secs, 0);
    println!("i64::MAX is {}", secs);
    println!(
        "from_timestamp is {:?}",
        res.map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    );
    assert!(res.is_none());
}
