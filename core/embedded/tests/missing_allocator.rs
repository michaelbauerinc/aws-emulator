// SPDX-License-Identifier: CC0-1.0

//! A Windows host without an allocation observer must refuse Python execution.
#![cfg(windows)]

mod common;

// This test executable deliberately uses the default allocator.
#[test]
fn python_refuses_to_run_without_the_host_allocation_observer() {
    let invoked = common::invoke_python();
    let payload = common::response_json(&invoked);
    assert_eq!(invoked.status().as_u16(), 200, "{payload}");
    assert_eq!(
        invoked
            .headers()
            .get("x-amz-function-error")
            .and_then(|value| value.to_str().ok()),
        Some("Unhandled"),
        "the missing observer must be reported as a runtime failure: {payload}"
    );
    assert_eq!(payload["errorType"], "Runtime.InternalError");
    assert_eq!(
        payload["errorMessage"],
        "Python Lambda execution is unavailable: the Windows allocation observer is not installed or could not verify its accounting"
    );
}
