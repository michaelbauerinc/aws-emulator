// SPDX-License-Identifier: CC0-1.0

//! The public in-process facade assembles and executes a deployed Python function.

mod common;

#[test]
fn the_in_process_facade_assembles_and_executes_python() {
    let invoked = common::invoke_python();
    let payload = common::response_json(&invoked);
    assert_eq!(invoked.status().as_u16(), 200, "{payload}");
    assert!(
        !invoked.headers().contains_key("x-amz-function-error"),
        "Python must run successfully in this embedding host: {payload}"
    );
    assert_eq!(payload, serde_json::json!({ "total": 10 }));
}

// This executable owns the allocator used by Windows Python invocations.
#[cfg(windows)]
#[global_allocator]
static WINDOWS_ALLOCATOR: aws_emulator_embedded::WindowsLambdaAllocator<std::alloc::System> =
    aws_emulator_embedded::WindowsLambdaAllocator::new(std::alloc::System);
