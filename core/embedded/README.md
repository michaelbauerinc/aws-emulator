# aws-emulator-embedded

The in-process facade over the multi-service emulator. A host links this crate
to drive the emulator inside its own test process without binding a socket or
running the standalone binary.

`AwsEmulatorEmbedded::new(options)` builds one emulator over a fresh in-memory
engine. Its `http_client()` is an `aws_smithy_runtime_api::client::http::HttpClient`:
hand it to an AWS SDK config's `.http_client(..)` in place of a network connector,
and SDK calls are served in-process with no socket or network I/O. Every client from
one emulator shares its state; two emulators never do.

## Options

`EmbeddedOptions::default()` is authentication off and usage telemetry on.

- `.authentication(Authentication::On)`: every request to this emulator must be
  signed with the credentials it vends, or ones its operations created; anything
  else gets 403. No credentials file is written.
- `.telemetry(Telemetry::Off)`: turns usage telemetry off for the whole process,
  whichever emulator says it. Telemetry is process-wide and never delays a test:
  one batch is sent when the process exits. `EMULATOR_TELEMETRY=off` or the config file turn it off as well,
  and off always wins.

`credentials()` lists what this emulator's authentication accepts, empty when it is
off; `aws_credentials_provider()` turns that into an AWS SDK credentials provider,
with placeholder keys when authentication is off.

`certificate_authority()` is the TLS certificate authority behind every listener the
emulator opens, such as one a signed URL it returns points at. Trust `pem()` (for
`AWS_CA_BUNDLE` or `curl --cacert`) or `der()` (for a rustls root store) to fetch
those URLs.

## Usage

This crate names no service and depends on no `aws-sdk-*` crate. The host adds
the specific `aws-sdk-<service>` and `aws-config` dev-dependencies it needs for
whichever service the project scaffolded. The example below is illustrative:
replace `aws_sdk_example` with the SDK crate for your service.

```rust
// dev-dependencies the HOST adds: aws-config, aws-sdk-<service>, tokio.
#[tokio::test]
async fn calls_are_served_by_the_in_process_emulator() {
    let emulator = AwsEmulatorEmbedded::new(
        EmbeddedOptions::default().authentication(Authentication::On),
    );

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .http_client(emulator.http_client())
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(emulator.aws_credentials_provider())
        .load()
        .await;

    let client = aws_sdk_example::Client::new(&config);

    // Served by the emulator, not the network.
    let _response = client.some_operation().send().await.expect("served");
}
```

## Tests

`tests/boot_serve.rs` checks assembly and invokes a Python function through the
public facade without binding a socket. On Windows, `tests/missing_allocator.rs`
checks that a host without the allocation observer refuses Python execution.
Broader service behavior is tested in the service crates.

## Native Windows hosts

Windows embedding hosts need the [Windows build prerequisites](../../WINDOWS.md).
Cargo applies dependency patches and build profiles only from the invoking
workspace root. External hosts must copy the RustPython overrides from
`[patch.crates-io]` and the `[profile.dev.package.rustpython-vm]` setting in the
emulator's [root manifest](../../Cargo.toml). The VM optimization also applies to
test builds and avoids the unoptimized dispatch's large native stack frames.

Each executable that invokes Python Lambda must wrap its global allocator:

```rust
#[cfg(windows)]
#[global_allocator]
static ALLOCATOR: aws_emulator_embedded::WindowsLambdaAllocator<std::alloc::System> =
    aws_emulator_embedded::WindowsLambdaAllocator::new(std::alloc::System);
```

An application with its own allocator wraps that allocator instead of `System`.
Libraries do not select an allocator for their host. Python refuses to start if
the observer is absent or its accounting is unavailable. The observer measures
owned Rust allocations cooperatively; it is not a hard resident-memory limit.
See [memory accounting](../../platform/windows-support/MEMORY_ACCOUNTING.md).
