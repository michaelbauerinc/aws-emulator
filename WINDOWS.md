# Building on Windows

Native Windows support is experimental and targets x64
(`x86_64-pc-windows-msvc`). Use Rust 1.99.1 or later, Visual Studio 2022 C++ Build
Tools with a Windows SDK, CMake, NASM, and Git. Run Cargo from an x64 Developer
PowerShell so it can find the native compiler and linker. The workspace is large;
allow at least the build space described in the [source-build guide](README.md#building-from-source).

## Build

```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --locked --release --target x86_64-pc-windows-msvc -p aws-emulator-router --bin aws-emulator
```

The executable is `target/x86_64-pc-windows-msvc/release/aws-emulator.exe`, unless
`CARGO_TARGET_DIR` selects another directory. Use the checked-in lockfile. The
root [Cargo.toml](Cargo.toml) pins RustPython's VM, standard library, frozen Python
library, host helpers, and matching string types to the same upstream revision.
Windows uses an adapted
[CSV module](services/service-com-amazonaws-lambda-awsgirapiservice/src/state/execution/host_csv.rs)
with per-interpreter state and its upstream MIT notice.

## Run

```powershell
.\target\x86_64-pc-windows-msvc\release\aws-emulator.exe --bind 127.0.0.1 --port 9297 --auth on
```

Point the AWS CLI or SDK at the configuration, credentials, and CA published for
this port:

```powershell
$emulatorFiles = Join-Path $env:USERPROFILE ".aws\emulator\9297"
$env:AWS_CONFIG_FILE = Join-Path $emulatorFiles "config"
$env:AWS_SHARED_CREDENTIALS_FILE = Join-Path $emulatorFiles "emulator_credentials"
$env:AWS_CA_BUNDLE = Join-Path $emulatorFiles "ca.pem"
aws --endpoint-url https://127.0.0.1:9297 --region us-east-1 lambda list-functions
```

Each start creates new credentials and a new CA. Keep credential contents private.
`--idle-timeout 60` requests a graceful stop after 60 seconds without API calls.

## Tests and embedding

Run service tests with the same MSVC target and lockfile. The Windows helper and
embedding boundary have focused test targets:

```powershell
cargo test --locked --target x86_64-pc-windows-msvc -p aws-emulator-windows-support --features credentials,allocation --lib
cargo test --locked --target x86_64-pc-windows-msvc -p aws-emulator-embedded --tests
cargo test --locked --target x86_64-pc-windows-msvc -p aws-emulator-router --test emulator_core -- --include-ignored
```

Run permission-sensitive tests as an ordinary user. Windows symbolic-link tests
need Developer Mode or the corresponding privilege; their output identifies
skipped assertions. The process security suite also needs the source Smithy models.

Every embedding executable that invokes Python must install the allocation
observer and apply the dependency overrides at its workspace root. See the
[embedding guide](core/embedded/README.md).

## Platform limits

Credential publication requires a filesystem with Windows ACLs and stable file
identities, such as NTFS. Existing publication directories must have protected,
owner-only permissions. Reparse points and hard-linked destination files are
refused; a conflicting open handle can prevent cleanup.

Python's [memory observer](platform/windows-support/MEMORY_ACCOUNTING.md) measures
owned Rust allocations cooperatively. Foreign heaps, OS mappings, and stacks are
outside that measurement; it is not a hard process-memory cap.

CSV fields may contain Unicode, but Windows CSV delimiter, quote, and escape
characters must be ASCII; other dialect characters are rejected.

MSVC builds may depend on the Visual C++ runtime. A build-host run alone does not
establish that an executable is self-contained; package and test its runtime
prerequisites before distributing it.
