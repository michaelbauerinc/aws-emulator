// SPDX-License-Identifier: CC0-1.0

//! Signed Python deployment shared by the embedding host contract tests.

use std::io::Write as _;
use std::time::{Duration, SystemTime};

use aws_emulator_embedded::{Authentication, AwsEmulatorEmbedded, EmbeddedOptions, Telemetry};
use aws_smithy_runtime_api::client::{http::HttpConnector, orchestrator::HttpRequest};
use base64::Engine as _;
use emulator_server::{
    aws_smithy_types::body::SdkBody,
    bytes::Bytes,
    http,
    http_body_util::BodyExt,
    request_authentication::{PresignTarget, presign_url, presigned_payload_header},
};
use serde_json::{Value, json};

/// Stack for assembling the facade here. Keep this at or above the size the
/// router's own boot check uses, so a workspace that boots in production also
/// passes here.
const BOOT_STACK_SIZE: usize = 64 * 1024 * 1024;

/// An AWS SDK config builder's `http_client(..)` accepts only an `HttpClient`, so the
/// facade must stay one: this stops compiling if `http_client()` no longer returns it.
fn assert_sdk_http_client(_client: impl aws_smithy_runtime_api::client::http::HttpClient) {}

/// Deploy and invoke through a host thread large enough to assemble the router.
pub fn invoke_python() -> http::Response<Bytes> {
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("embedded-python-check".to_string())
        .stack_size(BOOT_STACK_SIZE)
        .spawn(move || {
            let result = std::panic::catch_unwind(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build the embedding host's async runtime");
                runtime.block_on(async {
                    tokio::time::timeout(Duration::from_secs(60), deployed_python_invocation())
                        .await
                        .expect("embedded deployment and invocation finish within one minute")
                })
            });
            let _ = sent.send(result);
        })
        .expect("spawn the embedding host with its required stack");
    // Bound the caller even if a native call prevents the async timer from running.
    let result = received
        .recv_timeout(Duration::from_secs(90))
        .expect("embedding host finishes within ninety seconds");
    worker.join().expect("embedding host thread exits");
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

const FUNCTIONS: &str = "/2015-03-31/functions";
const FUNCTION_NAME: &str = "embedded-python-host-contract";
const LAMBDA_ENDPOINT: &str = "https://lambda.us-east-1.amazonaws.com";
const HANDLER_SOURCE: &str = r#"
def lambda_handler(event, context):
    return {"total": sum(event["values"])}
"#;

async fn deployed_python_invocation() -> http::Response<Bytes> {
    let emulator = AwsEmulatorEmbedded::new(
        EmbeddedOptions::default()
            .authentication(Authentication::On)
            .telemetry(Telemetry::Off),
    );
    assert_sdk_http_client(emulator.http_client());
    assert!(
        emulator
            .certificate_authority()
            .pem()
            .starts_with("-----BEGIN CERTIFICATE-----"),
        "the facade must hand a host the certificate its listeners present"
    );
    let created = lambda_request(
        &emulator,
        "POST",
        FUNCTIONS,
        Some(&json!({
            "FunctionName": FUNCTION_NAME,
            "Role": "arn:aws:iam::000000000000:role/service-role/lambda-exec",
            "Runtime": "python3.12",
            "Handler": "lambda_function.lambda_handler",
            "Timeout": 5,
            "MemorySize": 128,
            "Code": { "ZipFile": deployment_zip() },
        })),
    )
    .await;
    assert_eq!(
        created.status().as_u16(),
        201,
        "{}",
        response_json(&created)
    );

    let function_path = format!("{FUNCTIONS}/{FUNCTION_NAME}");
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let response = lambda_request(
                &emulator,
                "GET",
                &format!("{function_path}/configuration"),
                None,
            )
            .await;
            let configuration = response_json(&response);
            assert_eq!(response.status().as_u16(), 200, "{configuration}");
            match configuration["State"].as_str() {
                Some("Active") => break,
                Some("Pending") => tokio::time::sleep(Duration::from_millis(50)).await,
                other => panic!("unexpected function state {other:?}: {configuration}"),
            }
        }
    })
    .await
    .expect("the uploaded function becomes active");

    let invoked = lambda_request(
        &emulator,
        "POST",
        &format!("{function_path}/invocations"),
        Some(&json!({ "values": [2, 3, 5] })),
    )
    .await;
    let deleted = lambda_request(&emulator, "DELETE", &function_path, None).await;
    assert_eq!(deleted.status().as_u16(), 204);
    invoked
}

/// The same deployment format the Lambda integration fixtures upload, with a
/// readable source fixture rather than opaque archived bytes checked into the test.
fn deployment_zip() -> String {
    let mut archive = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut archive);
        let options: zip::write::FileOptions<'_, '_, ()> = zip::write::FileOptions::default();
        writer
            .start_file("lambda_function.py", options)
            .expect("start ZIP entry");
        writer
            .write_all(HANDLER_SOURCE.as_bytes())
            .expect("write Python source");
        writer.finish().expect("finish deployment ZIP");
    }
    base64::engine::general_purpose::STANDARD.encode(archive.into_inner())
}

/// Sign with the credentials this facade vends, using the framework's maintained
/// SigV4 signer. AWS-shaped URLs are delivered only to the in-process connector.
async fn lambda_request(
    emulator: &AwsEmulatorEmbedded,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> http::Response<Bytes> {
    let credentials = emulator.credentials();
    let (key, secret) = emulator_server::embedded::signing_key_pair(&credentials);
    let target = PresignTarget {
        endpoint: LAMBDA_ENDPOINT,
        method,
        signing_name: "lambda",
        region: "us-east-1",
        path,
        query: &[],
        headers: &[("content-type", "application/json")],
    };
    let url = presign_url(&target, key, secret, SystemTime::now(), 60)
        .expect("the framework signs this Lambda request");
    let mut request = http::Request::builder()
        .method(method)
        .uri(url)
        .header("host", "lambda.us-east-1.amazonaws.com")
        .header("content-type", "application/json");
    if let Some((name, value)) = presigned_payload_header("lambda", method) {
        request = request.header(name, value);
    }
    let body = body
        .map(|value| serde_json::to_vec(value).expect("JSON serializes"))
        .unwrap_or_default();
    let request = request
        .body(SdkBody::from(body))
        .expect("well-formed signed request");
    let response = emulator
        .http_connector()
        .call(HttpRequest::try_from(request).expect("SDK request conversion"))
        .await
        .expect("the in-process connector answers the signed request")
        .try_into_http1x()
        .expect("HTTP response conversion");
    let (parts, body) = response.into_parts();
    let bytes = body
        .collect()
        .await
        .expect("complete in-process response")
        .to_bytes();
    http::Response::from_parts(parts, bytes)
}

pub fn response_json(response: &http::Response<Bytes>) -> Value {
    serde_json::from_slice(response.body()).expect("the Lambda response is JSON")
}
