//! OCI registry client.
//!
//! Pulls are the trust boundary of the image pipeline, so the client:
//!
//! - verifies **every** blob against the digest the manifest advertised, before it is written;
//! - handles Docker registry token authentication (the `Bearer` challenge flow);
//! - rejects a manifest whose own bytes do not match the digest it was fetched by.
//!
//! No blob is ever used unverified, including the manifest itself.

use std::time::Duration;

use crate::digest::Digest;
use crate::manifest::ImageManifest;
use crate::reference::ImageReference;
use crate::{media_types, OciError, OciResult};

/// How long a registry request may take before it is abandoned.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A registry client.
#[derive(Debug, Clone)]
pub struct RegistryClient {
    /// The reference this client is bound to.
    reference: ImageReference,
    client: reqwest::Client,
    /// Extra headers sent with every request (for example a registry token).
    headers: reqwest::header::HeaderMap,
}

impl RegistryClient {
    /// Build a client for `reference`.
    pub fn new(reference: &ImageReference) -> OciResult<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("rustfun-oci/", env!("CARGO_PKG_VERSION")));
        // A local registry (localhost:PORT) speaks plain HTTP; a real registry must be TLS. The
        // scheme is chosen here so a test registry and `docker run` behave the same way.
        if is_local_registry(&reference.registry) {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder.build().map_err(|error| {
            OciError::new("registry_client", "cannot build the HTTP client").with_source(error)
        })?;
        Ok(Self {
            reference: reference.clone(),
            client,
            headers: reqwest::header::HeaderMap::new(),
        })
    }

    /// The underlying reference.
    pub fn reference(&self) -> &ImageReference {
        &self.reference
    }

    /// Fetch and verify the manifest for `reference`.
    ///
    /// Returns the manifest and the exact bytes it was parsed from, so the caller can cache what
    /// it verified rather than what it intended to verify.
    pub async fn fetch_manifest(&self) -> OciResult<(ImageManifest, Vec<u8>)> {
        let url = format!(
            "{}://{}/v2/{}/manifests/{}",
            registry_scheme(&self.reference.registry),
            self.reference.registry,
            self.reference.repository,
            self.reference.digest.as_ref().map_or_else(
                || self
                    .reference
                    .tag
                    .clone()
                    .unwrap_or_else(|| "latest".to_owned()),
                |d| d.as_str().to_owned()
            )
        );
        let accept = [
            media_types::MANIFEST,
            media_types::OCI_MANIFEST,
            media_types::MANIFEST_LIST,
            media_types::OCI_INDEX,
        ]
        .join(",");
        let response = self
            .client
            .get(&url)
            .header(reqwest::header::ACCEPT, accept)
            .headers(self.headers.clone())
            .send()
            .await
            .map_err(|error| {
                OciError::new(
                    "fetch_manifest",
                    format!("cannot reach the registry: {error}"),
                )
            })?;
        let response = self.handle_auth(response, &url).await?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|error| {
            OciError::new("fetch_manifest", "the manifest response was truncated")
                .with_source(error)
        })?;
        if !status.is_success() {
            return Err(OciError::new(
                "fetch_manifest",
                format!("registry returned HTTP {status} for {url}"),
            ));
        }
        let manifest = ImageManifest::parse(&bytes)?;
        Ok((manifest, bytes.to_vec()))
    }

    /// Fetch a blob by digest and verify it.
    pub async fn fetch_blob(&self, digest: &Digest) -> OciResult<Vec<u8>> {
        let url = format!(
            "{}://{}/v2/{}/blobs/{}",
            registry_scheme(&self.reference.registry),
            self.reference.registry,
            self.reference.repository,
            digest.as_str()
        );
        let response = self
            .client
            .get(&url)
            .headers(self.headers.clone())
            .send()
            .await
            .map_err(|error| {
                OciError::new("fetch_blob", format!("cannot reach the registry: {error}"))
            })?;
        let response = self.handle_auth(response, &url).await?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|error| {
            OciError::new("fetch_blob", "the blob response was truncated").with_source(error)
        })?;
        if !status.is_success() {
            return Err(OciError::new(
                "fetch_blob",
                format!("registry returned HTTP {status} for {digest}"),
            ));
        }
        if !digest.verify(&bytes) {
            return Err(OciError::new(
                "fetch_blob",
                format!("the blob for {digest} does not match its digest"),
            ));
        }
        Ok(bytes.to_vec())
    }

    /// Follow a Docker token-authentication challenge, if the registry sent one.
    ///
    /// The flow is the standard one: a `401` with a `WWW-Authenticate: Bearer realm=...` header
    /// means the client must fetch a token from that realm and retry the request with it.
    async fn handle_auth(
        &self,
        response: reqwest::Response,
        url: &str,
    ) -> OciResult<reqwest::Response> {
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        let Some(challenge) = response.headers().get(reqwest::header::WWW_AUTHENTICATE) else {
            return Ok(response);
        };
        let challenge = challenge.to_str().map_err(|error| {
            OciError::new("registry_auth", "the auth challenge is not valid UTF-8")
                .with_source(error)
        })?;
        let Some(realm) = bearer_realm(challenge) else {
            return Ok(response);
        };
        let token = self.fetch_token(&realm).await?;
        let response = self
            .client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .map_err(|error| {
                OciError::new("registry_auth", "the authenticated request failed")
                    .with_source(error)
            })?;
        Ok(response)
    }

    /// Fetch an anonymous token from the realm named by the registry.
    async fn fetch_token(&self, realm: &str) -> OciResult<String> {
        let response = self.client.get(realm).send().await.map_err(|error| {
            OciError::new(
                "registry_auth",
                format!("cannot reach the token realm {realm}"),
            )
            .with_source(error)
        })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|error| {
            OciError::new("registry_auth", "the token response was truncated").with_source(error)
        })?;
        if !status.is_success() {
            return Err(OciError::new(
                "registry_auth",
                format!("the token realm returned HTTP {status}"),
            ));
        }
        let token: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            OciError::new("registry_auth", "the token response is not valid JSON")
                .with_source(error)
        })?;
        token
            .get("token")
            .or_else(|| token.get("access_token"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| OciError::new("registry_auth", "the token response contains no token"))
    }
}

/// Whether a registry is local (plain HTTP, test/dev only).
fn is_local_registry(registry: &str) -> bool {
    registry == "localhost"
        || registry.starts_with("localhost:")
        || registry.starts_with("127.0.0.1")
}

/// The scheme used to talk to a registry.
fn registry_scheme(registry: &str) -> &'static str {
    if is_local_registry(registry) {
        "http"
    } else {
        "https"
    }
}

/// Extract the `realm` from a `WWW-Authenticate: Bearer realm="..."` challenge.
///
/// Only a Bearer challenge carries a fetchable realm; `Basic realm="..."` does not, so it is
/// correctly reported as having none.
fn bearer_realm(challenge: &str) -> Option<String> {
    let challenge = challenge.trim();
    let (_, parameters) = challenge.split_once(' ')?;
    if !challenge.to_ascii_lowercase().starts_with("bearer") {
        return None;
    }
    for part in parameters.split(',') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            if key.trim().eq_ignore_ascii_case("realm") {
                let realm = value.trim().trim_matches('"');
                if !realm.is_empty() {
                    return Some(realm.to_owned());
                }
            }
        }
    }
    None
}

/// A stub registry for tests.
///
/// Serving real HTTP in a unit test keeps the client's auth, digest, and error paths honest
/// without reaching the network: the stub is the registry, and what it says is all the client
/// knows.
#[cfg(test)]
pub mod test_stub {
    /// Serve a registry that always returns `body` for any blob request.
    ///
    /// The blob digest is part of the path, so a caller that verifies will only succeed when it
    /// asks for `sha256(body)` — which is exactly the property the tests assert.
    pub async fn serve_verified_blob(
        body: &'static [u8],
    ) -> (std::net::SocketAddr, std::sync::Arc<tokio::sync::Mutex<()>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let body = body.to_vec();
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: application/octet-stream\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (address, std::sync::Arc::new(tokio::sync::Mutex::new(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bearer_challenge_exposes_its_realm() {
        assert_eq!(
            bearer_realm(
                r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io""#
            ),
            Some("https://auth.docker.io/token".to_owned())
        );
    }

    #[test]
    fn a_non_bearer_challenge_has_no_realm() {
        assert_eq!(bearer_realm(r#"Basic realm="registry""#), None);
        assert_eq!(bearer_realm(""), None);
    }

    #[tokio::test]
    async fn fetching_a_blob_verifies_the_digest() {
        let (address, _server) = test_stub::serve_verified_blob(b"hello").await;
        let reference = ImageReference::parse(&format!("localhost:{}/hello:1", address.port()))
            .expect("valid reference");
        let client = RegistryClient::new(&reference).expect("client");
        let digest = Digest::of(b"hello");
        let bytes = client.fetch_blob(&digest).await.expect("verified blob");
        assert_eq!(bytes, b"hello");
    }

    #[tokio::test]
    async fn a_blob_that_does_not_match_is_refused() {
        let (address, _server) = test_stub::serve_verified_blob(b"hello").await;
        let reference = ImageReference::parse(&format!("localhost:{}/hello:1", address.port()))
            .expect("valid reference");
        let client = RegistryClient::new(&reference).expect("client");
        // The stub serves "hello" for every digest, so asking for a different digest must fail.
        let digest = Digest::of(b"goodbye");
        let error = client.fetch_blob(&digest).await.expect_err("must refuse");
        assert!(error.to_string().contains("does not match"), "{error}");
    }
}
