//! ClosedMCP authorization for an official rmcp Streamable HTTP server.

use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::any,
    Json, Router,
};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use rmcp::{
    service::RequestContext,
    transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    RoleServer, ServerHandler,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use url::Url;

pub const CLOSEDMCP: &str = "https://closedmcp.canpai.io";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Person {
    pub id: String,
    pub email: String,
    pub company: String,
    pub org: String,
    pub ai_app: Option<String>,
}

/// Read the verified caller from an rmcp tool request.
pub fn closed_mcp_person(ctx: &RequestContext<RoleServer>) -> &Person {
    ctx.extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<Person>())
        .expect("No verified ClosedMCP person in this request")
}

#[derive(Clone, Debug)]
pub struct Options {
    pub resource: String,
    pub allowed_domains: Vec<String>,
    pub issuer: String,
    pub jwks_url: Option<String>,
}

impl Options {
    pub fn new(resource: impl Into<String>, allowed_domains: Vec<String>) -> Self {
        Self {
            resource: resource.into(),
            allowed_domains,
            issuer: CLOSEDMCP.into(),
            jwks_url: None,
        }
    }
}

#[derive(Debug)]
pub struct ConfigError(pub &'static str);
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ConfigError {}

#[derive(Debug)]
pub struct VerifyError;
impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pass verification failed")
    }
}
impl std::error::Error for VerifyError {}
impl From<()> for VerifyError {
    fn from(_: ()) -> Self {
        Self
    }
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: serde_json::Value,
    sub: String,
    email: String,
    domain: String,
    org: String,
    #[serde(default, deserialize_with = "optional_string_if_present")]
    client: Option<String>,
    iat: i64,
    exp: i64,
    jti: String,
}

fn optional_string_if_present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

#[derive(Clone)]
pub struct Verifier {
    resource: String,
    issuer: String,
    allowed: HashSet<String>,
    jwks_url: String,
    keys: Arc<RwLock<Option<JwkSet>>>,
    http: reqwest::Client,
}

impl Verifier {
    pub fn new(options: &Options) -> Result<Self, ConfigError> {
        let url = Url::parse(&options.resource).map_err(|_| {
            ConfigError("resource must be an absolute HTTP(S) MCP URL without query or fragment")
        })?;
        if !matches!(url.scheme(), "http" | "https")
            || url.query().is_some()
            || url.fragment().is_some()
            || url.host_str().is_none()
        {
            return Err(ConfigError(
                "resource must be an absolute HTTP(S) MCP URL without query or fragment",
            ));
        }
        let allowed: HashSet<_> = options
            .allowed_domains
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if allowed.is_empty() {
            return Err(ConfigError(
                "allowed_domains must name at least one company",
            ));
        }
        let jwks_url = options
            .jwks_url
            .clone()
            .unwrap_or_else(|| format!("{}/.well-known/jwks.json", options.issuer));
        Url::parse(&jwks_url).map_err(|_| ConfigError("jwks_url must be a URL"))?;
        Ok(Self {
            resource: options.resource.clone(),
            issuer: options.issuer.clone(),
            allowed,
            jwks_url,
            keys: Arc::new(RwLock::new(None)),
            http: reqwest::Client::new(),
        })
    }

    async fn fetch_keys(&self) -> Result<JwkSet, ()> {
        self.http
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|_| ())?
            .error_for_status()
            .map_err(|_| ())?
            .json()
            .await
            .map_err(|_| ())
    }

    pub async fn verify(&self, authorization: Option<&str>) -> Result<Person, VerifyError> {
        let value = authorization.ok_or(())?;
        let (scheme, token) = value.split_once(char::is_whitespace).ok_or(())?;
        if !scheme.eq_ignore_ascii_case("Bearer")
            || token.is_empty()
            || token.chars().any(char::is_whitespace)
        {
            return Err(VerifyError);
        }
        let header = decode_header(token).map_err(|_| ())?;
        if header.alg != Algorithm::EdDSA {
            return Err(VerifyError);
        }
        let kid = header.kid.ok_or(())?;
        let mut keys = self.keys.read().await.clone();
        if keys.as_ref().and_then(|set| set.find(&kid)).is_none() {
            let fresh = self.fetch_keys().await?;
            *self.keys.write().await = Some(fresh.clone());
            keys = Some(fresh);
        }
        let key = keys.as_ref().and_then(|set| set.find(&kid)).ok_or(())?;
        let decoding = DecodingKey::from_jwk(key).map_err(|_| ())?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.resource.as_str()]);
        validation.leeway = 0;
        validation.required_spec_claims = ["iss", "aud", "sub", "iat", "exp", "jti"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let claims = decode::<Claims>(token, &decoding, &validation)
            .map_err(|_| ())?
            .claims;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs() as i64;
        if claims.iss != self.issuer
            || claims.aud != self.resource
            || claims.iat > now
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > 300
            || now - claims.iat > 300
            || claims.sub.is_empty()
            || claims.email.is_empty()
            || claims.domain.is_empty()
            || claims.org.is_empty()
            || claims.jti.is_empty()
            || !self.allowed.contains(&claims.domain.to_ascii_lowercase())
        {
            return Err(VerifyError);
        }
        Ok(Person {
            id: claims.sub,
            email: claims.email,
            company: claims.domain,
            org: claims.org,
            ai_app: claims.client,
        })
    }
}

#[derive(Serialize)]
struct Metadata {
    resource: String,
    authorization_servers: Vec<String>,
    bearer_methods_supported: Vec<&'static str>,
}

/// Build an axum router around a fresh rmcp handler for each MCP request.
pub fn router<S, F>(options: Options, factory: F) -> Result<Router, ConfigError>
where
    S: ServerHandler + Send + 'static,
    F: Fn() -> S + Clone + Send + Sync + 'static,
{
    let verifier = Verifier::new(&options)?;
    let url = Url::parse(&options.resource).map_err(|_| ConfigError("invalid resource"))?;
    let path = url.path().to_owned();
    let metadata_path = format!(
        "/.well-known/oauth-protected-resource{}",
        if path == "/" { "" } else { &path }
    );
    let metadata_url = format!("{}{}", url.origin().ascii_serialization(), metadata_path);
    let metadata = Arc::new(Metadata {
        resource: options.resource,
        authorization_servers: vec![options.issuer],
        bearer_methods_supported: vec!["header"],
    });
    let service = StreamableHttpService::new(
        move || Ok(factory()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true),
    );
    let handler = move |mut req: Request| {
        let verifier = verifier.clone();
        let service = service.clone();
        let metadata_url = metadata_url.clone();
        async move {
            let authorization = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            let person = match verifier.verify(authorization).await {
                Ok(person) => person,
                Err(VerifyError) => {
                    let mut response = (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error":"unauthorized"})),
                    )
                        .into_response();
                    response.headers_mut().insert(
                        header::WWW_AUTHENTICATE,
                        HeaderValue::from_str(&format!(
                            "Bearer resource_metadata=\"{metadata_url}\""
                        ))
                        .expect("valid metadata URL"),
                    );
                    return response;
                }
            };
            if req.method() != axum::http::Method::POST {
                return (
                    StatusCode::METHOD_NOT_ALLOWED,
                    Json(serde_json::json!({"error":"method not allowed"})),
                )
                    .into_response();
            }
            req.extensions_mut().insert(person);
            let response = service.handle(req).await;
            response.map(Body::new)
        }
    };
    let metadata_handler = {
        let metadata = metadata.clone();
        move || {
            let metadata = metadata.clone();
            async move { Json(metadata) }
        }
    };
    let generic_handler = {
        let metadata = metadata.clone();
        move || {
            let metadata = metadata.clone();
            async move { Json(metadata) }
        }
    };
    let app = Router::new()
        .route(&metadata_path, axum::routing::get(metadata_handler))
        .route(
            "/.well-known/oauth-protected-resource",
            axum::routing::get(generic_handler),
        );
    Ok(app.route(&path, any(handler)))
}
