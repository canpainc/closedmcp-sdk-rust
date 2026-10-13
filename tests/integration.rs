const EMAIL_ONE: &str = concat!("user1", "@", "example.com");
const EMAIL_TWO: &str = concat!("user2", "@", "example.com");

use axum::{routing::get, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use closedmcp_sdk::{closed_mcp_person, router, Options, Verifier, VerifyError};
use ed25519_dalek::{pkcs8::EncodePrivateKey, SigningKey};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::rngs::OsRng;
use rmcp::{service::RequestContext, tool, tool_router, RoleServer};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, task::JoinHandle};

#[derive(Clone)]
struct Hello;
#[tool_router(server_handler)]
impl Hello {
    #[tool(description = "Greet caller")]
    async fn hello(&self, ctx: RequestContext<RoleServer>) -> String {
        tokio::time::sleep(Duration::from_millis(80)).await;
        format!("Hello {}", closed_mcp_person(&ctx).unwrap().email)
    }
}

async fn serve(app: Router) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (address, task)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

struct Fixture {
    key: SigningKey,
    resource: String,
    issuer: String,
    jwks_url: String,
    jwks_task: JoinHandle<()>,
    fetches: Arc<AtomicUsize>,
}
impl Fixture {
    async fn new() -> Self {
        let key = SigningKey::generate(&mut OsRng);
        let jwk = json!({"kty":"OKP", "crv":"Ed25519", "x": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()), "kid":"test-key", "alg":"EdDSA", "use":"sig"});
        let fetches = Arc::new(AtomicUsize::new(0));
        let count = fetches.clone();
        let (addr, jwks_task) = serve(Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let jwk = jwk.clone();
                let count = count.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"keys":[jwk]}))
                }
            }),
        ))
        .await;
        Self {
            key,
            resource: "http://127.0.0.1:8789/mcp".into(),
            issuer: "https://issuer.example".into(),
            jwks_url: format!("http://{addr}/.well-known/jwks.json"),
            jwks_task,
            fetches,
        }
    }
    fn options(&self) -> Options {
        let mut options = Options::new(&self.resource, vec!["example.com".into()]);
        options.issuer = self.issuer.clone();
        options.jwks_url = Some(self.jwks_url.clone());
        options
    }
    fn pass(&self, changes: Value, key: Option<&SigningKey>) -> String {
        self.pass_with_kid(changes, key, "test-key")
    }
    fn pass_with_kid(&self, changes: Value, key: Option<&SigningKey>, kid: &str) -> String {
        let mut claims = json!({"iss":self.issuer,"aud":self.resource,"sub":"person-123","email":EMAIL_ONE,"domain":"example.com","org":"acme","client":"Test app","iat":now(),"exp":now()+300,"jti":"pass-123"});
        for (name, value) in changes.as_object().unwrap() {
            claims[name] = value.clone();
        }
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.into());
        let der = key.unwrap_or(&self.key).to_pkcs8_der().unwrap();
        encode(&header, &claims, &EncodingKey::from_ed_der(der.as_bytes())).unwrap()
    }
}

#[tokio::test]
async fn default_issuers_and_unknown_kid_cooldown() {
    let f = Fixture::new().await;
    let mut options = Options::new(&f.resource, vec!["example.com".into()]);
    assert_eq!(options.issuer, "https://closedmcp.com");
    options.jwks_url = Some(f.jwks_url.clone());
    let verifier = Verifier::new(&options).unwrap();
    for issuer in ["https://closedmcp.com", "https://closedmcp.canpai.io"] {
        let token = f.pass(json!({"iss":issuer}), None);
        assert!(verifier
            .verify(Some(&format!("Bearer {token}")))
            .await
            .is_ok());
    }
    assert_eq!(f.fetches.load(Ordering::SeqCst), 2);
    let other = f.pass(json!({"iss":"https://other.example"}), None);
    assert!(verifier
        .verify(Some(&format!("Bearer {other}")))
        .await
        .is_err());
    assert_eq!(f.fetches.load(Ordering::SeqCst), 2);
    let unknown = f.pass_with_kid(json!({"iss":"https://closedmcp.com"}), None, "unknown");
    for _ in 0..2 {
        assert!(verifier
            .verify(Some(&format!("Bearer {unknown}")))
            .await
            .is_err());
    }
    assert_eq!(f.fetches.load(Ordering::SeqCst), 3);
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.jwks_task.abort();
    }
}

#[tokio::test]
async fn verifies_passes_and_required_config() {
    let f = Fixture::new().await;
    let verify = Verifier::new(&f.options()).unwrap();
    let good = f.pass(json!({}), None);
    let person = verify
        .verify(Some(&format!("Bearer {good}")))
        .await
        .unwrap();
    assert_eq!(person.id, "person-123");
    assert_eq!(person.email, EMAIL_ONE);
    assert_eq!(person.company, "example.com");
    assert_eq!(person.org, "acme");
    assert_eq!(person.ai_app.as_deref(), Some("Test app"));
    let wrong_key = SigningKey::generate(&mut OsRng);
    let bad = [
        f.pass(json!({"aud":"https://other.example/mcp"}), None),
        f.pass(json!({"exp":now()-1}), None),
        f.pass(json!({"exp":now()+301}), None),
        f.pass(json!({"domain":"other.example"}), None),
        f.pass(json!({}), Some(&wrong_key)),
        f.pass(json!({"client":5}), None),
        f.pass(json!({"client":null}), None),
        f.pass(json!({"jti":""}), None),
        f.pass(json!({"aud":[f.resource]}), None),
    ];
    assert!(matches!(verify.verify(None).await, Err(VerifyError)));
    for token in bad {
        assert!(verify
            .verify(Some(&format!("Bearer {token}")))
            .await
            .is_err());
    }
    assert!(Verifier::new(&Options::new(&f.resource, vec![])).is_err());
}

async fn call(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    method: &str,
    params: Value,
    id: u64,
) -> Value {
    let response = client
        .post(url)
        .bearer_auth(token)
        .header("accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, 200, "{body}");
    if body.starts_with("event:") {
        serde_json::from_str(body.lines().find_map(|s| s.strip_prefix("data: ")).unwrap()).unwrap()
    } else {
        serde_json::from_str(&body).unwrap()
    }
}

#[tokio::test]
async fn metadata_mcp_and_concurrent_people() {
    let f = Fixture::new().await;
    let (addr, task) = serve(router(f.options(), || Hello).unwrap()).await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let metadata: Value = client
        .get(format!("{base}/.well-known/oauth-protected-resource/mcp"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        metadata,
        json!({"resource":f.resource,"authorization_servers":[f.issuer],"bearer_methods_supported":["header"]})
    );
    let denied = client.post(format!("{base}/mcp")).send().await.unwrap();
    assert_eq!(denied.status(), 401);
    assert_eq!(denied.headers()["www-authenticate"], "Bearer resource_metadata=\"http://127.0.0.1:8789/.well-known/oauth-protected-resource/mcp\"");
    let url = format!("{base}/mcp");
    let alice = f.pass(json!({}), None);
    let bob = f.pass(json!({"sub":"person-456","email":EMAIL_TWO}), None);
    let init = call(&client, &url, &alice, "initialize", json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}), 1).await;
    assert_eq!(init["result"]["serverInfo"]["name"], "rmcp");
    let listed = call(&client, &url, &alice, "tools/list", json!({}), 2).await;
    assert_eq!(listed["result"]["tools"][0]["name"], "hello");
    let (a, b) = tokio::join!(
        call(
            &client,
            &url,
            &alice,
            "tools/call",
            json!({"name":"hello","arguments":{}}),
            3
        ),
        call(
            &client,
            &url,
            &bob,
            "tools/call",
            json!({"name":"hello","arguments":{}}),
            4
        )
    );
    assert_eq!(
        a["result"]["content"][0]["text"],
        format!("Hello {EMAIL_ONE}")
    );
    assert_eq!(
        b["result"]["content"][0]["text"],
        format!("Hello {EMAIL_TWO}")
    );
    task.abort();
}

#[tokio::test]
async fn starts_template_and_makes_real_mcp_call() {
    let f = Fixture::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_hello-template"))
        .env("MCP_URL", &f.resource)
        .env("ALLOWED_DOMAINS", "example.com")
        .env("CLOSEDMCP_ORIGIN", &f.issuer)
        .env("CLOSEDMCP_JWKS_URL", &f.jwks_url)
        .env("PORT", port.to_string())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..60 {
        if let Ok(response) = client
            .get(format!("{base}/.well-known/oauth-protected-resource/mcp"))
            .send()
            .await
        {
            if response.status() == 200 {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "template did not start: {:?}", child.try_wait());
    let answer = call(
        &client,
        &format!("{base}/mcp"),
        &f.pass(json!({}), None),
        "tools/call",
        json!({"name":"hello","arguments":{}}),
        1,
    )
    .await;
    assert_eq!(
        answer["result"]["content"][0]["text"],
        format!("Hello {EMAIL_ONE}"),
        "{answer}"
    );
    child.kill().await.unwrap();
}
