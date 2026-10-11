# closedmcp-sdk

A small Rust wrapper for the official `rmcp` Streamable HTTP server. It checks a ClosedMCP signed pass on every MCP request and serves protected-resource metadata. The crate is its own Cargo workspace and is not part of the server workspace.

Install with `cargo add closedmcp-sdk rmcp axum` and `cargo add tokio --features macros,rt-multi-thread,net`. Wrap your existing rmcp handler factory with `router(Options::new(resource, allowed_domains), || MyServer::new())`; tools can read `closed_mcp_person(&ctx).email` and `.org`.

## Hello

```rust
use closedmcp_sdk::{closed_mcp_person, router, Options};
use rmcp::{RoleServer, service::RequestContext, tool, tool_router};
#[derive(Clone)] struct Hello;
#[tool_router(server_handler)] impl Hello {
    #[tool(description = "Greet the caller")] fn hello(&self, ctx: RequestContext<RoleServer>) -> String { format!("Hello {}", closed_mcp_person(&ctx).email) }
}
#[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = router(Options::new("https://example.com/mcp", vec!["example.com".into()]), || Hello)?;
    axum::serve(tokio::net::TcpListener::bind("0.0.0.0:8787").await?, app).await?;
    Ok(()) }
```

The runnable [template](template/src/main.rs) accepts `MCP_URL`, `ALLOWED_DOMAINS` (comma-separated), and optionally `PORT`, `CLOSEDMCP_ORIGIN`, and `CLOSEDMCP_JWKS_URL`. Run it with `cargo run --bin hello-template` from this folder.

`closed_mcp_person(&ctx)` gives a tool the verified `id`, `email`, `company`, `org`, and optional `ai_app` for that request. `ai_app` is display-only. The router creates a fresh rmcp handler per request and supports concurrent calls. Mount the returned `Router` directly or merge it into an axum application. The router authenticates `/mcp` (or the path in `MCP_URL`) and serves both specific and generic protected-resource metadata paths. A missing or invalid pass gets `401` with `WWW-Authenticate: Bearer resource_metadata="..."`.

The resource must exactly match the public MCP URL and token audience. At least one allowed company domain is required. The issuer defaults to `https://closedmcp.canpai.io` and its JWKS. For local tests, set `options.issuer` and `options.jwks_url` before calling `router`. Keys are cached and refreshed on an unknown key ID.

See the [ClosedMCP documentation](https://closedmcp.canpai.io/docs).
