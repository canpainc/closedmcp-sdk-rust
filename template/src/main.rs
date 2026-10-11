use closedmcp_sdk::{closed_mcp_person, router, Options};
use rmcp::{service::RequestContext, tool, tool_router, RoleServer};

#[derive(Clone)]
struct Hello;

#[tool_router(server_handler)]
impl Hello {
    #[tool(description = "Say hello to the signed-in person")]
    fn hello(&self, ctx: RequestContext<RoleServer>) -> String {
        format!("Hello {}", closed_mcp_person(&ctx).email)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resource = std::env::var("MCP_URL")?;
    let domains = std::env::var("ALLOWED_DOMAINS")?
        .split(',')
        .map(str::to_owned)
        .collect();
    let mut options = Options::new(resource, domains);
    if let Ok(issuer) = std::env::var("CLOSEDMCP_ORIGIN") {
        options.issuer = issuer;
    }
    options.jwks_url = std::env::var("CLOSEDMCP_JWKS_URL").ok();
    let app = router(options, || Hello)?;
    let port = std::env::var("PORT").unwrap_or_else(|_| "8787".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
