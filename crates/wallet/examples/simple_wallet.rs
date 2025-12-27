//! Simple Wallet server example
//!
//! Run with: cargo run --example simple_wallet

use wallet::WalletService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create wallet service
    let service = WalletService::new().await?;

    // Bind to localhost:3001
    let addr = "127.0.0.1:3001".parse()?;

    println!("🔐 Wallet service starting on http://{}", addr);
    println!("📍 POST /permit - Create a new permit");
    println!("📍 GET /permit/:jti - Get permit status");
    println!("📍 DELETE /permit/:jti - Revoke a permit");
    println!("📍 GET /health - Health check");
    println!();
    println!("Example usage:");
    println!("  # Create permit");
    println!(r#"  curl -X POST http://localhost:3001/permit -H "Content-Type: application/json" \"#);
    println!(r#"    -d '{{"subject": "user@example.com", "ttl": 300, "scope": ["read", "write"]}}'"#);
    println!();
    println!("  # Revoke permit");
    println!("  curl -X DELETE http://localhost:3001/permit/<jti>");
    println!();
    println!("  # Health check");
    println!("  curl http://localhost:3001/health");

    // Start the server
    service.serve(addr).await?;

    Ok(())
}
