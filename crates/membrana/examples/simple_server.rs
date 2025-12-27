//! Simple Membrana server example
//!
//! Run with: cargo run --example simple_server

use membrana::MembranaService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create service with in-memory SQLite database
    let service = MembranaService::new("sqlite::memory:").await?;

    // Bind to localhost:3000
    let addr = "127.0.0.1:3000".parse()?;

    println!("🚀 Membrana service starting on http://{}", addr);
    println!("📍 POST /verify - Verify artifacts");
    println!("📍 GET /health - Health check");
    println!();
    println!("Example usage:");
    println!("  curl -X POST http://localhost:3000/verify -d 'test data'");
    println!("  curl http://localhost:3000/health");

    // Start the server
    service.serve(addr).await?;

    Ok(())
}
