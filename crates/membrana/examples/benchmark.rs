//! Membrana performance benchmark
//!
//! Run with: cargo run --example benchmark --release

use membrana::MembranaService;
use std::time::Instant;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🏁 Membrana Performance Benchmark\n");

    // Create service
    let service = MembranaService::new("sqlite::memory:").await?;
    let addr = "127.0.0.1:3001".parse()?;

    // Start server in background
    tokio::spawn(async move {
        let _ = service.serve(addr).await;
    });

    // Wait for server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let url = "http://127.0.0.1:3001/verify";

    println!("Warming up...");
    for _ in 0..100 {
        let _ = client
            .post(url)
            .body("warmup")
            .send()
            .await;
    }

    println!("\n📊 Running benchmark: 1000 requests\n");

    let mut latencies = Vec::new();
    let total_start = Instant::now();

    for i in 0..1000 {
        let start = Instant::now();
        let payload = format!("benchmark-payload-{}", i);
        
        let response = client
            .post(url)
            .body(payload)
            .send()
            .await?;

        let latency = start.elapsed();
        latencies.push(latency.as_micros() as f64);

        if response.status().is_success() {
            // Success
        } else {
            eprintln!("Request {} failed: {}", i, response.status());
        }
    }

    let total_duration = total_start.elapsed();

    // Calculate statistics
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let count = latencies.len() as f64;
    
    let min = latencies.first().unwrap();
    let max = latencies.last().unwrap();
    let median = latencies[latencies.len() / 2];
    let p95_idx = ((count * 0.95) as usize).min(latencies.len() - 1);
    let p95 = latencies[p95_idx];
    let p99_idx = ((count * 0.99) as usize).min(latencies.len() - 1);
    let p99 = latencies[p99_idx];
    let avg: f64 = latencies.iter().sum::<f64>() / count;

    let throughput = 1000.0 / total_duration.as_secs_f64();

    println!("📈 Results:");
    println!("  Total time:   {:.2}s", total_duration.as_secs_f64());
    println!("  Throughput:   {:.0} req/s", throughput);
    println!();
    println!("  Latency (μs):");
    println!("    Min:        {:.0}", min);
    println!("    Median:     {:.0}", median);
    println!("    Average:    {:.0}", avg);
    println!("    p95:        {:.0}", p95);
    println!("    p99:        {:.0}", p99);
    println!("    Max:        {:.0}", max);
    println!();

    // Check if p95 meets the target
    let p95_ms = p95 / 1000.0;
    if p95_ms <= 1.0 {
        println!("✅ SUCCESS: p95 latency ({:.2}ms) is ≤ 1ms target!", p95_ms);
    } else {
        println!("⚠️  WARNING: p95 latency ({:.2}ms) exceeds 1ms target", p95_ms);
    }

    // Concurrent benchmark
    println!("\n📊 Running concurrent benchmark: 100 concurrent requests x 10 rounds\n");

    let mut concurrent_latencies = Vec::new();
    let concurrent_start = Instant::now();

    for round in 0..10 {
        let mut set = JoinSet::new();
        
        for i in 0..100 {
            let url = url.to_string();
            set.spawn(async move {
                let start = Instant::now();
                let payload = format!("concurrent-{}-{}", round, i);
                let _ = reqwest::Client::new()
                    .post(&url)
                    .body(payload)
                    .send()
                    .await;
                start.elapsed().as_micros() as f64
            });
        }

        while let Some(result) = set.join_next().await {
            if let Ok(latency) = result {
                concurrent_latencies.push(latency);
            }
        }
    }

    let concurrent_duration = concurrent_start.elapsed();

    concurrent_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let concurrent_count = concurrent_latencies.len() as f64;
    let concurrent_p95_idx = ((concurrent_count * 0.95) as usize).min(concurrent_latencies.len() - 1);
    let concurrent_p95 = concurrent_latencies[concurrent_p95_idx];
    let concurrent_throughput = concurrent_count / concurrent_duration.as_secs_f64();

    println!("📈 Concurrent Results:");
    println!("  Total time:   {:.2}s", concurrent_duration.as_secs_f64());
    println!("  Throughput:   {:.0} req/s", concurrent_throughput);
    println!("  p95 latency:  {:.2}ms", concurrent_p95 / 1000.0);

    if concurrent_p95 / 1000.0 <= 1.0 {
        println!("\n✅ Concurrent benchmark PASSED!");
    } else {
        println!("\n⚠️  Concurrent benchmark: p95 above target");
    }

    Ok(())
}
