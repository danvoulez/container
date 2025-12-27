//! Policy Engine example
//!
//! Run with: cargo run --example simple_policy

use policy_engine::{Policy, PolicyEngine, PolicyDecision};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️  Policy Engine Example\n");

    // Create policy engine
    let engine = PolicyEngine::new()?;
    println!("✅ Policy Engine initialized with fuel limit: {} units", policy_engine::MAX_FUEL);
    println!();

    // Test 1: Allow-all policy
    println!("📋 Test 1: Allow-all Policy");
    let allow_policy = Policy::allow_all();
    let context = serde_json::json!({"action": "read", "resource": "data.txt"});
    
    let decision = engine.evaluate(&allow_policy, &context)?;
    println!("  Context: {}", context);
    println!("  Decision: {:?}", decision);
    assert_eq!(decision, PolicyDecision::Allow);
    println!("  ✅ Passed\n");

    // Test 2: Deny-all policy
    println!("📋 Test 2: Deny-all Policy");
    let deny_policy = Policy::deny_all();
    let context = serde_json::json!({"action": "write", "resource": "secrets.txt"});
    
    let decision = engine.evaluate(&deny_policy, &context)?;
    println!("  Context: {}", context);
    println!("  Decision: {:?}", decision);
    assert_eq!(decision, PolicyDecision::Deny);
    println!("  ✅ Passed\n");

    // Test 3: Policy hashing (determinism)
    println!("📋 Test 3: Policy Hash Determinism");
    let policy1 = Policy::allow_all();
    let policy2 = Policy::allow_all();
    
    let hash1 = engine.policy_hash(&policy1);
    let hash2 = engine.policy_hash(&policy2);
    
    println!("  Policy 1 hash: {}", hex::encode(&hash1));
    println!("  Policy 2 hash: {}", hex::encode(&hash2));
    assert_eq!(hash1, hash2);
    println!("  ✅ Same policy produces identical hash\n");

    // Test 4: Different policies have different hashes
    println!("📋 Test 4: Different Policies");
    let allow = Policy::allow_all();
    let deny = Policy::deny_all();
    
    let hash_allow = engine.policy_hash(&allow);
    let hash_deny = engine.policy_hash(&deny);
    
    println!("  Allow policy hash: {}", hex::encode(&hash_allow));
    println!("  Deny policy hash:  {}", hex::encode(&hash_deny));
    assert_ne!(hash_allow, hash_deny);
    println!("  ✅ Different policies have different hashes\n");

    // Test 5: WASM compilation
    println!("📋 Test 5: WASM Compilation");
    let policy = Policy::allow_all();
    let wasm_bytes = engine.compile_to_wasm(&policy)?;
    
    println!("  Compiled WASM size: {} bytes", wasm_bytes.len());
    println!("  ✅ Policy compiled to WASM\n");

    // Test 6: WASM execution
    println!("📋 Test 6: WASM Execution with Fuel Limit");
    let allow_wasm = engine.compile_to_wasm(&Policy::allow_all())?;
    let deny_wasm = engine.compile_to_wasm(&Policy::deny_all())?;
    
    let allow_result = engine.execute_wasm(&allow_wasm)?;
    let deny_result = engine.execute_wasm(&deny_wasm)?;
    
    println!("  Allow policy WASM result: {:?}", allow_result);
    println!("  Deny policy WASM result:  {:?}", deny_result);
    assert_eq!(allow_result, PolicyDecision::Allow);
    assert_eq!(deny_result, PolicyDecision::Deny);
    println!("  ✅ WASM execution successful with fuel metering\n");

    println!("🎉 All tests passed!");
    println!();
    println!("Summary:");
    println!("  - Policy evaluation working");
    println!("  - Deterministic hashing working");
    println!("  - WASM compilation working");
    println!("  - WASM execution with fuel limit working");
    println!("  - Gas metering prevents runaway policies");

    Ok(())
}
