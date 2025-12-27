//! # Policy Engine
//!
//! Policy evaluation engine with WASM execution and gas metering.
//!
//! ## Features
//! - JSON-based policy format (extensible to TDLN DSL)
//! - WASM execution via Wasmtime
//! - Gas-meter limiting fuel to 100k
//! - Deterministic policy evaluation
//!
//! ## Example
//!
//! ```no_run
//! use policy_engine::{PolicyEngine, Policy, PolicyDecision};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = PolicyEngine::new()?;
//! 
//! let policy = Policy::allow_all();
//! let decision = engine.evaluate(&policy, &serde_json::json!({"action": "read"}))?;
//! 
//! assert_eq!(decision, PolicyDecision::Allow);
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use wasmtime::*;

/// Maximum fuel (gas) allowed for policy execution
pub const MAX_FUEL: u64 = 100_000;

/// Error types for Policy Engine operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// WASM compilation error
    #[error("WASM compilation error: {0}")]
    Compilation(String),

    /// WASM execution error
    #[error("WASM execution error: {0}")]
    Execution(String),

    /// Policy validation error
    #[error("Policy validation error: {0}")]
    Validation(String),

    /// Fuel exhausted (gas limit exceeded)
    #[error("Fuel exhausted: policy exceeded {MAX_FUEL} fuel limit")]
    FuelExhausted,

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Wasmtime error
    #[error("Wasmtime error: {0}")]
    Wasmtime(#[from] wasmtime::Error),
}

/// Result type for Policy Engine operations
pub type Result<T> = std::result::Result<T, Error>;

/// Policy decision result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyDecision {
    /// Allow the action
    Allow,
    /// Deny the action
    Deny,
}

/// Policy structure (JSON-based, extensible to TDLN)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy identifier
    pub id: String,
    /// Policy version
    pub version: String,
    /// Policy rules
    pub rules: Vec<PolicyRule>,
    /// Policy hash for determinism verification
    pub hash: Option<Vec<u8>>,
}

/// Individual policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule name
    pub name: String,
    /// Rule effect (allow/deny)
    pub effect: PolicyDecision,
    /// Conditions (simplified JSON path matching)
    pub conditions: Vec<String>,
}

impl Policy {
    /// Create a simple allow-all policy
    pub fn allow_all() -> Self {
        Self {
            id: "allow-all".to_string(),
            version: "1.0.0".to_string(),
            rules: vec![PolicyRule {
                name: "allow-all-rule".to_string(),
                effect: PolicyDecision::Allow,
                conditions: vec![],
            }],
            hash: None,
        }
    }

    /// Create a simple deny-all policy
    pub fn deny_all() -> Self {
        Self {
            id: "deny-all".to_string(),
            version: "1.0.0".to_string(),
            rules: vec![PolicyRule {
                name: "deny-all-rule".to_string(),
                effect: PolicyDecision::Deny,
                conditions: vec![],
            }],
            hash: None,
        }
    }

    /// Compute deterministic hash of the policy
    pub fn compute_hash(&self) -> Vec<u8> {
        use ubl_kernel::{blake3_hash, canonical_json, EventDomain};
        
        // Create a copy without the hash field for canonical representation
        let policy_data = serde_json::json!({
            "id": self.id,
            "version": self.version,
            "rules": self.rules,
        });
        
        let canonical = canonical_json(&policy_data).unwrap_or_default();
        blake3_hash(EventDomain::Decision, canonical.as_bytes()).to_vec()
    }

    /// Verify that the policy hash matches
    pub fn verify_hash(&self) -> bool {
        if let Some(ref stored_hash) = self.hash {
            let computed = self.compute_hash();
            stored_hash == &computed
        } else {
            false
        }
    }
}

/// Policy Engine for evaluating policies
pub struct PolicyEngine {
    engine: Engine,
}

impl PolicyEngine {
    /// Create a new Policy Engine
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use policy_engine::PolicyEngine;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = PolicyEngine::new()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true); // Enable fuel metering
        
        let engine = Engine::new(&config)?;
        
        Ok(Self { engine })
    }

    /// Evaluate a policy against a context
    ///
    /// # Arguments
    ///
    /// * `policy` - The policy to evaluate
    /// * `context` - The context data for evaluation
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use policy_engine::{PolicyEngine, Policy};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = PolicyEngine::new()?;
    /// let policy = Policy::allow_all();
    /// let context = serde_json::json!({"action": "read"});
    /// let decision = engine.evaluate(&policy, &context)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn evaluate(&self, policy: &Policy, context: &serde_json::Value) -> Result<PolicyDecision> {
        // For now, use simple rule-based evaluation
        // In a full implementation, this would compile to WASM and execute
        
        // If no rules, deny by default
        if policy.rules.is_empty() {
            return Ok(PolicyDecision::Deny);
        }

        // Simple evaluation: check first matching rule
        // Note: Currently all rules with empty conditions match
        // TODO: Implement proper condition evaluation when TDLN parser is added
        for rule in &policy.rules {
            if self.evaluate_conditions(&rule.conditions, context) {
                return Ok(rule.effect);
            }
        }

        // Default to deny if no rules match
        Ok(PolicyDecision::Deny)
    }

    /// Evaluate policy conditions (simplified)
    /// 
    /// NOTE: Current implementation is simplified:
    /// - Empty conditions always match (allow-all/deny-all patterns)
    /// - Non-empty conditions are not yet implemented
    /// - Will be extended when TDLN DSL parser is added
    fn evaluate_conditions(&self, conditions: &[String], _context: &serde_json::Value) -> bool {
        // Empty conditions always match (for allow-all/deny-all policies)
        if conditions.is_empty() {
            return true;
        }

        // TODO: Implement condition parsing and evaluation
        // For now, conditions are not supported - return false to be safe
        false
    }

    /// Compile policy to WASM module
    ///
    /// This creates a simple WASM module that represents the policy logic.
    /// In a full implementation, this would compile TDLN to WASM.
    /// 
    /// NOTE: Current implementation only supports single-rule policies
    /// with empty conditions (allow-all/deny-all patterns).
    /// Multi-rule policies will use the first rule only.
    pub fn compile_to_wasm(&self, policy: &Policy) -> Result<Vec<u8>> {
        use wasm_encoder::*;

        let mut module = Module::new();

        // Type section - define function signature: () -> i32
        let mut types = TypeSection::new();
        types.ty().function(vec![], vec![ValType::I32]);

        // Function section - reference type 0
        let mut functions = FunctionSection::new();
        functions.function(0);

        // Memory section
        let mut memories = MemorySection::new();
        memories.memory(MemoryType {
            minimum: 1,
            maximum: Some(1),
            memory64: false,
            shared: false,
            page_size_log2: None,
        });

        // Export section - export the evaluate function
        let mut exports = ExportSection::new();
        exports.export("evaluate", ExportKind::Func, 0);

        // Code section - function body
        // NOTE: Simplified implementation - only uses first rule
        // TODO: Compile all rules when TDLN parser is added
        let mut function_body = wasm_encoder::Function::new(vec![]);
        
        // Determine decision based on first rule with empty conditions
        let decision = if !policy.rules.is_empty() && policy.rules[0].conditions.is_empty() {
            match policy.rules[0].effect {
                PolicyDecision::Allow => 1,
                PolicyDecision::Deny => 0,
            }
        } else {
            0 // Deny by default for policies with conditions or no rules
        };

        function_body.instruction(&Instruction::I32Const(decision));
        function_body.instruction(&Instruction::End);

        let mut code = CodeSection::new();
        code.function(&function_body);

        // Assemble the module in the correct order
        // Order: Type, Import, Function, Table, Memory, Global, Export, Start, Element, DataCount, Code, Data
        module.section(&types);
        module.section(&functions);
        module.section(&memories);
        module.section(&exports);
        module.section(&code);

        Ok(module.finish())
    }

    /// Execute WASM module with fuel limit
    pub fn execute_wasm(&self, wasm_bytes: &[u8]) -> Result<PolicyDecision> {
        let module = Module::new(&self.engine, wasm_bytes)?;
        
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(MAX_FUEL)?;
        
        let instance = Instance::new(&mut store, &module, &[])?;
        
        let evaluate = instance
            .get_typed_func::<(), i32>(&mut store, "evaluate")
            .map_err(|e| Error::Execution(e.to_string()))?;
        
        // Execute with fuel limit - errors are caught here
        let result = evaluate.call(&mut store, ()).map_err(|e| {
            // Fuel exhaustion is caught here during execution
            if e.to_string().contains("fuel") || e.to_string().contains("out of fuel") {
                Error::FuelExhausted
            } else {
                Error::Execution(e.to_string())
            }
        })?;

        Ok(match result {
            1 => PolicyDecision::Allow,
            _ => PolicyDecision::Deny,
        })
    }

    /// Get the policy hash for determinism
    pub fn policy_hash(&self, policy: &Policy) -> Vec<u8> {
        policy.compute_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_engine_creation() {
        let engine = PolicyEngine::new();
        assert!(engine.is_ok());
    }

    #[test]
    fn test_allow_all_policy() {
        let engine = PolicyEngine::new().unwrap();
        let policy = Policy::allow_all();
        let context = serde_json::json!({"action": "read"});
        
        let decision = engine.evaluate(&policy, &context).unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_deny_all_policy() {
        let engine = PolicyEngine::new().unwrap();
        let policy = Policy::deny_all();
        let context = serde_json::json!({"action": "write"});
        
        let decision = engine.evaluate(&policy, &context).unwrap();
        assert_eq!(decision, PolicyDecision::Deny);
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let policy1 = Policy::allow_all();
        let policy2 = Policy::allow_all();
        
        let hash1 = policy1.compute_hash();
        let hash2 = policy2.compute_hash();
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_policy_hash_different() {
        let policy1 = Policy::allow_all();
        let policy2 = Policy::deny_all();
        
        let hash1 = policy1.compute_hash();
        let hash2 = policy2.compute_hash();
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compile_to_wasm() {
        let engine = PolicyEngine::new().unwrap();
        let policy = Policy::allow_all();
        
        let wasm = engine.compile_to_wasm(&policy);
        assert!(wasm.is_ok());
        assert!(!wasm.unwrap().is_empty());
    }

    #[test]
    fn test_execute_wasm_allow() {
        let engine = PolicyEngine::new().unwrap();
        let policy = Policy::allow_all();
        
        let wasm = engine.compile_to_wasm(&policy).unwrap();
        let decision = engine.execute_wasm(&wasm).unwrap();
        
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_execute_wasm_deny() {
        let engine = PolicyEngine::new().unwrap();
        let policy = Policy::deny_all();
        
        let wasm = engine.compile_to_wasm(&policy).unwrap();
        let decision = engine.execute_wasm(&wasm).unwrap();
        
        assert_eq!(decision, PolicyDecision::Deny);
    }

    #[test]
    fn test_fuel_limit_constant() {
        assert_eq!(MAX_FUEL, 100_000);
    }

    #[test]
    fn test_policy_decision_serialization() {
        let allow = PolicyDecision::Allow;
        let json = serde_json::to_string(&allow).unwrap();
        assert_eq!(json, "\"ALLOW\"");
        
        let deny = PolicyDecision::Deny;
        let json = serde_json::to_string(&deny).unwrap();
        assert_eq!(json, "\"DENY\"");
    }
}
