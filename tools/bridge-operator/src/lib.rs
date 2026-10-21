//! Read-only operator commands for a deployed BridgeEscrow and its Liquid light client. Nothing here signs or
//! sends: the commands print calldata for the operator's own wallet tooling, and write the escrow's deposit list.
//!
//! The browser interface implements the same rules in bridge-core/lib; the two are kept equal by shared vectors
//! (vectors/protocol.json, the Liquid testnet headers fixture) and by tests that repeat the JavaScript suite's
//! expected values.
pub mod abi;
pub mod bridge;
pub mod deposits;
pub mod elements;
pub mod esplora;
pub mod hash;
pub mod hex;
pub mod light_client;
pub mod rpc;
