//! Load a generated program and run it the way a node would: prune against the transaction, execute,
//! serialise, decode again and execute the decoded program (its types, hence its cost, are what a node
//! sees).  Mirrors simple-groth16 `tools/harness` (`hand`, `deploy spend`), MIT, commit 4f787ea0.
use simplicity::elements::taproot::ControlBlock;
use simplicity::elements::{BlockHash, Transaction, TxOut};
use simplicity::human_encoding::Forest;
use simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicity::jet::Elements;
use simplicity::{BitIter, BitMachine, Cmr, RedeemNode, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// A parsed generator program or its canonically decoded form.
pub enum Program {
    Text(Forest),
    Encoded(Arc<RedeemNode>),
}

pub struct Report {
    pub cost: u64,
    pub cost_pre_decode: u64,
    pub program: Vec<u8>,
    pub witness: Vec<u8>,
    pub cells: usize,
    pub frames: usize,
}

pub fn environment(
    tx: &Transaction,
    utxos: &[TxOut],
    ix: u32,
    cmr: &[u8; 32],
    control: &ControlBlock,
    genesis: BlockHash,
) -> ElementsEnv<Arc<Transaction>> {
    ElementsEnv::new(
        Arc::new(tx.clone()),
        utxos
            .iter()
            .map(|u| ElementsUtxo::from(u.clone()))
            .collect(),
        ix,
        Cmr::from_byte_array(*cmr),
        control.clone(),
        None,
        genesis,
    )
}

impl Program {
    pub fn load(path: &str) -> Program {
        let text = std::fs::read_to_string(path).expect("read program");
        Self::from_str(&text).expect("parse program")
    }

    pub fn from_str(text: &str) -> Result<Program, String> {
        Forest::parse::<Elements>(text)
            .map(Program::Text)
            .map_err(|e| format!("program: {}", e))
    }

    /// The commitment Merkle root: the program's taproot leaf script.
    pub fn try_cmr(&self) -> Result<[u8; 32], String> {
        match self {
            Self::Encoded(node) => Ok(node.cmr().to_byte_array()),
            Self::Text(forest) => simplicity::types::Context::with_context(|ctx| {
                forest
                    .to_witness_node(&ctx, &HashMap::new())
                    .ok_or_else(|| "program has no main".to_string())
                    .map(|node| node.cmr().to_byte_array())
            }),
        }
    }

    /// Canonical Simplicity decoding checks both types and witness encoding.
    pub fn from_encoded(program: &[u8], witness: &[u8]) -> Result<Program, String> {
        RedeemNode::decode::<_, _, Elements>(BitIter::from(program), BitIter::from(witness))
            .map(Program::Encoded)
            .map_err(|e| format!("compiled program: {}", e))
    }

    /// Transaction-independent proof preparation. No pruning or execution happens here.
    pub fn compile(&self, wmap: &HashMap<Arc<str>, Value>) -> Result<(Vec<u8>, Vec<u8>), String> {
        let node = match self {
            Self::Encoded(node) => node.clone(),
            Self::Text(forest) => simplicity::types::Context::with_context(|ctx| {
                forest
                    .to_witness_node(&ctx, wmap)
                    .ok_or_else(|| "program has no main".to_string())?
                    .finalize_unpruned()
                    .map_err(|e| format!("compile program: {}", e))
            })?,
        };
        Ok(node.to_vec_with_witness())
    }

    pub fn cmr(&self) -> [u8; 32] {
        self.try_cmr().expect("program has main")
    }

    pub fn execute(
        &self,
        env: &ElementsEnv<Arc<Transaction>>,
        wmap: &HashMap<Arc<str>, Value>,
    ) -> Result<Report, (&'static str, String)> {
        let program: Arc<RedeemNode> = match self {
            Self::Encoded(node) => node.prune(env).map_err(|e| ("finalize", e.to_string()))?,
            Self::Text(forest) => simplicity::types::Context::with_context(|ctx| {
                let node = forest
                    .to_witness_node(&ctx, wmap)
                    .ok_or(("parse", "no main".to_string()))?;
                node.finalize_pruned(env)
                    .map_err(|e| ("finalize", e.to_string()))
            })?,
        };
        let mut mac = BitMachine::for_program(&program).map_err(|e| ("machine", e.to_string()))?;
        mac.exec(&program, env)
            .map_err(|e| ("exec", e.to_string()))?;
        let (p, w) = program.to_vec_with_witness();
        let decoded = RedeemNode::decode::<_, _, Elements>(
            BitIter::from(p.iter().cloned()),
            BitIter::from(w.iter().cloned()),
        )
        .map_err(|e| ("decode", e.to_string()))?;
        if decoded.cmr() != program.cmr() {
            return Err(("decode", "the CMR changed in the round trip".to_string()));
        }
        let mut mac = BitMachine::for_program(&decoded).map_err(|e| ("machine", e.to_string()))?;
        mac.exec(&decoded, env)
            .map_err(|e| ("exec2", e.to_string()))?;
        let bounds = decoded.bounds();
        Ok(Report {
            cost: bounds.cost.to_string().parse().unwrap(),
            cost_pre_decode: program.bounds().cost.to_string().parse().unwrap(),
            program: p,
            witness: w,
            cells: bounds.extra_cells,
            frames: bounds.extra_frames,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness;

    #[test]
    fn compiled_witness_round_trip_preserves_cmr_and_bytes() {
        let program =
            Program::from_str("w := witness : 1 -> 2\nmain := comp (w) (jet_verify)\n").unwrap();
        let map = witness::try_map(&serde_json::json!({"w": {"bit": 1}})).unwrap();
        let (code, wit) = program.compile(&map).unwrap();
        let decoded = Program::from_encoded(&code, &wit).unwrap();
        assert_eq!(decoded.try_cmr().unwrap(), program.try_cmr().unwrap());
        assert_eq!(decoded.compile(&HashMap::new()).unwrap(), (code, wit));
    }

    #[test]
    fn malformed_compiled_program_is_an_error() {
        assert!(Program::from_encoded(&[], &[]).is_err());
        assert!(Program::from_encoded(&[0xff], &[0xff]).is_err());
        assert!(Program::from_str("this is not a program").is_err());
    }
}
