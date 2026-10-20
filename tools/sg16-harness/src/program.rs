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

/// A program in the human-readable encoding the generator writes, parsed once (slow for the full verifier).
pub struct Program(Forest);

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
        let t0 = std::time::Instant::now();
        let text = std::fs::read_to_string(path).expect("read program");
        let forest = Forest::parse::<Elements>(&text).expect("parse");
        eprintln!("loaded {} in {:.1}s", path, t0.elapsed().as_secs_f64());
        Program(forest)
    }

    /// The commitment Merkle root: the program's taproot leaf script.
    pub fn cmr(&self) -> [u8; 32] {
        simplicity::types::Context::with_context(|ctx| {
            self.0
                .to_witness_node(&ctx, &HashMap::new())
                .expect("no main")
                .cmr()
                .to_byte_array()
        })
    }

    pub fn execute(
        &self,
        env: &ElementsEnv<Arc<Transaction>>,
        wmap: &HashMap<Arc<str>, Value>,
    ) -> Result<Report, (&'static str, String)> {
        let program: Arc<RedeemNode> = simplicity::types::Context::with_context(|ctx| {
            let node = self
                .0
                .to_witness_node(&ctx, wmap)
                .ok_or(("parse", "no main".to_string()))?;
            node.finalize_pruned(env)
                .map_err(|e| ("finalize", e.to_string()))
        })?;
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
