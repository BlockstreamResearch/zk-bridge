// sg16: run the generated update leaf (tools/sg16/bridge-guest/liquid.py) in realistic Elements transactions.
//
//   sg16 consts <config.json>
//       the constants the generator compiles in: bridge asset, reissuance token, the two public token
//       commitments, the token's value commitment, fee asset, genesis (JSON)
//   sg16 run <program.simpl> <cases.json>
//       for every case: build the honest transaction, apply its mutations, prune the program against it,
//       execute, round-trip the encoding and execute again; report one JSON line with the outcome, the
//       cost bound, sizes, the input's budget, the full transaction weight and whether Elements' amount,
//       surjection and range proofs verify (rust-elements verify_tx_amt_proofs)
//
// cases.json: {"config": CONFIG, "cases": [{"name", "expect": "ok"|"fail", "witness": {"w_in": VALUE, ...},
//              "tx": TX, "mutations": [names]}]}, the witness by node name (w_in, then the update leaf's wl0..wl87 and
//              wq); see src/bridge.rs for CONFIG, TX and the mutations.
use serde_json::{json, Value as Json};
use sg16_harness::bridge::{self, stack_bytes, Config, Plan};
use sg16_harness::program::{environment, Program};
use sg16_harness::witness::{self, hex};
use simplicity::elements::secp256k1_zkp::Secp256k1;
use simplicity::elements::Witness;

const USAGE: &str = "usage: sg16 consts <config.json> | run <program.simpl> <cases.json>";

fn read_json(path: &str) -> Json {
    serde_json::from_str(
        &std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {}", path, e)),
    )
    .expect("json")
}

fn plan_of(cfg: &Config, case: &Json) -> Plan {
    let mut plan = Plan::honest(cfg, &case["tx"]);
    for m in case["mutations"]
        .as_array()
        .map(|v| v.as_slice())
        .unwrap_or(&[])
    {
        plan.mutate(m.as_str().expect("mutation name"));
    }
    plan
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("consts") if args.len() == 2 => {
            let cfg = Config::from_json(&read_json(&args[1]));
            println!("{}", cfg.constants());
        }
        Some("run") if args.len() == 3 => run(&args[1], &args[2]),
        _ => {
            eprintln!("{}", USAGE);
            std::process::exit(2);
        }
    }
}

fn run(program_path: &str, cases_path: &str) {
    let file = read_json(cases_path);
    let cfg = Config::from_json(&file["config"]);
    let program = Program::load(program_path);
    let cmr = program.cmr();
    println!(
        "{}",
        json!({"cmr": hex(&cmr), "constants": cfg.constants()})
    );
    let secp = Secp256k1::new();
    for case in file["cases"].as_array().expect("cases") {
        let t0 = std::time::Instant::now();
        let plan = plan_of(&cfg, case);
        let mut built = bridge::build(&cfg, &plan, &cmr);
        let amounts = built.tx.verify_tx_amt_proofs(&secp, &built.utxos);
        let env = environment(
            &built.tx,
            &built.utxos,
            built.ix,
            &cmr,
            &built.control,
            built.genesis,
        );
        let wmap = witness::map(&case["witness"]);
        let mut out = json!({
            "name": case["name"],
            "expect": case["expect"],
            "mutations": case["mutations"],
            "amounts_valid": amounts.is_ok(),
            "amounts_error": amounts.err().map(|e| format!("{:?}", e)),
        });
        match program.execute(&env, &wmap) {
            Ok(r) => {
                let control = built.control.serialize();
                let items = vec![r.witness.clone(), r.program.clone(), cmr.to_vec(), control];
                let stack = stack_bytes(&items);
                built.tx.input[built.ix as usize].witness.script_witness =
                    Witness::from_slice(&items);
                let budget = (stack as u64 + 50) * 1000;
                let o = out.as_object_mut().unwrap();
                o.insert("ok".into(), json!(true));
                o.insert("cost".into(), json!(r.cost));
                o.insert("cost_pre_decode".into(), json!(r.cost_pre_decode));
                o.insert("program_bytes".into(), json!(r.program.len()));
                o.insert("witness_bytes".into(), json!(r.witness.len()));
                o.insert("stack_bytes".into(), json!(stack));
                o.insert("budget".into(), json!(budget));
                o.insert("budget_ok".into(), json!(r.cost <= budget));
                o.insert("tx_weight".into(), json!(built.tx.weight()));
                o.insert("tx_inputs".into(), json!(built.tx.input.len()));
                o.insert("tx_outputs".into(), json!(built.tx.output.len()));
                o.insert("cells".into(), json!(r.cells));
                o.insert("frames".into(), json!(r.frames));
            }
            Err((stage, error)) => {
                let o = out.as_object_mut().unwrap();
                o.insert("ok".into(), json!(false));
                o.insert("stage".into(), json!(stage));
                o.insert("error".into(), json!(error));
            }
        }
        out.as_object_mut()
            .unwrap()
            .insert("seconds".into(), json!(t0.elapsed().as_secs_f64()));
        println!("{}", out);
    }
}
