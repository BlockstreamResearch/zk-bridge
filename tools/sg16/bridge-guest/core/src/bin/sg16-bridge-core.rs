// sg16-bridge-core: encode/decode the bridge guest's public values (cross-check for tools/sg16/bridge-guest/liquid.py).
//
//   sg16-bridge-core encode <in.json>   {config, escrow, slot_key, prev_lc, new_lc, slot_value, execution_state_root,
//                                        execution_block_number, new_head} -> {public_values, public_input}
//   sg16-bridge-core decode <hex>       -> the fields
//   sg16-bridge-core lc <slot> <header> <committee>
//   sg16-bridge-core config <genesis_root> <forks encoding hex>
use serde_json::{json, Value as J};
use sg16_bridge_core::{config_hash, lc, UpdateOutputs};

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert!(s.len() % 2 == 0, "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn b32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

fn fields(o: &UpdateOutputs) -> J {
    json!({"config": hx(&o.config), "escrow": hx(&o.escrow), "slot_key": hx(&o.slot_key), "prev_lc": hx(&o.prev_lc),
           "new_lc": hx(&o.new_lc), "slot_value": hx(&o.slot_value), "execution_state_root": hx(&o.execution_state_root),
           "execution_block_number": o.execution_block_number, "new_head": o.new_head})
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = match args.first().map(String::as_str) {
        Some("encode") => {
            let j: J = serde_json::from_str(&std::fs::read_to_string(&args[1]).expect("read"))
                .expect("json");
            let s = |k: &str| {
                j[k].as_str()
                    .unwrap_or_else(|| panic!("{} missing", k))
                    .to_string()
            };
            let o = UpdateOutputs {
                config: b32(&s("config")),
                escrow: unhex(&s("escrow")).try_into().expect("20-byte escrow"),
                slot_key: b32(&s("slot_key")),
                prev_lc: b32(&s("prev_lc")),
                new_lc: b32(&s("new_lc")),
                slot_value: b32(&s("slot_value")),
                execution_state_root: b32(&s("execution_state_root")),
                execution_block_number: j["execution_block_number"]
                    .as_u64()
                    .expect("execution_block_number"),
                new_head: j["new_head"].as_u64().expect("new_head"),
            };
            let pv = o.encode();
            json!({"public_values": hx(&pv), "public_input": hx(&o.public_input()), "fields": fields(&o)})
        }
        Some("decode") => match UpdateOutputs::decode(&unhex(&args[1])) {
            Ok(o) => json!({"ok": true, "fields": fields(&o)}),
            Err(e) => json!({"ok": false, "error": e}),
        },
        Some("lc") => {
            json!({"lc": hx(&lc(args[1].parse().expect("slot"), &b32(&args[2]), &b32(&args[3])))})
        }
        Some("config") => json!({"config": hx(&config_hash(&b32(&args[1]), &unhex(&args[2])))}),
        _ => {
            eprintln!("usage: sg16-bridge-core encode <in.json> | decode <hex> | lc <slot> <header> <committee> | config <genesis_root> <forks hex>");
            std::process::exit(2);
        }
    };
    println!("{}", out);
}
