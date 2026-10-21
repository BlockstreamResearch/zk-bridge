# Self-service proving and claiming of finalized deposits (OPERATOR.md, "Taking over a stalled deposit").
#
# Each recipe belongs to one group, which says what it may touch:
#   read       public reads (Esplora, Sepolia RPC); writes only under BRIDGE_WORK
#   build      local compilation; the network only for crates, pinned deps and the SP1 Docker image
#   prove      Sepolia RPC reads and local SP1 execution or proving
#   key        creates or reads the fee key file
#   sign       builds and signs Liquid transactions into BRIDGE_WORK; sends nothing
#   assemble   builds an unsigned Liquid update or claim against an open Humid fee coin; sends nothing
#   publish    writes the instance's light-client store files in the working tree; no git, no upload
#   deploy     prepares a new instance under DEPLOY_WORK and writes its record; only deploy-escrow sends, to
#              Sepolia, after a simulation and a confirmation prompt
#   broadcast  sends one signed file to Esplora, after its checks and a confirmation prompt
#
# Settings come from the environment or `just NAME=value <recipe>`. RPC URLs are read only from the
# environment, by the tools, and no recipe prints them. `just config` shows what is in effect.

set dotenv-load := false
set export

# The instance directory; its instance.json pins the escrow, deployment block and guest. The default is the
# instance the published site serves (bridge-core/config.js INSTANCE). Every chain walk prints which one it targets.
BRIDGE_INSTANCE := env("BRIDGE_INSTANCE", "instances/sepolia-liquid-testnet")
# Optional cross-check: if set, it must equal the instance's ESCROW. The escrow always comes from the instance.
BRIDGE_ESCROW := env("BRIDGE_ESCROW", "")
# Where recovered state, proofs and transactions are written. Keep it under the ignored target/.
BRIDGE_WORK := env("BRIDGE_WORK", "target/takeover")
# Light-client preimages for `recover`. Set it empty to recover without them (enough to claim, not to update).
BRIDGE_HINT := env("BRIDGE_HINT", BRIDGE_INSTANCE / "lc_preimages.json")
BRIDGE_ELF := env("BRIDGE_ELF", BRIDGE_WORK / "elf/sg16-bridge-program")
# The live head's store as `just reconstruct` rebuilds it when the update reaching that head published none.
# `recover` tries it after BRIDGE_HINT, and uses it only if it hashes to the live lc.
REBUILT_STORE := BRIDGE_WORK / "reconstructed.store.json"
LIQUID_ESPLORA := env("LIQUID_ESPLORA", "https://blockstream.info/liquidtestnet/api")
# Path of the Liquid testnet fee key file. No default: signing recipes refuse to run without it.
LIQUID_FEE_KEY := env("LIQUID_FEE_KEY", "")
# Public base URL serving this instance directory, e.g. the Pages site's instances/<name>. An update is
# broadcast only after its store file and lc_preimages.json are read back from here.
STORE_READBACK_URL := env("STORE_READBACK_URL", "")
# Fee slots and split fee, in sats: the costs recorded so far (OPERATOR.md), not minimums.
FEE_UPDATE_SATS := env("FEE_UPDATE_SATS", "12000")
FEE_CLAIM_SATS := env("FEE_CLAIM_SATS", "2000")
SPLIT_FEE_SATS := env("SPLIT_FEE_SATS", "300")
# Initial maximum; bridge-operator reduces it automatically when an RPC enforces a smaller eth_getLogs range.
DEPOSIT_LOG_STEP := env("DEPOSIT_LOG_STEP", "2000")
# Delay between Sepolia RPC requests; bridge-operator increases it if the provider rate-limits.
DEPOSIT_LOG_PACE := env("DEPOSIT_LOG_PACE", "250")
WAIT_SECONDS := env("WAIT_SECONDS", "30")
WAIT_TRIES := env("WAIT_TRIES", "60")

# Deployment of a new instance (the deploy group, OPERATOR.md "Deploying the instance"). Fixed: foundry.toml lets
# the deployment script read and write this directory and no other.
DEPLOY_WORK := "target/deploy"
# The deployer's Sepolia address, and its encrypted key, one of two ways: DEPLOY_ACCOUNT, the name of a keystore in
# Foundry's own directory as `cast wallet list` shows it (cast asks for its password); or DEPLOY_KEYSTORE, a keystore
# file, with DEPLOY_PASSWORD_FILE, a file holding its password, both outside Git (under the ignored target/ or
# outside the repository). Only cast and forge read the password, from the file; no recipe prints it.
DEPLOYER := env("DEPLOYER", "")
DEPLOY_ACCOUNT := env("DEPLOY_ACCOUNT", "")
DEPLOY_KEYSTORE := env("DEPLOY_KEYSTORE", "")
DEPLOY_PASSWORD_FILE := env("DEPLOY_PASSWORD_FILE", "")
# The guest build the new instance pins: `just prover` from this checkout (SP1 6.8.1, Docker image v6.8.1).
# deploy-record refuses an ELF that does not give exactly these.
DEPLOY_GUEST_ELF_SHA256 := "51e486a3dd022dfd75a798a793cbca738324d558ce0ace8affde8a85e27aeabd"
DEPLOY_PROGRAM_VKEY := "002a725145d840f50eb445417d03eeb9070ffee307180d2d0e6eba0d77354962"
# Sepolia's Amsterdam fork charges state gas for deployed bytecode. Foundry's Prague simulator omits it, so use a
# larger transaction limit and compare it with eth_estimateGas on Sepolia before signing.
DEPLOY_GAS_MULTIPLIER := "800"

ASSEMBLE_PY := "tools/sg16/bridge-guest/testnet/assemble.py"
TX_BIN := "tools/sg16/bridge-guest/target/testnet-tx/release/sg16-testnet"
WALLET_BIN := "tools/sg16/liquid-testnet-wallet/target/release/sg16-liquid-testnet-wallet"
BRIDGE_HOST_BIN := "tools/sg16/bridge-guest/target/release/sg16-bridge-host"
OPERATOR_BIN := "tools/bridge-operator/target/release/bridge-operator"

# Shell helpers shared by the recipes below. Values reach them only as environment variables, never by
# interpolation into the script text.
_prelude := '''
    set -euo pipefail
    die() { printf 'error: %s\n' "$*" >&2; exit 1; }
    need() { [ -e "$1" ] || die "$1 is missing${2:+; $2}"; }
    need_env() { [ -n "${!1:-}" ] || die "set $1 to $2; it is read from the environment and never printed"; }
    need_key() {
      [ -n "$LIQUID_FEE_KEY" ] || die "set LIQUID_FEE_KEY to your Liquid testnet fee key file (just fee-key-new creates one)"
      need "$LIQUID_FEE_KEY"
    }
    hex32() { [[ "$1" =~ ^[0-9a-f]{64}$ ]] || die "$2 must be 64 lowercase hex characters, got '$1'"; }
    jget() {  # jget <file|-> <key>...: one JSON value; a list prints one item per line, null prints nothing
      python3 -c '
    import json, sys
    path, keys = sys.argv[1], sys.argv[2:]
    v = json.load(sys.stdin if path == "-" else open(path))
    try:
        for k in keys:
            v = v[int(k)] if isinstance(v, list) else v[k]
    except (KeyError, IndexError, ValueError):
        sys.exit(f"{path}: no {keys}")
    if isinstance(v, list):
        print("\n".join(map(str, v)))
    elif isinstance(v, bool):
        print(str(v).lower())
    elif v is not None:
        print(v)
    ' "$@"
    }
    escrow() {
      python3 -c '
    import json, sys
    pinned = json.load(open(sys.argv[1]))["ESCROW"].lower().removeprefix("0x")
    given = sys.argv[2].lower().removeprefix("0x")
    if given and given != pinned:
        sys.exit(f"BRIDGE_ESCROW 0x{given} is not the escrow {sys.argv[1]} pins, 0x{pinned}")
    print("0x" + pinned)
    ' "$BRIDGE_INSTANCE/instance.json" "$BRIDGE_ESCROW"
    }
    site() {  # whether the published site serves BRIDGE_INSTANCE: "served", or "not served: <every difference>"
      # Served means all of bridge-core/config.js INSTANCE: BRIDGE_INSTANCE is its record directory instances/<name>, and that
      # directory's escrow, code hash, bootstrap txid and manifest state address are the ones the page pins. An
      # escrow alone does not decide it: a copied or edited record with the same escrow is not what Pages publishes.
      local e b=""; e=$(escrow)
      [ ! -f "$BRIDGE_INSTANCE/bootstrap.hex" ] || b=$(txid_of "$BRIDGE_INSTANCE/bootstrap.hex") || b=""
      node --input-type=module - "$BRIDGE_INSTANCE" "$e" "$b" <<'JS' || die "could not compare $BRIDGE_INSTANCE with bridge-core/config.js INSTANCE"
    import { existsSync, readFileSync, realpathSync } from 'node:fs';
    const [dir, escrow, bootstrap] = process.argv.slice(2);
    const { INSTANCE } = await import('./bridge-core/config.js');
    if (INSTANCE === null) { console.log('not served: the published site serves no instance'); process.exit(0); }
    const read = (f) => { try { return JSON.parse(readFileSync(`${dir}/${f}`, 'utf8')); } catch { return {}; } };
    const record = `instances/${INSTANCE.name}`;
    const short = (h) => (h ? `${h.slice(0, 10)}…` : 'none');
    const differ = [];
    if (escrow !== INSTANCE.escrow.toLowerCase()) differ.push(`escrow ${escrow} is not the site's ${INSTANCE.escrow.toLowerCase()}`);
    if (!existsSync(record) || !existsSync(dir) || realpathSync(dir) !== realpathSync(record)) differ.push(`directory is not ${record}`);
    const code = String(read('instance.json').ESCROW_CODE_HASH ?? '').toLowerCase().replace(/^0x/, '');
    if (code !== INSTANCE.codeHash) differ.push(`escrow code hash ${short(code)} is not the site's ${short(INSTANCE.codeHash)}`);
    if (bootstrap !== INSTANCE.bootstrap) differ.push(`bootstrap ${short(bootstrap)} is not the site's ${short(INSTANCE.bootstrap)}`);
    if (read('manifest.json').state_tree?.address !== INSTANCE.state) differ.push("manifest state address is not the site's");
    console.log(differ.length ? `not served: ${differ.join('; ')}` : 'served');
    JS
    }
    site_name() {  # the record the published site serves, instances/<name>, or "no instance"
      node --input-type=module -e '
    const { INSTANCE } = await import("./bridge-core/config.js");
    console.log(INSTANCE === null ? "no instance" : `instances/${INSTANCE.name}`);
    ' || die "could not read the site's instance from bridge-core/config.js"
    }
    target() {  # one line: the instance and escrow this recipe acts on, and whether the published site serves them
      local e s; e=$(escrow); s=$(site)
      if [ "$s" = served ]; then
        echo "target: $BRIDGE_INSTANCE, escrow $e (the published site's current instance)"
      else
        echo "target: $BRIDGE_INSTANCE, escrow $e (${s}; the published site serves only $(site_name))"
      fi
    }
    claim_refused() {  # after assemble.py claim fails: identify the escrow and the failed gate
      gate "$BRIDGE_WORK/claim.assemble.json"
      die "assemble.py claim refused for escrow $(escrow) ($BRIDGE_INSTANCE); run just status <deposit number> ($BRIDGE_WORK/claim.assemble.json)"
    }
    esplora() { curl -fsS --retry 3 "$LIQUID_ESPLORA/$1" || die "Esplora GET $1 failed"; }
    outspend() {  # "<txid> <vin> <confirmed>" of the spend of output $2 (default 0) of $1; nothing if unspent
      local o; o=$(esplora "tx/$1/outspend/${2:-0}")
      python3 -c '
    import json, re, sys
    o = json.loads(sys.argv[1])
    if type(o.get("spent")) is not bool:  # a reply without the flag must not read as unspent
        sys.exit("Esplora supplied no spent flag")
    if o["spent"]:
        txid, vin = o.get("txid"), o.get("vin")
        if not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid) or type(vin) is not int or vin < 0:
            sys.exit("Esplora supplied an invalid outspend txid or input index")
        print(txid, vin, str(o.get("status", {}).get("confirmed", False)).lower())
    ' "$o"
    }
    check_funding() {  # the asset's issuance input must still exist when the escrow is deployed
      local funding txid vout spent asset f
      need "$DEPLOY_WORK/escrow-params.json" "run: just deploy-params"
      need "$DEPLOY_WORK/asset.json" "run: just deploy-asset"
      funding=$(jget "$DEPLOY_WORK/escrow-params.json" funding) || die "cannot read the funding outpoint"
      [[ "$funding" =~ ^[0-9a-f]{64}:(0|[1-9][0-9]*)$ ]] || die "invalid funding outpoint in escrow parameters"
      [ "$funding" = "$(jget "$DEPLOY_WORK/asset.json" result funding)" ] \
        || die "escrow parameters and asset report name different funding outpoints"
      asset=$(jget "$DEPLOY_WORK/escrow-params.json" bridgeAsset)
      [ "$asset" = "$(jget "$DEPLOY_WORK/asset.json" result bridge_asset_internal)" ] \
        || die "escrow parameters and asset report name different assets"
      txid=${funding%:*}; vout=${funding#*:}
      confirmed "$txid" || die "funding transaction $txid is not confirmed"
      # Esplora reports any output index it has never seen, existing or not, as unspent.
      f=$(tx_file "$txid") || die "could not fetch funding transaction $txid"
      tx_report output "$f" "$vout" > /dev/null || die "could not confirm that funding transaction $txid has an output $vout"
      spent=$(outspend "$txid" "$vout") || die "could not check whether funding output $funding is unspent"
      [ -z "$spent" ] || die "funding output $funding is spent by ${spent%% *}; do not deploy this escrow"
    }
    check_deploy_gas() {
      python3 - "$DEPLOY_WORK/simulation.json" \
        "$DEPLOY_WORK/broadcast/DeployBridgeEscrow.s.sol/11155111/dry-run/run-latest.json" <<'PY'
    import json
    import os
    import sys
    import urllib.request

    simulation = json.load(open(sys.argv[1]))
    run = json.load(open(sys.argv[2]))
    transactions = run.get("transactions", [])
    if len(transactions) != 1:
        sys.exit("the dry run must contain exactly one escrow deployment")
    transaction = transactions[0]
    if transaction.get("contractAddress", "").lower() != simulation["escrow"].lower():
        sys.exit("the dry-run transaction does not create the simulated escrow")
    call = transaction["transaction"]
    limit = int(call["gas"], 16)
    request_body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_estimateGas",
        "params": [{"from": call["from"], "data": call["input"]}],
    }).encode()
    try:  # Request too: its error for a malformed URL would print the URL, and any key in it
        request = urllib.request.Request(
            os.environ["SEPOLIA_EXECUTION_RPC"], request_body,
            {"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.load(response)
        required = int(result["result"], 16)
    except (OSError, KeyError, ValueError, TypeError):
        sys.exit("Sepolia eth_estimateGas failed; deployment gas is not verified")
    if required <= 0 or limit * 85 < required * 100:
        sys.exit(f"transaction limit {limit:,} has less than 15% headroom over Sepolia's {required:,} gas estimate")
    print(f"Sepolia deployment gas: {required:,} estimated, {limit:,} limit")
    PY
    }
    anchor_store() {  # the anchor's starting store, rebuilt offline from the anchor inputs, into DEPLOY_WORK/anchor.store.json
      local head lc
      need "$DEPLOY_WORK/anchor-inputs.cbor" "run: just deploy-anchor"
      need "$DEPLOY_WORK/anchor.json" "run: just deploy-anchor"
      head=$(jget "$DEPLOY_WORK/anchor.json" anchor slot); lc=$(jget "$DEPLOY_WORK/anchor.json" anchor lc)
      rm -f "$DEPLOY_WORK/anchor.store.json" "$DEPLOY_WORK/anchor.reconstruct.json" "$DEPLOY_WORK/anchor.check-store.json"
      "$BRIDGE_HOST_BIN" reconstruct --head "$head" --lc "$lc" --source "$DEPLOY_WORK/anchor-inputs.cbor" --offline \
          --out "$DEPLOY_WORK/anchor.store.json" > "$DEPLOY_WORK/anchor.reconstruct.json" \
        || die "sg16-bridge-host reconstruct did not rebuild the store of anchor slot $head from $DEPLOY_WORK/anchor-inputs.cbor"
      "$BRIDGE_HOST_BIN" check-store "$DEPLOY_WORK/anchor.store.json" --lc "$lc" > "$DEPLOY_WORK/anchor.check-store.json" \
        || die "$DEPLOY_WORK/anchor.store.json does not hash to the anchor lc $lc"
      [ "$(jget "$DEPLOY_WORK/anchor.check-store.json" head)" = "$head" ] \
        || die "$DEPLOY_WORK/anchor.store.json is not at the anchor slot $head"
    }
    confirmed() {
      local status
      status=$(esplora "tx/$1/status") || return 1
      [ "$(jget - confirmed <<< "$status")" = true ]
    }
    gate() { python3 -c '
    import json, sys
    try:
        doc = json.load(open(sys.argv[1]))
    except (OSError, ValueError):
        print("no JSON gate report; see the preceding error", file=sys.stderr)
    else:
        print("failed gate:", doc.get("failed_gate", "not named"), file=sys.stderr)
    ' "$1"; }
    check_artifact() {
      need "$BRIDGE_WORK/proof.json" "run: just prove"
      need "$BRIDGE_WORK/state.json" "run: just recover"
      rm -f "$BRIDGE_WORK/check-artifact.json"
      if ! python3 "$ASSEMBLE_PY" check-artifact --report "$BRIDGE_WORK/check-artifact.json" \
          --instance "$BRIDGE_INSTANCE/instance.json" --artifact "$BRIDGE_WORK/proof.json" \
          --state "$BRIDGE_WORK/state.json" > "$BRIDGE_WORK/check-artifact.log"; then
        gate "$BRIDGE_WORK/check-artifact.json"
        die "the proof does not fit the instance or the state ($BRIDGE_WORK/check-artifact.json; details in $BRIDGE_WORK/check-artifact.log)"
      fi
      proof_block=$(jget "$BRIDGE_WORK/check-artifact.json" result exec_block) \
        || die "$BRIDGE_WORK/check-artifact.json does not name a proved execution block"
      [[ "$proof_block" =~ ^[0-9]+$ ]] || die "$BRIDGE_WORK/check-artifact.json has an invalid proved execution block"
      echo "proof accepted: proves through Sepolia block $proof_block"
    }
    check_inputs() {  # refuse inputs.cbor unless it starts from the recovered state and reads this escrow's slot 0
      need "$BRIDGE_WORK/inputs.cbor" "run: just inputs"
      need "$BRIDGE_WORK/state.json" "run: just inputs"
      "$BRIDGE_HOST_BIN" anchor "$BRIDGE_WORK/inputs.cbor" > "$BRIDGE_WORK/inputs.anchor.json" \
        || die "$BRIDGE_WORK/inputs.cbor does not decode as proof inputs; run just inputs"
      # A proof takes hours; inputs left from an earlier state or another instance would only be refused after it.
      python3 - "$BRIDGE_WORK/inputs.anchor.json" "$BRIDGE_WORK/state.json" "$(escrow)" <<'PY' \
        || die "$BRIDGE_WORK/inputs.cbor is not for the recovered state of $BRIDGE_INSTANCE; run just inputs again"
    import json, sys
    sys.path.insert(0, "tools/sg16/bridge-guest/testnet")
    import pins
    summary, state, escrow = json.load(open(sys.argv[1])), json.load(open(sys.argv[2])), sys.argv[3]
    hx = lambda h: str(h).lower().removeprefix("0x")
    a, net, storage = summary["anchor"], summary["network"], summary["storage"]
    bad = []
    if (a["slot"], hx(a["lc"])) != (state["head"], hx(state["lc"])):
        bad.append(f"they start at slot {a['slot']}, lc {hx(a['lc'])}; the state is at slot {state['head']}, lc {hx(state['lc'])}")
    if not net["is_sepolia"] or hx(net["config"]) != pins.SEPOLIA_CONFIG:
        bad.append(f"their network (config {hx(net['config'])}) is not Sepolia's, pins.py SEPOLIA_CONFIG")
    reads = [(hx(c["address"]), [int(s["key"], 16) for s in c["slots"]]) for c in storage]
    if reads != [(hx(escrow), [pins.SLOT_KEY])]:
        bad.append(f"they read {reads}, not slot {pins.SLOT_KEY} of escrow {escrow} alone")
    if bad:
        sys.exit("the inputs do not fit:\n  " + "\n  ".join(bad))
    print(f"inputs start from the state at slot {a['slot']} and read escrow {escrow} at finalized slot "
          f"{summary['target_finalized_slot']}")
    PY
    }
    tx_report() {  # tx_report <command> <arg>...: the sg16-testnet report; a refusal prints its failed gate and fails
      need "$TX_BIN" "run: just tools"
      local r; r=$("$TX_BIN" "$@") && { printf '%s\n' "$r"; return; }
      printf 'sg16-testnet %s refused: %s\n' "$1" "$(jget - failed_gate <<< "$r" 2>/dev/null || printf '%s' "$r")" >&2
      return 1
    }
    txid_of() {  # the Elements txid of hex file $1, computed locally by sg16-testnet txid
      local r; r=$(tx_report txid "$1") || return 1
      jget - txid <<< "$r"
    }
    check_txid() {  # check_txid <file> <txid>: refuse unless the file's bytes are transaction <txid>
      local got; got=$(txid_of "$1") || die "$1 does not parse as an Elements transaction"
      [ "$got" = "$2" ] || die "$1 holds transaction $got, not $2"
    }
    tx_file() {  # the local copy of transaction $1, fetched from Esplora if missing; its bytes must hash to $1
      hex32 "$1" txid
      local f="$BRIDGE_WORK/tx/$1.hex"
      if [ ! -s "$f" ]; then
        mkdir -p "$BRIDGE_WORK/tx"; esplora "tx/$1/hex" > "$f.part"
        check_txid "$f.part" "$1"
        mv "$f.part" "$f"
      fi
      check_txid "$f" "$1"
      printf '%s\n' "$f"
    }
    recover_state() {  # BRIDGE_WORK/state.json and recover.json from the chain `chain` walked (BRIDGE_WORK/spends.txt)
      need "$TX_BIN" "run: just tools"
      local spends=() hints=() f failed
      while IFS= read -r f; do spends+=(--spend "$f"); done < "$BRIDGE_WORK/spends.txt"
      [ -z "$BRIDGE_HINT" ] || hints=(--hint "$BRIDGE_HINT")
      [ ! -f "$REBUILT_STORE" ] || hints+=(--hint "$REBUILT_STORE")
      recover_with() {
        rm -f "$BRIDGE_WORK/state.json" "$BRIDGE_WORK/recover.json"
        python3 "$ASSEMBLE_PY" recover --report "$BRIDGE_WORK/recover.json" \
          --instance "$BRIDGE_INSTANCE/instance.json" --manifest "$BRIDGE_INSTANCE/manifest.json" \
          --bootstrap-tx "$BRIDGE_INSTANCE/bootstrap.hex" ${spends[@]+"${spends[@]}"} "$@" \
          --out "$BRIDGE_WORK/state.json" > "$BRIDGE_WORK/recover.log"
      }
      if ! recover_with ${hints[@]+"${hints[@]}"}; then
        failed=$(jget "$BRIDGE_WORK/recover.json" failed_gate)
        if [[ "$failed" == 'a hint is the preimage of the recovered lc:'* ]]; then
          echo "no published or rebuilt store matches the live head; recovering the record without one (enough to claim)" >&2
          if ! recover_with; then gate "$BRIDGE_WORK/recover.json"; die "recover refused without a store hint"; fi
        else
          gate "$BRIDGE_WORK/recover.json"
          rm -f "$BRIDGE_WORK/state.json"
          die "recover refused ($BRIDGE_WORK/recover.json)"
        fi
      fi
      python3 - "$BRIDGE_WORK/recover.json" "$REBUILT_STORE" <<'PY'
    import json, sys
    r, rebuilt = json.load(open(sys.argv[1]))["result"], sys.argv[2]
    s, store = r["state"], r["lc_store"]
    updates = [txid for txid, kind in r["chain"] if kind == "update"]
    print(f"recovered head {s['head']}, {len(s['claimed'])} claimed deposit(s); live state {r['outpoint']}")
    if store and r["hint"] == rebuilt:
        print(f"store: {store}, rebuilt by just reconstruct and hashing to the live lc; not published (just stage-recovered)")
    elif store:
        print(f"store: {store}")
    elif r["complete"]:
        print("store: none named for this head; its roots are known, but the next proof needs a beacon bootstrap there")
    else:
        reached = f", which update {updates[-1]} reached without publishing one" if updates else ""
        print(f"store: none published for head {s['head']}{reached}")
        print("claims work from this record; before an update, run: just reconstruct")
    PY
    }
    meta() {  # meta <file> key=value...: the sidecar that preflight and broadcast read
      python3 -c '
    import json, sys
    f, *kv = sys.argv[1:]
    m = dict(dict(state="", new_state=""), **dict(a.split("=", 1) for a in kv))
    m["parents"] = [p for p in m.get("parents", "").split(",") if p]
    json.dump(m, open(f + ".meta.json", "w"), indent=1)
    ' "$@"
    }
'''

# List the recipes by group.
default:
    @{{ quote(just_executable()) }} --justfile {{ quote(justfile()) }} --list --unsorted

# Print the settings in effect. RPC variables are reported as set or unset, never shown.
[group('read')]
config:
    #!/usr/bin/env bash
    {{ _prelude }}
    e=$(escrow)
    target
    echo "instance        $BRIDGE_INSTANCE"
    echo "escrow          $e"
    echo "work dir        $BRIDGE_WORK"
    echo "hint            ${BRIDGE_HINT:-(none)}"
    echo "guest ELF       $BRIDGE_ELF"
    echo "esplora         configured"
    echo "fee key path    ${LIQUID_FEE_KEY:-(unset)}"
    if [ -n "$STORE_READBACK_URL" ]; then echo "store readback  set"; else echo "store readback  unset"; fi
    for v in SEPOLIA_EXECUTION_RPC SEPOLIA_CONSENSUS_RPC; do
      if [ -n "${!v:-}" ]; then echo "$v set"; else echo "$v unset"; fi
    done

# Fetch the pinned vendored dependencies (network).
[group('build')]
deps:
    python3 tools/bootstrap-deps.py

# Build the assembly tools, the fee wallet and the operator commands.
[group('build')]
tools:
    cargo build --release --locked --manifest-path tools/sg16-harness/Cargo.toml
    CARGO_TARGET_DIR=tools/sg16/bridge-guest/target/testnet-tx cargo build --release --locked --manifest-path tools/sg16/bridge-guest/testnet/tx/Cargo.toml
    CARGO_TARGET_DIR=tools/sg16/bridge-guest/target/testnet-claim cargo build --release --locked --manifest-path tools/sg16/bridge-guest/testnet/claim/Cargo.toml
    cargo build --release --locked --manifest-path tools/sg16/liquid-testnet-wallet/Cargo.toml
    cargo build --release --locked --manifest-path tools/bridge-operator/Cargo.toml

# Build the prover host without Docker or the SP1 cargo-prove tool.
[group('build')]
host:
    cargo build --release --locked --manifest-path tools/sg16/bridge-guest/Cargo.toml -p sg16-bridge-host

# Build the guest ELF in the pinned SP1 Docker image (into BRIDGE_WORK/elf) and the prover host. Proof only.
[group('build')]
prover:
    #!/usr/bin/env bash
    {{ _prelude }}
    export PATH="$HOME/.sp1/bin:$PATH"
    version=$(cargo prove --version 2>/dev/null) || die "install the SP1 cargo-prove tool before building the pinned 6.8.1 guest"
    # The v6.8.1 release binary prints its Git revision rather than the tag. c84ada1 is refs/tags/v6.8.1.
    [[ "$version" == *6.8.1* || "$version" == *c84ada1* ]] || die "SP1 cargo-prove 6.8.1 is required; found $version"
    mkdir -p "$BRIDGE_WORK/elf"
    out=$(cd "$BRIDGE_WORK/elf" && pwd)
    (cd tools/sg16/bridge-guest/program && cargo prove build --docker --tag v6.8.1 --locked --workspace-directory ../../../.. --output-directory "$out")
    just host
    echo "built $out/sg16-bridge-program; next: just check-elf"

# Refuse BRIDGE_ELF unless its SHA-256 and program vkey are the instance's pins. No RPC.
[group('build')]
check-elf:
    #!/usr/bin/env bash
    {{ _prelude }}
    need "$BRIDGE_HOST_BIN" "run: just host (or just prover to build the ELF as well)"
    need "$BRIDGE_ELF" "run: just prover, or set BRIDGE_ELF"
    "$BRIDGE_HOST_BIN" vkey --elf "$BRIDGE_ELF" | python3 -c '
    import json, sys
    got, pin = json.load(sys.stdin), json.load(open(sys.argv[1]))
    norm = lambda h: str(h).lower().removeprefix("0x")
    bad = [f"{k}: ELF gives {norm(got[g])}, instance pins {norm(pin[k])}"
           for g, k in (("elf_sha256", "GUEST_ELF_SHA256"), ("vkey", "PROGRAM_VKEY")) if norm(got[g]) != norm(pin[k])]
    sys.exit("\n".join(bad)) if bad else print("ELF and vkey match", sys.argv[1])
    ' "$BRIDGE_INSTANCE/instance.json"

# Walk the state output from the bootstrap through every confirmed public spend (Esplora reads).
[group('read')]
chain:
    #!/usr/bin/env bash
    {{ _prelude }}
    target
    mkdir -p "$BRIDGE_WORK/tx"
    rm -f "$BRIDGE_WORK/spends.txt" "$BRIDGE_WORK/state-tx.path" "$BRIDGE_WORK/state-tx.txid"
    boot=$(txid_of "$BRIDGE_INSTANCE/bootstrap.hex") || die "the instance's bootstrap does not parse as an Elements transaction"
    [ "$(esplora "tx/$boot/hex" | tr -d '[:space:]')" = "$(tr -d '[:space:]' < "$BRIDGE_INSTANCE/bootstrap.hex")" ] \
      || die "Esplora's transaction $boot differs from $BRIDGE_INSTANCE/bootstrap.hex"
    t=$boot; n=0; : > "$BRIDGE_WORK/spends.txt.part"
    while :; do
      r=$(outspend "$t")
      [ -n "$r" ] || break
      set -- $r
      [ "$2" = 0 ] || die "output 0 of $t is spent by input $2 of $1; a state spend uses input 0"
      [ "$3" = true ] || die "$1 spends the state but is unconfirmed; run just wait $1, then this again"
      f=$(tx_file "$1")
      echo "$f" >> "$BRIDGE_WORK/spends.txt.part"
      t=$1; n=$((n + 1))
    done
    mv "$BRIDGE_WORK/spends.txt.part" "$BRIDGE_WORK/spends.txt"
    if [ "$t" = "$boot" ]; then st="$BRIDGE_INSTANCE/bootstrap.hex"; else st="$BRIDGE_WORK/tx/$t.hex"; fi
    echo "$st" > "$BRIDGE_WORK/state-tx.path"
    echo "$t" > "$BRIDGE_WORK/state-tx.txid"
    echo "$n confirmed state spend(s) after bootstrap $boot; the live state is output 0 of $t"

# Print the Elements txid of a transaction hex file, computed locally; with <expect>, refuse any other. No network.
[group('read')]
txid file expect='':
    #!/usr/bin/env bash
    {{ _prelude }}
    need "$file"
    if [ -n "$expect" ]; then check_txid "$file" "$expect"; fi
    txid_of "$file" || die "$file does not parse as an Elements transaction"

# Rebuild the live state record (BRIDGE_WORK/state.json) from the public chain.
[group('read')]
recover: chain
    #!/usr/bin/env bash
    {{ _prelude }}
    recover_state

# Write the escrow's Deposit events up to the finalized block (needs SEPOLIA_EXECUTION_RPC).
[group('read')]
deposits:
    #!/usr/bin/env bash
    {{ _prelude }}
    need_env SEPOLIA_EXECUTION_RPC "a Sepolia execution RPC serving eth_getLogs and eth_call"
    need "$OPERATOR_BIN" "run: just tools"
    e=$(escrow)
    from=$(jget "$BRIDGE_INSTANCE/instance.json" ESCROW_DEPLOY_BLOCK)
    mkdir -p "$BRIDGE_WORK"
    rm -f "$BRIDGE_WORK/deposits.report.json"
    # bridge-operator reads the URL from the environment, so it stays out of the process list.
    "$OPERATOR_BIN" deposits --escrow "$e" --from "$from" --step "$DEPOSIT_LOG_STEP" --pace "$DEPOSIT_LOG_PACE" \
      --out "$BRIDGE_WORK/deposits.json" > "$BRIDGE_WORK/deposits.report.json"
    echo "$(jget "$BRIDGE_WORK/deposits.report.json" deposits) deposit(s) to escrow $e final through Sepolia block $(jget "$BRIDGE_WORK/deposits.report.json" to_block)"

# Recover the state, read the final deposits, and say which are proven, claimed, and claimable. With a deposit
# number, report its own status; claims may be made in any order.
[group('read')]
status deposit='': recover deposits
    #!/usr/bin/env bash
    {{ _prelude }}
    [[ "$deposit" =~ ^(0|[1-9][0-9]*)?$ ]] || die "deposit must be a deposit number, got '$deposit'"
    s=$(site)
    python3 - "$BRIDGE_INSTANCE/instance.json" "$BRIDGE_WORK" "$(escrow)" "$s" "$deposit" <<'PY'
    import json, os, sys
    from pathlib import Path
    sys.path.insert(0, "tools/sg16/bridge-guest/testnet")
    import pins
    inst, work = pins.load(sys.argv[1]), Path(sys.argv[2])
    escrow, served, mine = sys.argv[3], sys.argv[4] == "served", sys.argv[5]
    read = lambda name: json.loads((work / name).read_text())
    state, rec, deps = read("state.json"), read("recover.json")["result"], read("deposits.json")
    to_block = read("deposits.report.json")["to_block"]
    def recipient(spk):  # as assemble.py claim: a deposit commits to the SHA-256 of the scriptPubKey
        return pins.sha(bytes.fromhex(spk.removeprefix("0x")))
    events = [(u, recipient(r)) for u, r in deps]
    domain, acc = bytes.fromhex(inst.deposit_domain), bytes.fromhex(state["acc"])
    claimed = set(pins.claimed_indices(state["claimed"]))
    if pins.claimed_root(claimed).hex() != state["claimed_root"]:
        sys.exit("the recovered claimed set does not match the state's claimed root")
    proven = next((k for k in range(len(events), -1, -1)
                   if pins.accumulator(pins.tree_root(domain, events[:k]), k) == acc), None)
    print(f"live state      output 0 of {rec['chain'][-1][0]}, head slot {state['head']}, {len(claimed)} claimed")
    print(f"proven through  Sepolia block {state.get('exec_block', 'none yet (anchor)')}")
    print(f"final deposits  {len(events)} through Sepolia block {to_block}")
    if rec["lc_store"] and rec["hint"] == os.environ["REBUILT_STORE"]:
        print(f"store           {rec['lc_store']} (rebuilt by just reconstruct, hashes to the live lc; not published)")
    else:
        print(f"store           {rec['lc_store'] or 'none published for this head'}")
    if proven is None:
        sys.exit("no prefix of the final deposits gives the state's accumulator; the RPC may lag the proven block: run just status again")
    if any(k >= proven for k in claimed):
        sys.exit("the recovered claimed set names a deposit outside the state's proven accumulator")
    print(f"proven          {proven}")
    claimable = [k for k in range(proven) if k not in claimed]
    for k in claimable[:5]:
        units, spk = deps[k]
        print(f"claimable       #{k}: {units} units to script {spk.removeprefix('0x')}")
    if len(claimable) > 5:
        print(f"claimable       ... {len(claimable) - 5} more proven deposit(s)")
    if mine:
        k = int(mine)
        if k >= len(events):
            print(f"deposit #{k}     not among the {len(events)} deposits to escrow {escrow} final through block {to_block}: "
                  "wait for Ethereum finality, or check that it was sent to this escrow")
        elif k in claimed:
            print(f"deposit #{k}     claimed")
        elif k >= proven:
            print(f"deposit #{k}     final, not proven yet: a proof update covering it comes before its claim")
        else:
            print(f"deposit #{k}     proven and unclaimed; anyone may claim it now, paying its committed script "
                  f"with about {os.environ['FEE_CLAIM_SATS']} sats of Liquid fee")
    if claimable and served:
        target = int(mine) if mine and int(mine) in claimable else claimable[0]
        print(f"next: claim deposit #{target}: with Humid, just claim-unsigned <fee txid> <vout> {target}, then load "
              f"{work}/claim.hex in the site's Claim panel; or use the fee-key path: just split claim <txid> <vout>, "
              f"just broadcast {work}/fee-claim.hex, just wait <its txid>, just claim {target}")
    elif claimable:
        target = int(mine) if mine and int(mine) in claimable else claimable[0]
        print(f"next: claim deposit #{target} with your fee key; the published site does not serve this instance, so it "
              f"has no Humid route: just split claim <txid> <vout>, just broadcast {work}/fee-claim.hex, "
              f"just wait <its txid>, just claim {target}, just broadcast {work}/claim.signed.hex")
    elif len(events) > proven:
        if not (rec["complete"] and rec["lc_store"]):
            print(f"next: deposits #{proven}..#{len(events) - 1} are final but unproven, and no store is published for the "
                  f"live head {state['head']}: just reconstruct rebuilds it from public data and checks it against the "
                  "live lc; then just inputs, just execute, just prove")
        else:
            print(f"next: deposits #{proven}..#{len(events) - 1} are final but unproven: just inputs, just execute, just prove")
    else:
        print(f"next: nothing; every final deposit to escrow {escrow} is proven and claimed")
    PY

# Build proof inputs from the live head's store: the published one, or the one `just reconstruct` rebuilt.
[group('prove')]
inputs: recover
    #!/usr/bin/env bash
    {{ _prelude }}
    head=$(jget "$BRIDGE_WORK/state.json" head)
    store=$(jget "$BRIDGE_WORK/recover.json" result lc_store)
    [ -n "$store" ] || die "no store for the live head $head: the update that reached it published none. Run just reconstruct," \
      "which rebuilds it from public data and checks it against the live lc, then just inputs again"
    need_env SEPOLIA_EXECUTION_RPC "a Sepolia execution RPC serving eth_getProof at the finalized block"
    need_env SEPOLIA_CONSENSUS_RPC "a Sepolia beacon API serving light-client updates"
    need "$BRIDGE_HOST_BIN" "run: just prover"
    finality=$(curl -fsS --max-time 30 "${SEPOLIA_CONSENSUS_RPC%/}/eth/v1/beacon/light_client/finality_update" | python3 -c '
    import json, sys
    try: print(int(json.load(sys.stdin)["data"]["finalized_header"]["beacon"]["slot"]))
    except (KeyError, ValueError, TypeError): sys.exit("the beacon RPC gave no finality slot")
    ') || die "the beacon RPC did not serve a light-client finality update"
    [ "$finality" -gt "$head" ] || die "the beacon RPC is behind the Liquid light-client head $head (finality $finality); use a current Sepolia beacon API"
    e=$(escrow)
    lc=$(jget "$BRIDGE_WORK/state.json" lc)
    rm -f "$BRIDGE_WORK/inputs.cbor"
    "$BRIDGE_HOST_BIN" inputs --store "$store" --lc "$lc" --escrow "$e" --out "$BRIDGE_WORK/inputs.cbor"

# Recovery, when the update that reached the live head published no store: rebuild that store from public data (the
# beacon node at SEPOLIA_CONSENSUS_RPC, the instance's published stores and any store or inputs <sources> given,
# paths without spaces), check that it hashes to the lc read from Liquid, and complete the state record with it.
# Writes only under BRIDGE_WORK; without SEPOLIA_CONSENSUS_RPC it uses the files alone.
[group('read')]
reconstruct *sources: recover
    #!/usr/bin/env bash
    {{ _prelude }}
    need "$BRIDGE_HOST_BIN" "run: just prover"
    head=$(jget "$BRIDGE_WORK/state.json" head); lc=$(jget "$BRIDGE_WORK/state.json" lc)
    store=$(jget "$BRIDGE_WORK/recover.json" result lc_store)
    if [ -n "$store" ] && [ "$(jget "$BRIDGE_WORK/recover.json" result hint)" != "$REBUILT_STORE" ]; then
      echo "the instance publishes the live head's store, $store; nothing to reconstruct. next: just inputs"
      exit 0
    fi
    if [ -z "$store" ]; then
      src=()
      for f in "$BRIDGE_INSTANCE"/lc_stores/*.json; do
        if [ -f "$f" ]; then src+=(--source "$f"); fi
      done
      read -ra given <<< "${sources:-}"
      for f in ${given[@]+"${given[@]}"}; do need "$f"; src+=(--source "$f"); done
      mode=()
      if [ -z "${SEPOLIA_CONSENSUS_RPC:-}" ]; then
        mode=(--offline)
        echo "SEPOLIA_CONSENSUS_RPC is unset: using only the instance's published stores and the given files" >&2
      fi
      rm -f "$REBUILT_STORE" "$BRIDGE_WORK/reconstruct.json"
      if ! "$BRIDGE_HOST_BIN" reconstruct --state "$BRIDGE_WORK/state.json" --out "$REBUILT_STORE" \
          ${src[@]+"${src[@]}"} ${mode[@]+"${mode[@]}"} > "$BRIDGE_WORK/reconstruct.json"; then
        rm -f "$REBUILT_STORE"
        die "not recovered: the public data found does not give the store of head $head (refusal above); nothing was" \
          "written. Pass an archived store or inputs file of that head's sync-committee period (just reconstruct" \
          "<file>...), or use a beacon node that keeps older light-client updates (OPERATOR.md, Recovering a withheld store)"
      fi
      recover_state
    fi
    "$BRIDGE_HOST_BIN" check-store "$REBUILT_STORE" --lc "$lc" > "$BRIDGE_WORK/check-store.json" \
      || die "$REBUILT_STORE does not hash to the live lc $lc; not recovered"
    [ "$(jget "$BRIDGE_WORK/recover.json" result hint)" = "$REBUILT_STORE" ] && [ "$(jget "$BRIDGE_WORK/state.json" lc)" = "$lc" ] \
      || die "the state record was not completed by $REBUILT_STORE; not recovered"
    echo "recovered: $REBUILT_STORE is the store of the live head $head; its roots hash to the live Liquid lc $lc" \
      "(state output $(jget "$BRIDGE_WORK/recover.json" result outpoint))"
    echo "next: just inputs execute prove; also, to spare later provers this step, just stage-recovered and publish it"

# Execute the guest on the inputs without proving, as a check before `prove`. Minutes of CPU.
[group('prove')]
execute: check-elf
    #!/usr/bin/env bash
    {{ _prelude }}
    check_inputs
    "$BRIDGE_HOST_BIN" run --elf "$BRIDGE_ELF" "$BRIDGE_WORK/inputs.cbor" "$BRIDGE_WORK/execute.json"

# Make and SDK-verify a Groth16 proof (Docker; minutes to hours), then check it against the state.
[group('prove')]
[confirm("Generate an SP1 Groth16 proof now? It needs Docker and minutes to hours of CPU. [y/N]")]
prove: check-elf
    #!/usr/bin/env bash
    {{ _prelude }}
    [ ! -e "$BRIDGE_WORK/proof.json" ] || die "$BRIDGE_WORK/proof.json exists; move it aside first, a proof is costly to remake"
    check_inputs
    "$BRIDGE_HOST_BIN" run --elf "$BRIDGE_ELF" "$BRIDGE_WORK/inputs.cbor" "$BRIDGE_WORK/proof.json" --prove
    check_artifact

# Check the proof against the instance pins and the recovered state.
[group('prove')]
check-artifact:
    #!/usr/bin/env bash
    {{ _prelude }}
    check_artifact

# Create the fee key file at LIQUID_FEE_KEY (mode 0600) and print its address. Refuses an existing file.
[group('key')]
fee-key-new:
    #!/usr/bin/env bash
    {{ _prelude }}
    [ -n "$LIQUID_FEE_KEY" ] || die "set LIQUID_FEE_KEY to the new key file's path, under target/ or outside the repository"
    [ ! -e "$LIQUID_FEE_KEY" ] || die "$LIQUID_FEE_KEY exists; this never overwrites a key"
    if git check-ignore -q -- "$LIQUID_FEE_KEY" 2>/dev/null; then :; else
      [ $? -ne 1 ] || die "$LIQUID_FEE_KEY is inside the repository and not ignored by git; put it under target/ or outside"
    fi
    need "$WALLET_BIN" "run: just tools"
    mkdir -p "$(dirname "$LIQUID_FEE_KEY")"
    "$WALLET_BIN" new "$LIQUID_FEE_KEY"

# Print the fee key's unconfidential address, to fund with tL-BTC.
[group('key')]
fee-address:
    #!/usr/bin/env bash
    {{ _prelude }}
    need_key
    need "$WALLET_BIN" "run: just tools"
    "$WALLET_BIN" address "$LIQUID_FEE_KEY"

# Split a fee slot for an update or a claim from output <vout> of your transaction <txid>. Signs; sends nothing.
[group('sign')]
split kind txid vout:
    #!/usr/bin/env bash
    {{ _prelude }}
    case "$kind" in
      update) slot=$FEE_UPDATE_SATS ;;
      claim) slot=$FEE_CLAIM_SATS ;;
      *) die "kind is update or claim, got '$kind'" ;;
    esac
    hex32 "$txid" txid
    [[ "$vout" =~ ^[0-9]+$ ]] || die "vout must be an output index, got '$vout'"
    need_key
    need "$WALLET_BIN" "run: just tools"
    prev=$(tx_file "$txid")
    out="$BRIDGE_WORK/fee-$kind.hex"
    [ ! -e "$out" ] || echo "note: replacing $out; a copy of each split stays in $BRIDGE_WORK/tx/" >&2
    rm -f "$out" "$out.meta.json"
    r=$("$WALLET_BIN" split "$LIQUID_FEE_KEY" "$prev" "$vout" "$slot" "$SPLIT_FEE_SATS" "$out")
    echo "$r"
    id=$(echo "$r" | jget - txid)
    check_txid "$out" "$id"
    cp "$out" "$BRIDGE_WORK/tx/$id.hex"
    meta "$out" kind=split txid="$id" parents="$txid" source_vout="$vout"
    echo "next: just broadcast $out, then just wait $id; its change is output 1"

# Build, sign and verify the Liquid update from the checked proof and freshly recovered state. Sends nothing.
[group('sign')]
update: recover
    #!/usr/bin/env bash
    {{ _prelude }}
    need_key
    need "$WALLET_BIN" "run: just tools"
    need "$BRIDGE_WORK/proof.json" "run: just prove"
    need "$BRIDGE_WORK/fee-update.hex.meta.json" "run: just split update <txid> <vout>"
    w=$BRIDGE_WORK; st=$(cat "$w/state-tx.path"); st_id=$(cat "$w/state-tx.txid"); fee_id=$(jget "$w/fee-update.hex.meta.json" txid)
    check_txid "$w/fee-update.hex" "$fee_id"
    rm -f "$w/update.hex" "$w/update.signed.hex" "$w/update.signed.hex.meta.json" "$w/update.new_state.json" "$w/update.assemble.json"
    if ! python3 "$ASSEMBLE_PY" update --report "$w/update.assemble.json" \
        --instance "$BRIDGE_INSTANCE/instance.json" --manifest "$BRIDGE_INSTANCE/manifest.json" \
        --artifact "$w/proof.json" --state "$w/state.json" --state-tx "$st" --fee-tx "$w/fee-update.hex" --fee-vout 0 \
        --out "$w/update.hex" > "$w/update.assemble.log"; then
      gate "$w/update.assemble.json"
      die "assemble.py update refused ($w/update.assemble.json)"
    fi
    r=$("$WALLET_BIN" sign "$LIQUID_FEE_KEY" "$w/update.hex" 1 "$w/fee-update.hex" 0 "$w/update.signed.hex")
    id=$(echo "$r" | jget - txid)
    check_txid "$w/update.signed.hex" "$id"
    "$TX_BIN" verify "$w/update.signed.hex" 0 "$st" "$w/fee-update.hex" > "$w/update.verify.json" \
      || { gate "$w/update.verify.json"; die "the signed update does not verify"; }
    meta "$w/update.signed.hex" kind=update txid="$id" state="$st_id" parents="$st_id,$fee_id" new_state="$w/update.new_state.json"
    echo "signed update $id to head $(jget "$w/update.new_state.json" head). Do not broadcast it yet:"
    echo "next: just stage-store, publish the store and lc_preimages.json, then STORE_READBACK_URL=<url> just broadcast $w/update.signed.hex"

# Refuse a Humid route before any network read unless the published site serves BRIDGE_INSTANCE: its Humid panels
# load only that instance's updates and claims.
_humid-site route:
    #!/usr/bin/env bash
    {{ _prelude }}
    e=$(escrow); s=$(site)
    if [ "$s" = served ]; then exit 0; fi
    case "$route" in
      claim) other="claim with your own fee key; just status prints those steps" ;;
      update) other="sign the update with your own fee key (just update) and publish its store at your own HTTPS URL" ;;
      *) die "unknown Humid route $route" ;;
    esac
    printf '%s\n' "$BRIDGE_INSTANCE (escrow $e) is $s. The published site serves only $(site_name)," \
      "and its Humid $route panel refuses any other instance's file. For this instance, $other." \
      "Keep the same BRIDGE_INSTANCE and give it a work directory of its own:" \
      "  BRIDGE_INSTANCE=$BRIDGE_INSTANCE BRIDGE_WORK=target/takeover-$(basename "$BRIDGE_INSTANCE") just status" >&2
    die "no Humid $route route for $BRIDGE_INSTANCE; nothing was fetched or built"

# Build an unsigned update against one confirmed, open Humid fee coin. Humid signs and sends it in the site.
[group('assemble')]
update-unsigned txid vout: (_humid-site "update") recover
    #!/usr/bin/env bash
    {{ _prelude }}
    hex32 "$txid" 'Humid fee txid'
    [[ "$vout" =~ ^(0|[1-9][0-9]*)$ ]] || die 'Humid fee vout must be a nonnegative integer'
    check_artifact
    w=$BRIDGE_WORK; st=$(cat "$w/state-tx.path"); st_id=$(cat "$w/state-tx.txid")
    fee=$(tx_file "$txid")
    confirmed "$txid" || die "Humid fee coin $txid:$vout is not confirmed yet"
    [ -z "$(outspend "$txid" "$vout")" ] || die "Humid fee coin $txid:$vout has been spent"
    rm -f "$w/update.hex" "$w/update.hex.meta.json" "$w/update.new_state.json" "$w/update.assemble.json"
    if ! python3 "$ASSEMBLE_PY" update --report "$w/update.assemble.json" \
        --instance "$BRIDGE_INSTANCE/instance.json" --manifest "$BRIDGE_INSTANCE/manifest.json" \
        --artifact "$w/proof.json" --state "$w/state.json" --state-tx "$st" --fee-tx "$fee" --fee-vout "$vout" \
        --out "$w/update.hex" > "$w/update.assemble.log"; then
      gate "$w/update.assemble.json"
      die "assemble.py update refused ($w/update.assemble.json)"
    fi
    node --input-type=module - "$w/update.hex" "$st" "$fee" "$BRIDGE_INSTANCE/manifest.json" <<'JS'
    import { readFileSync } from 'node:fs';
    import { hexToBytes } from './bridge-core/lib/bytes.js';
    import { readUpdate, updatePset } from './bridge-core/lib/update.js';
    const [update, state, fee, manifest] = process.argv.slice(2);
    const cmr = hexToBytes(JSON.parse(readFileSync(manifest, 'utf8')).update_leaf.cmr);
    const raw = hexToBytes(readFileSync(update, 'utf8').trim());
    const plan = updatePset(readUpdate(raw, cmr), readFileSync(state, 'utf8').trim(), readFileSync(fee, 'utf8').trim());
    console.log(`Humid can review this ${plan.pset.length}-character PSET; it signs only input 1 at ${plan.feeAddress}`);
    JS
    id=$(txid_of "$w/update.hex")
    meta "$w/update.hex" kind=update-unsigned txid="$id" state="$st_id" parents="$st_id,$txid" new_state="$w/update.new_state.json"
    echo "unsigned update $id to head $(jget "$w/update.new_state.json" head). Do not upload it yet:"
    echo "next: just stage-store unsigned; publish the store and lc_preimages.json on this site's instance record, then load $w/update.hex into the page"

# Write the chosen update's store and lc_preimages.json entry into the instance (working tree only; you review and publish).
[group('publish')]
stage-store mode="signed":
    #!/usr/bin/env bash
    {{ _prelude }}
    case "$mode" in
      signed) update_file="$BRIDGE_WORK/update.signed.hex"; expected_kind=update ;;
      unsigned) update_file="$BRIDGE_WORK/update.hex"; expected_kind=update-unsigned ;;
      *) die 'stage-store mode must be signed or unsigned' ;;
    esac
    need "$update_file.meta.json" "run: just update or just update-unsigned <Humid fee txid> <vout>"
    [ "$(jget "$update_file.meta.json" kind)" = "$expected_kind" ] || die "$update_file.meta.json is not a $mode update record"
    check_txid "$update_file" "$(jget "$update_file.meta.json" txid)"
    need "$BRIDGE_WORK/proof.json" "just prove writes it"
    need "$BRIDGE_WORK/state.json" "just recover writes the spent state"
    need "$BRIDGE_WORK/proof.store.json" "just prove writes it beside proof.json"
    need "$TX_BIN" "run: just tools"
    target
    spends=$(tx_report input "$update_file" 0) || die "$update_file has no readable input 0"
    creates=$(tx_report output "$update_file" 0) || die "$update_file has no readable output 0"
    # Nothing is written into the instance until the update, its new state, the proof and the store are all shown to
    # be this instance's: a work directory once used for another BRIDGE_INSTANCE must not pollute this record.
    python3 - "$BRIDGE_INSTANCE" "$BRIDGE_WORK" "$update_file" "$update_file.meta.json" \
      "$(jget - previous_output <<< "$spends")" "$(jget - script_pubkey <<< "$creates")" <<'PY'
    import json, sys
    from pathlib import Path
    sys.path.insert(0, "tools/sg16/bridge-guest/testnet")
    import assemble
    inst, work, update_file = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    meta = json.loads(Path(sys.argv[4]).read_text())
    # The outpoint input 0 spends and the script of output 0, as sg16-testnet input and output read them.
    spends, creates = sys.argv[5], sys.argv[6]
    norm = lambda h: str(h).lower().removeprefix("0x")
    other = (f"; it was built for another BRIDGE_INSTANCE or another update. Nothing was staged into {inst}. "
             "Give each instance its own BRIDGE_WORK and rebuild from just recover")
    if Path(meta["new_state"]).resolve() != (work / "update.new_state.json").resolve():
        sys.exit(f"{sys.argv[4]} names new state {meta['new_state']}, not {work / 'update.new_state.json'}{other}")
    new = json.loads((work / "update.new_state.json").read_text())
    # The instance and its manifest, the proof's public values (escrow, successor) and the new state record, with
    # assemble.py's own gates; pairing is left to the update recipe, which ran it before writing this update.
    g = assemble.Gates()
    try:
        pinned = assemble.instance(g, inst / "instance.json")
        m = assemble.load_manifest(inst / "manifest.json")
        assemble.manifest_gates(g, m, pinned)
        o = assemble.check_artifact(g, json.loads((work / "proof.json").read_text()), assemble.sp1_keys(g, pinned), pinned,
                                    state=json.loads((work / "state.json").read_text()), pairing=False)["outputs"]
        rec = assemble.state_record(int(new["head"]), assemble.b32(new["header"]), assemble.b32(new["committee"]),
                                    assemble.b32(new["acc"]), new["claimed"], exec_root=norm(new["exec_root"]),
                                    exec_block=new["exec_block"])
        g.need("update.new_state.json recomputes its lc and state hash", rec == new, {k: new.get(k) for k in rec if rec[k] != new.get(k)})
        g.need("the proof's successor = update.new_state.json: head, lc, accumulator, execution root and block",
               (o["new_head"], o["new_lc"].hex(), o["slot_value"].hex(), o["exec_root"].hex(), o["exec_block"])
               == (new["head"], new["lc"], new["acc"], new["exec_root"], new["exec_block"]))
        tree = assemble.tool_ok(g, "state tree of update.new_state.json under this instance's manifest", assemble.TX_TOOL,
                                "tree", inst / "manifest.json", work / "update.new_state.json")
        g.need("the tree's state hash = update.new_state.json", tree["state_hash"] == new["state_hash"], tree["state_hash"])
    except (assemble.Gate, KeyError, TypeError, ValueError, AssertionError) as e:
        sys.exit(f"{inst} refuses this update: {e!r}{other}")
    # The update itself: input 0 spends output 0 of the state its sidecar names, and output 0 is the state UTXO of
    # update.new_state.json under this instance's leaves, which commit to its escrow, guest and claim leaf.
    if spends != f"{meta['state']}:0" or meta["parents"][:1] != [meta["state"]]:
        sys.exit(f"{update_file} input 0 spends {spends}, not output 0 of its sidecar's state {meta['state']}{other}")
    if creates != tree["script_pubkey"]:
        sys.exit(f"{update_file} output 0 is not {inst}'s state UTXO for update.new_state.json{other}")
    raw = (work / "proof.store.json").read_bytes()
    store = json.loads(raw)
    for k in ("head", "header", "committee", "lc"):
        if norm(store[k]) != norm(new[k]):
            sys.exit(f"proof.store.json {k} {store[k]} is not the update's {new[k]}{other}")
    rel = f"lc_stores/{new['head']}.json"
    dst = inst / rel
    if dst.exists() and dst.read_bytes() != raw:
        sys.exit(f"{dst} exists with other contents")
    entry = dict(head=new["head"], header=norm(new["header"]), committee=norm(new["committee"]), update=meta["txid"], store=rel)
    pre_path = inst / "lc_preimages.json"
    pre = json.loads(pre_path.read_text()) if pre_path.exists() else {"preimages": []}
    same = [e for e in pre["preimages"] if e.get("head") == entry["head"]]
    if same and same[0] != entry:
        sys.exit(f"{pre_path} already has another entry for head {entry['head']}: {same[0]}")
    dst.parent.mkdir(exist_ok=True)
    dst.write_bytes(raw)
    if not same:
        pre["preimages"].append(entry)
        pre_path.write_text(json.dumps(pre, indent=1) + "\n")
    print(f"staged {dst} and the {pre_path} entry for head {entry['head']}, update {entry['update']}")
    print("next: review git diff, publish both files, read them back, then send the update")
    PY
    RECORD="$(basename "$BRIDGE_INSTANCE")" RECORD_DIR="$BRIDGE_INSTANCE" node --test bridge-core/test/lc-store.test.js

# Write the store `just reconstruct` rebuilt for the live head into the instance, under the update that reached that
# head (working tree only; you review and publish). Later provers then need neither the beacon data it came from nor
# this work directory.
[group('publish')]
stage-recovered: recover
    #!/usr/bin/env bash
    {{ _prelude }}
    need "$REBUILT_STORE" "run: just reconstruct"
    need "$BRIDGE_HOST_BIN" "run: just prover"
    target
    lc=$(jget "$BRIDGE_WORK/state.json" lc)
    "$BRIDGE_HOST_BIN" check-store "$REBUILT_STORE" --lc "$lc" > "$BRIDGE_WORK/check-store.json" \
      || die "$REBUILT_STORE does not hash to the live lc $lc; run just reconstruct again"
    rm -f "$BRIDGE_WORK/stage-recovered.json"
    if ! python3 "$ASSEMBLE_PY" stage-recovered --report "$BRIDGE_WORK/stage-recovered.json" \
        --instance "$BRIDGE_INSTANCE/instance.json" --recovered "$BRIDGE_WORK/recover.json" --store "$REBUILT_STORE" \
        > "$BRIDGE_WORK/stage-recovered.log"; then
      gate "$BRIDGE_WORK/stage-recovered.json"
      die "assemble.py stage-recovered refused ($BRIDGE_WORK/stage-recovered.json); nothing was staged"
    fi
    echo "staged $(jget "$BRIDGE_WORK/stage-recovered.json" result store) and its lc_preimages.json entry, naming update" \
      "$(jget "$BRIDGE_WORK/stage-recovered.json" result entry update)"
    RECORD="$(basename "$BRIDGE_INSTANCE")" RECORD_DIR="$BRIDGE_INSTANCE" node --test bridge-core/test/lc-store.test.js
    echo "next: review git diff, then publish both files with the instance record"

# Build, sign and verify the claim of any proven, unclaimed deposit from freshly recovered state. Sends nothing.
[group('sign')]
claim deposit: recover deposits
    #!/usr/bin/env bash
    {{ _prelude }}
    [[ "$deposit" =~ ^(0|[1-9][0-9]*)$ ]] || die "deposit must be a nonnegative number"
    need_key
    need "$WALLET_BIN" "run: just tools"
    need "$BRIDGE_WORK/fee-claim.hex.meta.json" "run: just split claim <txid> <vout>"
    w=$BRIDGE_WORK; st=$(cat "$w/state-tx.path"); st_id=$(cat "$w/state-tx.txid"); fee_id=$(jget "$w/fee-claim.hex.meta.json" txid)
    check_txid "$w/fee-claim.hex" "$fee_id"
    rm -f "$w/claim.hex" "$w/claim.hex.meta.json" "$w/claim.signed.hex" "$w/claim.signed.hex.meta.json" "$w/claim.assemble.json"
    if ! python3 "$ASSEMBLE_PY" claim --report "$w/claim.assemble.json" \
        --instance "$BRIDGE_INSTANCE/instance.json" --manifest "$BRIDGE_INSTANCE/manifest.json" \
        --state "$w/state.json" --deposits "$w/deposits.json" --state-tx "$st" --fee-tx "$w/fee-claim.hex" --fee-vout 0 \
        --deposit "$deposit" --out "$w/claim.hex" > "$w/claim.assemble.log"; then
      claim_refused
    fi
    r=$("$WALLET_BIN" sign "$LIQUID_FEE_KEY" "$w/claim.hex" 1 "$w/fee-claim.hex" 0 "$w/claim.signed.hex")
    id=$(echo "$r" | jget - txid)
    check_txid "$w/claim.signed.hex" "$id"
    "$TX_BIN" verify "$w/claim.signed.hex" 0 "$st" "$w/fee-claim.hex" > "$w/claim.verify.json" \
      || { gate "$w/claim.verify.json"; die "the signed claim does not verify"; }
    meta "$w/claim.signed.hex" kind=claim txid="$id" state="$st_id" parents="$st_id,$fee_id"
    echo "signed claim $id of deposit #$deposit to escrow $(escrow)"
    echo "next: just broadcast $w/claim.signed.hex, just wait $id, then just status"

# Build an unsigned claim of any proven, unclaimed deposit against one confirmed, open Humid fee coin. Humid signs and sends it in the site.
# Only for the instance the published site serves, which `just config` names.
[group('assemble')]
claim-unsigned txid vout deposit: (_humid-site "claim") recover deposits
    #!/usr/bin/env bash
    {{ _prelude }}
    hex32 "$txid" 'Humid fee txid'
    [[ "$vout" =~ ^(0|[1-9][0-9]*)$ ]] || die 'Humid fee vout must be a nonnegative integer'
    [[ "$deposit" =~ ^(0|[1-9][0-9]*)$ ]] || die 'deposit must be a nonnegative number'
    w=$BRIDGE_WORK; st=$(cat "$w/state-tx.path"); st_id=$(cat "$w/state-tx.txid")
    fee=$(tx_file "$txid")
    confirmed "$txid" || die "Humid fee coin $txid:$vout is not confirmed yet"
    [ -z "$(outspend "$txid" "$vout")" ] || die "Humid fee coin $txid:$vout has been spent"
    rm -f "$w/claim.hex" "$w/claim.hex.meta.json" "$w/claim.signed.hex" "$w/claim.signed.hex.meta.json" "$w/claim.assemble.json"
    if ! python3 "$ASSEMBLE_PY" claim --report "$w/claim.assemble.json" \
        --instance "$BRIDGE_INSTANCE/instance.json" --manifest "$BRIDGE_INSTANCE/manifest.json" \
        --state "$w/state.json" --deposits "$w/deposits.json" --state-tx "$st" --fee-tx "$fee" --fee-vout "$vout" \
        --deposit "$deposit" --out "$w/claim.hex" > "$w/claim.assemble.log"; then
      claim_refused
    fi
    node --input-type=module - "$w/claim.hex" "$st" "$fee" "$BRIDGE_INSTANCE/manifest.json" <<'JS'
    import { readFileSync } from 'node:fs';
    import { hexToBytes } from './bridge-core/lib/bytes.js';
    import { claimParams, claimPset, readClaim } from './bridge-core/lib/claim.js';
    const [claim, state, fee, manifest] = process.argv.slice(2);
    const c = readClaim(hexToBytes(readFileSync(claim, 'utf8').trim()), claimParams(JSON.parse(readFileSync(manifest, 'utf8'))));
    const plan = claimPset(c, readFileSync(state, 'utf8').trim(), readFileSync(fee, 'utf8').trim());
    console.log(`Humid can review this ${plan.pset.length}-character PSET; it signs only input 1 at ${plan.feeAddress}`);
    console.log(`the claim pays ${c.mint.units} units to ${c.mint.address ?? 'script ' + Buffer.from(c.mint.script).toString('hex')}`);
    JS
    id=$(txid_of "$w/claim.hex")
    meta "$w/claim.hex" kind=claim-unsigned txid="$id" state="$st_id" parents="$st_id,$txid"
    echo "unsigned claim $id of deposit #$deposit to escrow $(escrow)"
    echo "next: load $w/claim.hex into the published site's \"Claim a proven deposit with Humid\" panel"

# Run every check `broadcast` makes, without sending: recipe sidecar, parents confirmed, inputs unspent, update store published.
[group('read')]
preflight file:
    #!/usr/bin/env bash
    {{ _prelude }}
    need "$file"
    need "$file.meta.json" "the split, update, claim and deploy-bootstrap recipes create it; update.hex and claim.hex are unsigned"
    m="$file.meta.json"; kind=$(jget "$m" kind)
    case "$kind" in
      split|update|claim|bootstrap) ;;
      update-unsigned) die "$file has no fee signature; load it into the published site's Humid update panel after publishing its store" ;;
      claim-unsigned) die "$file has no fee signature; load it into the published site's Claim a proven deposit with Humid panel" ;;
      *) die "$file.meta.json names unsupported transaction kind $kind" ;;
    esac
    id=$(jget "$m" txid); state=$(jget "$m" state)
    check_txid "$file" "$id"
    # The transaction itself, not its status: Esplora answers /status with 200 {"confirmed":false} for a txid it has
    # never seen, while /hex is 404 unless the transaction is in its mempool or a block.
    code=$(curl -sS -o /dev/null -w '%{http_code}' "$LIQUID_ESPLORA/tx/$id/hex") || die "could not reach Liquid Esplora"
    [ "$code" != 200 ] || die "$id is already known to Esplora; nothing to send (just wait $id)"
    [ "$code" = 404 ] || die "Esplora answered HTTP $code for $id"
    for p in $(jget "$m" parents); do
      confirmed "$p" || die "$kind $id spends $p, which is not confirmed yet: just wait $p"
    done
    if [ "$kind" = split ]; then
      source=$(jget "$m" parents 0); vout=$(jget "$m" source_vout)
      r=$(outspend "$source" "$vout")
      [ -z "$r" ] || die "the fee source $source:$vout is already spent by ${r%% *}; choose another confirmed coin"
    fi
    if [ "$kind" = bootstrap ]; then
      source=$(jget "$m" parents 0); vout=$(jget "$m" source_vout)
      r=$(outspend "$source" "$vout")
      [ -z "$r" ] || die "the funding output $source:$vout is already spent by ${r%% *}; its asset can no longer be issued"
    fi
    if [ -n "$state" ]; then
      r=$(outspend "$state")
      [ -z "$r" ] || die "the state output $state:0 is already spent by ${r%% *}; run just status, that spend may cover your deposit"
    fi
    if [ "$kind" = update ] || [ "$kind" = claim ]; then
      fee=$(jget "$m" parents 1)
      r=$(outspend "$fee")
      [ -z "$r" ] || die "the fee slot $fee:0 is already spent by ${r%% *}; split a fresh fee slot"
    fi
    if [ "$kind" = update ]; then
      RECORD="$(basename "$BRIDGE_INSTANCE")" RECORD_DIR="$BRIDGE_INSTANCE" node --test bridge-core/test/lc-store.test.js
      head=$(jget "$(jget "$m" new_state)" head)
      store="$BRIDGE_INSTANCE/lc_stores/$head.json"
      need "$store" "run: just stage-store"
      python3 -c '
    import json, sys
    es = [e for e in json.load(open(sys.argv[1]))["preimages"] if e.get("head") == int(sys.argv[2])]
    if not es or es[0].get("update") != sys.argv[3] or es[0].get("store") != f"lc_stores/{sys.argv[2]}.json":
        sys.exit(f"{sys.argv[1]} has no entry for head {sys.argv[2]} naming update {sys.argv[3]}: run just stage-store")
    ' "$BRIDGE_INSTANCE/lc_preimages.json" "$head" "$id"
      need_env STORE_READBACK_URL "the public URL of this instance directory, where the store was published"
      [[ "$STORE_READBACK_URL" == https://* ]] \
        || die "STORE_READBACK_URL must be a public HTTPS URL; local file and HTTP readback cannot establish publication"
      store_url=${STORE_READBACK_URL%/}
      for f in "lc_stores/$head.json" lc_preimages.json; do
        curl --proto '=https' -fsS --max-time 30 "$store_url/$f" | cmp -s - "$BRIDGE_INSTANCE/$f" \
          || die "the published $f differs from the local $BRIDGE_INSTANCE/$f; publish it before broadcasting the update"
      done
    fi
    echo "ready: $kind $id"

# Send one signed file to Esplora after `preflight` passes, with an informed confirmation prompt.
[group('broadcast')]
broadcast file: (preflight file)
    #!/usr/bin/env bash
    {{ _prelude }}
    id=$(jget "$file.meta.json" txid)
    [ -r /dev/tty ] || die "broadcast needs a terminal for confirmation"
    read -r -p "Send $id to Liquid testnet? Type yes: " answer </dev/tty
    [ "$answer" = yes ] || die "not sent"
    check_txid "$file" "$id"  # again: the file may have changed since preflight, during the prompt
    resp=$(tr -d '[:space:]' < "$file" | curl -sS -X POST --data-binary @- -w '\n%{http_code}' "$LIQUID_ESPLORA/tx") \
      || die "could not reach Liquid Esplora"
    code=${resp##*$'\n'}; body=${resp%$'\n'*}
    [ "$code" = 200 ] || die "Esplora refused $file (HTTP $code). Run just status; if the state moved, build a fresh transaction"
    [ "$body" = "$id" ] || die "Esplora accepted txid $body, but $file.meta.json expects $id"
    echo "sent $id; next: just wait $id"

# Poll Esplora until <txid> confirms (WAIT_TRIES polls, WAIT_SECONDS apart).
[group('read')]
wait txid:
    #!/usr/bin/env bash
    {{ _prelude }}
    hex32 "$txid" txid
    tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
    for _ in $(seq 1 "$WAIT_TRIES"); do
      code=$(curl -sS -o "$tmp" -w '%{http_code}' "$LIQUID_ESPLORA/tx/$txid/status" || true)
      if [ "$code" = 200 ] && [ "$(jget "$tmp" confirmed)" = true ]; then
        echo "$txid confirmed at Liquid height $(jget "$tmp" block_height)"; exit 0
      fi
      case "$code" in 200) echo "$txid: unconfirmed" ;; 404) echo "$txid: not known to Esplora" ;; *) echo "$txid: HTTP $code" ;; esac
      sleep "$WAIT_SECONDS"
    done
    die "$txid not confirmed after $WAIT_TRIES polls"

# ---- a new instance ----
#
# Run once, in this order, to deploy a new instance (OPERATOR.md, "Deploying the instance"). Parameters,
# simulations and transactions stay under DEPLOY_WORK until deploy-record writes BRIDGE_INSTANCE/instance.json,
# which it never overwrites. Only deploy-escrow sends anything; the bootstrap goes through `just broadcast`.

# The Sepolia config the guest commits to, from real proof inputs, without RPC. Record it as pins.py SEPOLIA_CONFIG.
[group('deploy')]
deploy-config inputs="tools/sg16/bridge-guest/host/tests/fixtures/inputs-11385472-11388896.cbor":
    #!/usr/bin/env bash
    {{ _prelude }}
    need "$BRIDGE_HOST_BIN" "run: just prover"
    need "$inputs"
    mkdir -p "$DEPLOY_WORK"
    "$BRIDGE_HOST_BIN" anchor "$inputs" > "$DEPLOY_WORK/config.json"
    python3 - "$DEPLOY_WORK/config.json" <<'PY'
    import json, sys
    sys.path.insert(0, "tools/sg16/bridge-guest/testnet")
    import pins
    net = json.load(open(sys.argv[1]))["network"]
    if not net["is_sepolia"]:
        sys.exit("these inputs are not for Sepolia")
    config = net["config"].lower().removeprefix("0x")
    if pins.SEPOLIA_CONFIG is None:
        print("SEPOLIA_CONFIG is not recorded. In tools/sg16/bridge-guest/testnet/pins.py, as a reviewed change:")
        print(f"    SEPOLIA_CONFIG = '{config}'")
    elif pins.SEPOLIA_CONFIG == config:
        print(f"pins.py SEPOLIA_CONFIG {config} is the config of these inputs")
    else:
        sys.exit(f"pins.py SEPOLIA_CONFIG {pins.SEPOLIA_CONFIG} is not these inputs' config {config}")
    PY

# The bridge asset that output <vout> of <txid>, explicit tL-BTC to the fee key, will issue (Esplora reads). Keep
# that output unspent until the bootstrap: another outpoint gives another asset, and the escrow pins this one.
[group('deploy')]
deploy-asset txid vout:
    #!/usr/bin/env bash
    {{ _prelude }}
    hex32 "$txid" 'funding txid'
    [[ "$vout" =~ ^(0|[1-9][0-9]*)$ ]] || die 'funding vout must be a nonnegative integer'
    need_key
    need "$TX_BIN" "run: just tools"
    need "$WALLET_BIN" "run: just tools"
    mkdir -p "$DEPLOY_WORK"
    f=$(tx_file "$txid")
    confirmed "$txid" || die "funding transaction $txid is not confirmed yet"
    spent=$(outspend "$txid" "$vout") || die "could not check the funding output"
    [ -z "$spent" ] || die "funding output $txid:$vout is already spent"
    spk=$("$WALLET_BIN" address "$LIQUID_FEE_KEY" | jget - script_pubkey)
    out=$(tx_report output "$f" "$vout") || die "funding transaction $txid has no readable output $vout"
    [ "$(jget - explicit_lbtc <<< "$out")" = true ] || die "the funding output is not explicit tL-BTC"
    [ "$(jget - script_pubkey <<< "$out")" = "$spk" ] \
      || die "the funding output does not pay the fee key, which must sign the bootstrap's issuance input"
    echo "funding output: $(jget - value <<< "$out") sats of explicit tL-BTC to the fee key"
    rm -f "$DEPLOY_WORK/asset.json"
    if ! python3 "$ASSEMBLE_PY" asset --report "$DEPLOY_WORK/asset.json" --funding-txid "$txid" --funding-vout "$vout" \
        > "$DEPLOY_WORK/asset.log"; then
      gate "$DEPLOY_WORK/asset.json"
      die "assemble.py asset refused ($DEPLOY_WORK/asset.json)"
    fi
    echo "bridge asset $(jget "$DEPLOY_WORK/asset.json" result bridge_asset_display)" \
      "(internal $(jget "$DEPLOY_WORK/asset.json" result bridge_asset_internal))"
    echo "keep $txid:$vout unspent until the bootstrap; next: just deploy-checkpoint <last height of a past epoch>"

# The light client's starting checkpoint: Liquid testnet block <height>, the last of a past epoch (Esplora reads).
[group('deploy')]
deploy-checkpoint height:
    #!/usr/bin/env bash
    {{ _prelude }}
    [[ "$height" =~ ^[1-9][0-9]*$ ]] || die 'height must be a positive integer'
    mkdir -p "$DEPLOY_WORK"
    python3 tools/liquid-relay/relay.py --esplora "$LIQUID_ESPLORA" checkpoint --height "$height" \
      > "$DEPLOY_WORK/checkpoint.json.part"
    mv "$DEPLOY_WORK/checkpoint.json.part" "$DEPLOY_WORK/checkpoint.json"
    echo "checkpoint: block $(jget "$DEPLOY_WORK/checkpoint.json" hashId) at height $height," \
      "$(jget "$DEPLOY_WORK/checkpoint.json" threshold)-of-$(jget "$DEPLOY_WORK/checkpoint.json" keys) signing script"
    echo "compare that block hash with an independently operated Liquid node or explorer (assumption L2) before deploying"

# The escrow's constructor parameters, checked offline against its bounds: a deposit window of <days> days, a fork
# check valid for <fork_check_age> seconds, the announced activation time (unix seconds) of the earliest Sepolia
# fork outside the guest's schedule or `none`, and the deposit closer's address (the zero address for none).
[group('deploy')]
deploy-params days fork_check_age unsupported_fork_at closer:
    #!/usr/bin/env bash
    {{ _prelude }}
    need "$DEPLOY_WORK/asset.json" "run: just deploy-asset"
    need "$DEPLOY_WORK/checkpoint.json" "run: just deploy-checkpoint"
    python3 - "$DEPLOY_WORK" "$days" "$fork_check_age" "$unsupported_fork_at" "$closer" <<'PY'
    import json, re, sys, time
    from pathlib import Path
    work, days, age, fork_at, closer = Path(sys.argv[1]), *sys.argv[2:]
    DAY, FORK_MARGIN = 86_400, 2 * 86_400
    asset = json.loads((work / "asset.json").read_text())["result"]
    cp = json.loads((work / "checkpoint.json").read_text())
    if not re.fullmatch(r"[1-9][0-9]*", days) or int(days) > 180:
        sys.exit("days: the deposit window in whole days, 1 to 180 (BridgeEscrow.MAX_DEPOSIT_WINDOW)")
    if not re.fullmatch(r"[1-9][0-9]*", age) or not 600 <= int(age) <= 21_600:
        sys.exit("fork_check_age: seconds, 600 to 21600 (MIN_FORK_CHECK_AGE to MAX_FORK_CHECK_AGE_BOUND)")
    if fork_at == "none":
        fork_at = 2**64 - 1
    elif re.fullmatch(r"[1-9][0-9]*", fork_at):
        fork_at = int(fork_at)
    else:
        sys.exit("unsupported_fork_at: unix seconds of the earliest announced fork outside the guest's schedule, or none")
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", closer):
        sys.exit("closer: a 0x-prefixed address, or 0x0000000000000000000000000000000000000000 for no closer")
    # An hour of slack for the time until the deployment's block; the constructor checks the bounds again.
    end = int(time.time()) + int(days) * DAY - 3_600
    if end + FORK_MARGIN > fork_at:
        sys.exit(f"deposits would end at {end}, less than FORK_MARGIN before the unsupported fork at {fork_at}: choose fewer days")
    params = {
        "bridgeAsset": asset["bridge_asset_internal"],
        "funding": asset["funding"],
        "minConfirmations": 2,
        "maxRelayLag": DAY,
        # As a string: a JSON number this large loses precision in some parsers.
        "admission": {"depositsEnd": end, "unsupportedForkAt": str(fork_at), "closer": closer, "maxForkCheckAge": int(age)},
        "checkpoint": {k: cp[k] for k in ("epochLength", "height", "hash", "witnessScript", "keyY", "signblockscriptKeccak")},
    }
    (work / "escrow-params.json").write_text(json.dumps(params, indent=1) + "\n")
    print(f"deposits until {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(end))}, fork check valid {age} s, "
          f"closer {closer}, checkpoint height {cp['height']}")
    PY
    echo "wrote $DEPLOY_WORK/escrow-params.json; next: just deploy-simulate"

# Simulate the deployment from DEPLOYER's current nonce against Sepolia, through the script that also deploys. Sends nothing.
[group('deploy')]
deploy-simulate:
    #!/usr/bin/env bash
    {{ _prelude }}
    need_env SEPOLIA_EXECUTION_RPC "a Sepolia execution RPC"
    [[ "$DEPLOYER" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "set DEPLOYER to the deployer's address: the simulation runs from its nonce"
    need "$DEPLOY_WORK/escrow-params.json" "run: just deploy-params"
    check_funding
    rm -f "$DEPLOY_WORK/escrow-params.json.expected.json" "$DEPLOY_WORK/simulation.json" \
      "$DEPLOY_WORK/simulation.params.json"
    # `--rpc-url sepolia` names foundry.toml's endpoint, which reads SEPOLIA_EXECUTION_RPC: without an RPC, forge
    # would simulate on a local chain. Check that it answers as Sepolia before simulating.
    chain=$(cd contracts/solidity && cast chain-id --rpc-url sepolia) || die "the Sepolia RPC did not answer eth_chainId"
    [ "$chain" = 11155111 ] || die "the RPC in SEPOLIA_EXECUTION_RPC serves chain $chain, not Sepolia (11155111)"
    cp "$DEPLOY_WORK/escrow-params.json" "$DEPLOY_WORK/simulation.params.json.part"
    (cd contracts/solidity && FOUNDRY_PROFILE=deploy DEPLOY_PARAMS="../../$DEPLOY_WORK/escrow-params.json" \
      forge script script/DeployBridgeEscrow.s.sol --rpc-url sepolia --sender "$DEPLOYER" \
        --gas-estimate-multiplier "$DEPLOY_GAS_MULTIPLIER")
    cmp -s "$DEPLOY_WORK/escrow-params.json" "$DEPLOY_WORK/simulation.params.json.part" \
      || die "escrow-params.json changed during the simulation; simulate again"
    mv "$DEPLOY_WORK/escrow-params.json.expected.json" "$DEPLOY_WORK/simulation.json"
    check_deploy_gas
    # The parameters this simulation and its gas check used, written only once both passed: deploy-escrow sends
    # nothing unless escrow-params.json is still these bytes.
    mv "$DEPLOY_WORK/simulation.params.json.part" "$DEPLOY_WORK/simulation.params.json"
    echo "simulated escrow $(jget "$DEPLOY_WORK/simulation.json" escrow), runtime code hash" \
      "$(jget "$DEPLOY_WORK/simulation.json" codeHash), $(jget "$DEPLOY_WORK/simulation.json" runtimeBytes) bytes"
    echo "next: just deploy-escrow, which sends one Sepolia transaction after a prompt"

# Deploy the simulated escrow to Sepolia with the deployer's key (DEPLOY_ACCOUNT, or DEPLOY_KEYSTORE with
# DEPLOY_PASSWORD_FILE), after checking that the key is DEPLOYER's and that DEPLOYER's next contract address is the
# simulated escrow, and after a confirmation prompt.
[group('deploy')]
deploy-escrow:
    #!/usr/bin/env bash
    {{ _prelude }}
    lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
    absolute() { (cd "$(dirname "$1")" && printf '%s/%s\n' "$PWD" "$(basename "$1")"); }
    outside_git() {  # refuse a key or password file that Git would track
      if git check-ignore -q -- "$1" 2>/dev/null; then :; else
        [ $? -ne 1 ] || die "$1 is inside the repository and not ignored by git; keep it under target/ or outside"
      fi
    }
    need_env SEPOLIA_EXECUTION_RPC "a Sepolia execution RPC"
    [[ "$DEPLOYER" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "set DEPLOYER to the deployer's address"
    need "$DEPLOY_WORK/simulation.json" "run: just deploy-simulate"
    need "$DEPLOY_WORK/simulation.params.json" "run: just deploy-simulate; it writes this once its gas check passes"
    [ ! -e "$DEPLOY_WORK/deployed.json" ] || die "$DEPLOY_WORK/deployed.json exists: this escrow is already deployed"
    sim=$(jget "$DEPLOY_WORK/simulation.json" escrow)

    # The signer: a named keystore, or a keystore file with its password file. Never both, never neither.
    if [ -n "$DEPLOY_KEYSTORE$DEPLOY_PASSWORD_FILE" ]; then
      [ -z "$DEPLOY_ACCOUNT" ] || die "set DEPLOY_ACCOUNT, or DEPLOY_KEYSTORE with DEPLOY_PASSWORD_FILE, not both"
      [ -n "$DEPLOY_KEYSTORE" ] && [ -n "$DEPLOY_PASSWORD_FILE" ] || die "DEPLOY_KEYSTORE and DEPLOY_PASSWORD_FILE are set together"
      for f in "$DEPLOY_KEYSTORE" "$DEPLOY_PASSWORD_FILE"; do
        [ -f "$f" ] && [ -r "$f" ] || die "$f is not a readable file"
        outside_git "$f"
      done
      mode=$(stat -f %Lp "$DEPLOY_PASSWORD_FILE" 2>/dev/null || stat -c %a "$DEPLOY_PASSWORD_FILE")  # BSD, then GNU
      [[ "$mode" =~ [0-7]00$ ]] || die "$DEPLOY_PASSWORD_FILE has mode $mode: other users may read it; chmod 600 it"
      signer=(--keystore "$(absolute "$DEPLOY_KEYSTORE")" --password-file "$(absolute "$DEPLOY_PASSWORD_FILE")")
    elif [ -n "$DEPLOY_ACCOUNT" ]; then
      signer=(--account "$DEPLOY_ACCOUNT")
    else
      die "set DEPLOY_ACCOUNT to a keystore name (cast wallet list), or DEPLOY_KEYSTORE and DEPLOY_PASSWORD_FILE"
    fi
    key=$(cast wallet address "${signer[@]}") || die "cast could not open the deployer's keystore"
    [ "$(lower "$key")" = "$(lower "$DEPLOYER")" ] || die "the keystore holds the key of $key, not DEPLOYER $DEPLOYER"

    # The same chain, nonce and parameters as the simulation, so the escrow lands at the simulated address with the
    # simulated code (DOMAIN, an immutable, names that address) and the transaction is the one whose gas was checked.
    as_simulated() {
      cmp -s "$DEPLOY_WORK/escrow-params.json" "$DEPLOY_WORK/simulation.params.json" \
        || die "escrow-params.json is not the simulated parameters; run just deploy-simulate again"
      next=$(cd contracts/solidity && cast compute-address "$DEPLOYER" --rpc-url sepolia) \
        || die "could not read DEPLOYER's nonce from the Sepolia RPC"
      next=${next##* }
      [ "$(lower "$next")" = "$(lower "$sim")" ] \
        || die "DEPLOYER's next contract address is $next, not the simulated $sim: its nonce moved; run just deploy-simulate again"
    }
    chain=$(cd contracts/solidity && cast chain-id --rpc-url sepolia) || die "the Sepolia RPC did not answer eth_chainId"
    [ "$chain" = 11155111 ] || die "the RPC in SEPOLIA_EXECUTION_RPC serves chain $chain, not Sepolia (11155111)"
    as_simulated
    check_deploy_gas

    [ -r /dev/tty ] || die "deploy-escrow needs a terminal for confirmation"
    read -r -p "Deploy BridgeEscrow to Sepolia from $DEPLOYER, expected at $sim? Type yes: " answer </dev/tty
    [ "$answer" = yes ] || die "not sent"
    # Again after the prompt, which may have waited: immediately before the Sepolia broadcast.
    as_simulated
    check_funding
    rm -f "$DEPLOY_WORK/escrow-params.json.expected.json"
    (cd contracts/solidity && FOUNDRY_PROFILE=deploy DEPLOY_PARAMS="../../$DEPLOY_WORK/escrow-params.json" \
      forge script script/DeployBridgeEscrow.s.sol --rpc-url sepolia --sender "$DEPLOYER" "${signer[@]}" \
        --gas-estimate-multiplier "$DEPLOY_GAS_MULTIPLIER" --broadcast)
    python3 - "$DEPLOY_WORK" <<'PY'
    import json, sys
    from pathlib import Path
    work = Path(sys.argv[1])
    run = json.loads((work / "broadcast/DeployBridgeEscrow.s.sol/11155111/run-latest.json").read_text())
    sim = json.loads((work / "simulation.json").read_text())
    built = json.loads((work / "escrow-params.json.expected.json").read_text())
    dry = json.loads((work / "broadcast/DeployBridgeEscrow.s.sol/11155111/dry-run/run-latest.json").read_text())
    receipt = run["receipts"][0]
    if receipt.get("status") != "0x1":
        sys.exit(f"the deployment transaction {receipt.get('transactionHash')} failed")
    escrow = receipt["contractAddress"].lower()
    if escrow != sim["escrow"].lower() or built["codeHash"] != sim["codeHash"]:
        sys.exit(f"deployed {escrow}, simulated {sim['escrow']}: the nonce or the parameters changed; re-simulate before recording")
    # Storage parameters (the checkpoint, depositsEnd) do not reach the code hash: the sent creation code and
    # arguments must be the simulated ones, whose gas limit check_deploy_gas compared with Sepolia's estimate.
    sent, simulated = run["transactions"][0]["transaction"], dry["transactions"][0]["transaction"]
    if (sent["input"], sent["gas"]) != (simulated["input"], simulated["gas"]):
        sys.exit(f"the sent transaction {receipt['transactionHash']} is not the simulated one; do not record it")
    deployed = {"escrow": escrow, "transaction": receipt["transactionHash"], "block": int(receipt["blockNumber"], 16)}
    (work / "deployed.json").write_text(json.dumps(deployed, indent=1) + "\n")
    print(f"deployed {escrow} in transaction {deployed['transaction']}, Sepolia block {deployed['block']}")
    PY
    echo "next: just deploy-anchor <a finalized epoch-boundary slot>"

# The weak-subjectivity anchor: proof inputs from a light-client bootstrap at <slot>, which the first proof starts from.
[group('deploy')]
deploy-anchor slot:
    #!/usr/bin/env bash
    {{ _prelude }}
    need_env SEPOLIA_EXECUTION_RPC "a Sepolia execution RPC serving eth_getProof at the finalized block"
    need_env SEPOLIA_CONSENSUS_RPC "a Sepolia beacon API that serves a light-client bootstrap at the slot"
    need "$BRIDGE_HOST_BIN" "run: just prover"
    need "$DEPLOY_WORK/deployed.json" "run: just deploy-escrow"
    [[ "$slot" =~ ^[1-9][0-9]*$ ]] && (( slot % 32 == 0 )) || die "slot must be an epoch boundary, a multiple of 32"
    e=$(jget "$DEPLOY_WORK/deployed.json" escrow)
    rm -f "$DEPLOY_WORK/anchor-inputs.cbor" "$DEPLOY_WORK/anchor.json"
    "$BRIDGE_HOST_BIN" inputs --anchor-slot "$slot" --escrow "$e" --out "$DEPLOY_WORK/anchor-inputs.cbor"
    "$BRIDGE_HOST_BIN" anchor "$DEPLOY_WORK/anchor-inputs.cbor" > "$DEPLOY_WORK/anchor.json"
    anchor_store
    echo "anchor: slot $(jget "$DEPLOY_WORK/anchor.json" anchor slot), lc $(jget "$DEPLOY_WORK/anchor.json" anchor lc)"
    echo "starting store: $DEPLOY_WORK/anchor.store.json, rebuilt offline from the anchor inputs and hashing to that lc"
    echo "keep $DEPLOY_WORK/anchor-inputs.cbor: deploy-record rebuilds the starting store from it"
    echo "next: just deploy-record"

# Write BRIDGE_INSTANCE/instance.json from the deployed escrow, read back from Sepolia, the guest build and the anchor,
# and beside it the anchor's starting store, lc_stores/<anchor slot>.json, rebuilt offline from the anchor inputs,
# with its lc_preimages.json entry (head, roots and store; a starting store names no update transaction).
# The constructor's storage is read at the deployment block, so SEPOLIA_EXECUTION_RPC must serve historical state
# (an archive node); relaying headers after the deployment moves the current tip and does not affect the record.
[group('deploy')]
deploy-record:
    #!/usr/bin/env bash
    {{ _prelude }}
    need_env SEPOLIA_EXECUTION_RPC "a Sepolia execution RPC that serves state at the escrow's deployment block (an archive node)"
    need "$BRIDGE_HOST_BIN" "run: just prover"
    need "$BRIDGE_ELF" "run: just prover, or set BRIDGE_ELF"
    for f in escrow-params.json checkpoint.json simulation.json deployed.json anchor.json; do need "$DEPLOY_WORK/$f"; done
    check_funding
    [ ! -e "$BRIDGE_INSTANCE/instance.json" ] || die "$BRIDGE_INSTANCE/instance.json exists; deploy-record never overwrites a record"
    for f in lc_preimages.json lc_stores; do
      [ ! -e "$BRIDGE_INSTANCE/$f" ] || die "$BRIDGE_INSTANCE/$f exists; deploy-record never overwrites published light-client data"
    done
    anchor_store
    export ETH_RPC_URL="$SEPOLIA_EXECUTION_RPC"
    e=$(jget "$DEPLOY_WORK/deployed.json" escrow)
    tx=$(jget "$DEPLOY_WORK/deployed.json" transaction)
    b=$(jget "$DEPLOY_WORK/deployed.json" block)
    [[ "$e" =~ ^0x[0-9a-fA-F]{40}$ ]] && [[ "$tx" =~ ^0x[0-9a-fA-F]{64}$ ]] && [[ "$b" =~ ^[1-9][0-9]*$ ]] \
      || die "$DEPLOY_WORK/deployed.json does not give an escrow address, transaction hash and block number"
    # cast's own errors are dropped below: a connection error can print the RPC URL, and any key in it.
    chain=$(cast chain-id 2>/dev/null) || die "the Sepolia RPC did not answer eth_chainId"
    [ "$chain" = 11155111 ] || die "the RPC in SEPOLIA_EXECUTION_RPC serves chain $chain, not Sepolia (11155111)"
    # The block of the deployment, from the chain rather than deployed.json alone, and final.
    cast receipt "$tx" --json > "$DEPLOY_WORK/receipt.json" 2>/dev/null || die "the Sepolia RPC did not return the receipt of $tx"
    cast block finalized --json > "$DEPLOY_WORK/finalized.json" 2>/dev/null \
      || die "the Sepolia RPC did not return its finalized block"
    # The checkpoint and deposit window are storage, outside the code hash: read them as raw 32-byte words, at the
    # deployment block (the constructor's values) and now (the code must still be there).
    readback() {  # readback <block>: one JSON object of the escrow's code hash, immutables and storage at <block>
      local q v sep='{'
      for q in codeHash 'DOMAIN()(bytes32)' 'BRIDGE_ASSET()(bytes32)' 'lcTipHash()' 'lcTipHeight()' \
          'signblockscriptHash()' 'depositsEnd()'; do
        if [ "$q" = codeHash ]; then v=$(cast codehash "$e" --block "$1" 2>/dev/null)
        else v=$(cast call "$e" "$q" --block "$1" 2>/dev/null); fi \
          || die "the Sepolia RPC could not read ${q%%(*} of $e at block $1; deploy-record needs an RPC that serves" \
            "state at the deployment block (an archive node)"
        printf '%s "%s": "%s"' "$sep" "${q%%(*}" "$v"; sep=,
      done
      echo ' }'
    }
    { echo '{"deployment":'; readback "$b"; echo ', "current":'; readback latest; echo '}'; } > "$DEPLOY_WORK/readback.json"
    "$BRIDGE_HOST_BIN" vkey --elf "$BRIDGE_ELF" > "$DEPLOY_WORK/vkey.json"
    python3 - "$DEPLOY_WORK" "$BRIDGE_INSTANCE" "$DEPLOY_GUEST_ELF_SHA256" "$DEPLOY_PROGRAM_VKEY" <<'PY'
    import json, re, sys
    from pathlib import Path
    sys.path.insert(0, "tools/sg16/bridge-guest/testnet")
    import pins
    work, record, elf_pin, vkey_pin = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4]
    read = lambda f: json.loads((work / f).read_text())
    hx = lambda h: str(h).lower().removeprefix("0x")
    params, sim, deployed, anchor = read("escrow-params.json"), read("simulation.json"), read("deployed.json"), read("anchor.json")
    chain, guest, receipt, final = read("readback.json"), read("vkey.json"), read("receipt.json"), read("finalized.json")
    at, now, block = chain["deployment"], chain["current"], deployed["block"]
    problems = []

    def need(ok, what):
        if not ok:
            problems.append(what)

    num = lambda v: int(v, 16) if isinstance(v, str) and re.fullmatch(r"0x[0-9a-fA-F]+", v) else v if type(v) is int else None
    need(num(receipt.get("status")) == 1 and hx(receipt.get("transactionHash")) == hx(deployed["transaction"])
         and hx(receipt.get("contractAddress")) == hx(deployed["escrow"]) and num(receipt.get("blockNumber")) == block,
         f"Sepolia's receipt of {deployed['transaction']} is the successful creation of {deployed['escrow']} in block {block}")
    need((num(final.get("number")) or 0) >= block, f"block {block} is finalized")
    need(hx(at["codeHash"]) == hx(now["codeHash"]) == hx(sim["codeHash"]),
         "the deployed runtime code, at the deployment block and now, is the local FOUNDRY_PROFILE=deploy simulation's")
    need(hx(at["DOMAIN"]) == hx(sim["domain"]), "DOMAIN() is the simulation's")
    need(hx(at["BRIDGE_ASSET"]) == hx(params["bridgeAsset"]), "BRIDGE_ASSET() is the funding outpoint's asset")
    word = lambda s, k: int(s[k], 16) if re.fullmatch(r"0x[0-9a-fA-F]{64}", s[k]) else None
    cp, checkpoint = params["checkpoint"], read("checkpoint.json")
    # The constructor's storage, at the end of the deployment block: a later transaction in that block that relays
    # headers or moves depositsEnd makes this refuse, never accept.
    # Internal byte order on chain; hashId is the displayed block hash compared with an independent explorer.
    need(word(at, "lcTipHash") == int(cp["hash"], 16) == int.from_bytes(bytes.fromhex(checkpoint["hashId"])[::-1], "big"),
         f"lcTipHash() at block {block} is block {checkpoint['hashId']} of the checkpoint, in internal byte order")
    need(word(at, "lcTipHeight") == cp["height"] == checkpoint["height"], f"lcTipHeight() at block {block} is the checkpoint height")
    need(word(at, "signblockscriptHash") == int(cp["signblockscriptKeccak"], 16),
         f"signblockscriptHash() at block {block} is keccak256 of the checkpoint's signing script")
    need(word(at, "depositsEnd") == params["admission"]["depositsEnd"], f"depositsEnd() at block {block} is the parameter file's")
    # Since then relaying only raises the tip, and depositsEnd only moves earlier.
    tip, end = word(now, "lcTipHeight"), word(now, "depositsEnd")
    need(tip is not None and tip >= cp["height"], "lcTipHeight() now is at or above the checkpoint height")
    need(end is not None and end <= params["admission"]["depositsEnd"], "depositsEnd() now is at or before the parameter file's")
    need((hx(guest["elf_sha256"]), hx(guest["vkey"])) == (elf_pin, vkey_pin),
         f"the ELF gives {hx(guest['elf_sha256'])} and vkey {hx(guest['vkey'])}, not the pinned guest build")
    net = anchor["network"]
    need(net["is_sepolia"], "the anchor inputs are Sepolia's")
    need(pins.SEPOLIA_CONFIG == hx(net["config"]), "pins.py SEPOLIA_CONFIG is the anchor inputs' config (just deploy-config)")
    need(any(hx(s["address"]) == hx(deployed["escrow"]) for s in anchor["storage"]), "the anchor inputs read this escrow")
    a = anchor["anchor"]
    store_raw = (work / "anchor.store.json").read_bytes()
    store = json.loads(store_raw)
    need((store.get("head"), hx(store.get("header")), hx(store.get("committee")), hx(store.get("lc")))
         == (a["slot"], hx(a["header"]), hx(a["committee"]), hx(a["lc"]))
         and pins.lc(a["slot"], bytes.fromhex(hx(a["header"])), bytes.fromhex(hx(a["committee"]))).hex() == hx(a["lc"]),
         "anchor.store.json is the anchor's slot, header, committee and lc")
    if problems:
        sys.exit("refused:\n  " + "\n  ".join(problems))

    doc = {
        "name": record.name,
        "ESCROW": hx(deployed["escrow"]),
        "ESCROW_CODE_HASH": hx(at["codeHash"]),
        "ESCROW_DEPLOY_BLOCK": deployed["block"],
        "DEPOSIT_DOMAIN": hx(at["DOMAIN"]),
        "GUEST_ELF_SHA256": elf_pin,
        "PROGRAM_VKEY": vkey_pin,
        "ANCHOR": {"slot": a["slot"], "header": hx(a["header"]), "committee": hx(a["committee"]), "lc": hx(a["lc"])},
        "sources": {
            "ESCROW": f"Sepolia transaction {deployed['transaction']} in block {deployed['block']}; its runtime code hash equals a "
                      "local FOUNDRY_PROFILE=deploy build simulated from the same deployer nonce; its checkpoint and "
                      "depositsEnd, read at that block, are the simulated parameters",
            "GUEST": "just prover (SP1 6.8.1, Docker image v6.8.1) from this checkout; sg16-bridge-host vkey",
            "ANCHOR": f"sg16-bridge-host anchor of inputs from a light-client bootstrap at slot {a['slot']}",
        },
    }
    draft = work / "instance.json"
    draft.write_text(json.dumps(doc, indent=1) + "\n")
    bad = pins.check(pins.load(draft))
    if bad:
        sys.exit("pins.py refuses the record:\n  " + "\n  ".join(bad))
    # The starting store's entry has no update: it is the anchor, which the bootstrap starts from. Later entries name
    # the update transaction that reached their head (stage-store, stage-recovered).
    rel = f"lc_stores/{a['slot']}.json"
    preimages = {
        "about": "The starting store is public. Publish every successor store and the transaction ID of the update that "
                 "reached it before broadcasting that update.",
        "preimages": [{"head": a["slot"], "header": hx(a["header"]), "committee": hx(a["committee"]), "store": rel}],
    }
    # Exclusive creation throughout: nothing already in the record is replaced, even if it appeared since the
    # recipe's own check.
    record.mkdir(parents=True, exist_ok=True)
    (record / "lc_stores").mkdir()
    with open(record / rel, "xb") as f:
        f.write(store_raw)
    with open(record / "lc_preimages.json", "x") as f:
        f.write(json.dumps(preimages, indent=1) + "\n")
    with open(record / "instance.json", "x") as f:
        f.write(draft.read_text())
    print(f"constructor storage read back at Sepolia block {block}; now the light client is at Liquid height {tip}"
          + ("" if end == params["admission"]["depositsEnd"] else f" and depositsEnd has moved earlier, to {end}"))
    print(f"wrote {record / 'instance.json'}, {record / rel} and {record / 'lc_preimages.json'}")
    PY
    head=$(jget "$DEPLOY_WORK/anchor.json" anchor slot); lc=$(jget "$DEPLOY_WORK/anchor.json" anchor lc)
    "$BRIDGE_HOST_BIN" check-store "$BRIDGE_INSTANCE/lc_stores/$head.json" --lc "$lc" > "$DEPLOY_WORK/record.check-store.json" \
      || die "$BRIDGE_INSTANCE/lc_stores/$head.json, as written, does not hash to the anchor lc $lc; do not publish it"
    echo "starting store $BRIDGE_INSTANCE/lc_stores/$head.json read back: it hashes to the anchor lc; next: just deploy-manifest"

# Build the Liquid manifest, initial state and update leaf of the record (minutes: the update leaf's verifier).
[group('deploy')]
deploy-manifest:
    #!/usr/bin/env bash
    {{ _prelude }}
    need "$TX_BIN" "run: just tools"
    need "$BRIDGE_INSTANCE/instance.json" "run: just deploy-record"
    [ ! -e "$BRIDGE_INSTANCE/manifest.json" ] || die "$BRIDGE_INSTANCE/manifest.json exists; deploy-manifest never overwrites it"
    funding=$(jget "$DEPLOY_WORK/escrow-params.json" funding)
    rm -f "$DEPLOY_WORK/manifest.assemble.json"
    if ! python3 "$ASSEMBLE_PY" manifest --report "$DEPLOY_WORK/manifest.assemble.json" \
        --instance "$BRIDGE_INSTANCE/instance.json" --funding-txid "${funding%:*}" --funding-vout "${funding#*:}" \
        --out "$BRIDGE_INSTANCE" > "$DEPLOY_WORK/manifest.assemble.log"; then
      gate "$DEPLOY_WORK/manifest.assemble.json"
      die "assemble.py manifest refused ($DEPLOY_WORK/manifest.assemble.json)"
    fi
    [ "$(jget "$BRIDGE_INSTANCE/manifest.json" deployable)" = true ] || die "the manifest is not deployable; see its gates"
    [ "0x$(jget "$BRIDGE_INSTANCE/manifest.json" bootstrap asset)" = "$(jget "$DEPLOY_WORK/escrow-params.json" bridgeAsset)" ] \
      || die "the manifest's asset is not the escrow's BRIDGE_ASSET"
    echo "state address $(jget "$BRIDGE_INSTANCE/manifest.json" state_tree address); next: just deploy-bootstrap <fee sats>"

# Build and sign the bootstrap: the issuance of the bridge asset's one reissuance token into the state address.
[group('deploy')]
deploy-bootstrap fee:
    #!/usr/bin/env bash
    {{ _prelude }}
    [[ "$fee" =~ ^[1-9][0-9]*$ ]] || die 'fee must be a positive number of sats'
    need_key
    need "$WALLET_BIN" "run: just tools"
    need "$BRIDGE_INSTANCE/manifest.json" "run: just deploy-manifest"
    funding=$(jget "$DEPLOY_WORK/escrow-params.json" funding); txid=${funding%:*}; vout=${funding#*:}
    f=$(tx_file "$txid")
    check_funding
    spk=$("$WALLET_BIN" address "$LIQUID_FEE_KEY" | jget - script_pubkey)
    w=$DEPLOY_WORK
    rm -f "$w/bootstrap.hex" "$w/bootstrap.signed.hex" "$w/bootstrap.signed.hex.meta.json" "$w/bootstrap.assemble.json"
    if ! python3 "$ASSEMBLE_PY" bootstrap --report "$w/bootstrap.assemble.json" \
        --instance "$BRIDGE_INSTANCE/instance.json" --manifest "$BRIDGE_INSTANCE/manifest.json" \
        --funding-tx "$f" --fee "$fee" --change-spk "$spk" --out "$w/bootstrap.hex" > "$w/bootstrap.assemble.log"; then
      gate "$w/bootstrap.assemble.json"
      die "assemble.py bootstrap refused ($w/bootstrap.assemble.json)"
    fi
    r=$("$WALLET_BIN" sign "$LIQUID_FEE_KEY" "$w/bootstrap.hex" 0 "$f" "$vout" "$w/bootstrap.signed.hex")
    id=$(echo "$r" | jget - txid)
    check_txid "$w/bootstrap.signed.hex" "$id"
    meta "$w/bootstrap.signed.hex" kind=bootstrap txid="$id" parents="$txid" source_vout="$vout"
    echo "signed bootstrap $id; next: just broadcast $w/bootstrap.signed.hex, just wait $id, then just deploy-verify"

# After the bootstrap confirms: check the public transaction against the record and the escrow, and add it to the record.
[group('deploy')]
deploy-verify:
    #!/usr/bin/env bash
    {{ _prelude }}
    need_env SEPOLIA_EXECUTION_RPC "a Sepolia execution RPC"
    need "$DEPLOY_WORK/bootstrap.signed.hex.meta.json" "run: just deploy-bootstrap"
    id=$(jget "$DEPLOY_WORK/bootstrap.signed.hex.meta.json" txid)
    confirmed "$id" || die "bootstrap $id is not confirmed yet: just wait $id"
    public=$(tx_file "$id")
    e=$(jget "$DEPLOY_WORK/deployed.json" escrow)
    asset=$(ETH_RPC_URL="$SEPOLIA_EXECUTION_RPC" cast call "$e" 'BRIDGE_ASSET()(bytes32)')
    rm -f "$DEPLOY_WORK/verify-bootstrap.json"
    if ! python3 "$ASSEMBLE_PY" verify-bootstrap --report "$DEPLOY_WORK/verify-bootstrap.json" \
        --instance "$BRIDGE_INSTANCE/instance.json" --manifest "$BRIDGE_INSTANCE/manifest.json" \
        --bootstrap-tx "$public" --escrow-asset "$asset" > "$DEPLOY_WORK/verify-bootstrap.log"; then
      gate "$DEPLOY_WORK/verify-bootstrap.json"
      die "verify-bootstrap refused the public bootstrap ($DEPLOY_WORK/verify-bootstrap.json)"
    fi
    if [ -e "$BRIDGE_INSTANCE/bootstrap.hex" ]; then
      cmp -s "$public" "$BRIDGE_INSTANCE/bootstrap.hex" || die "$BRIDGE_INSTANCE/bootstrap.hex holds another transaction"
    else
      cp "$public" "$BRIDGE_INSTANCE/bootstrap.hex"
    fi
    echo "bootstrap $id verified against $BRIDGE_INSTANCE and escrow $e's BRIDGE_ASSET"
    echo "next, to open deposits: relay Liquid to its tip (relay.py batches) and send a fork proof (fork_proof.py build --escrow $e);"
    echo "then review the record, set bridge-core/config.js INSTANCE and the live-state pin in their own commit, and publish"
