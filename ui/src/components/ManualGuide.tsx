import { PUBLISHED } from '@bridge/core/config.js';
import { useBridge } from '../bridge/context';
import { LIQUID_FAUCET, REPO } from '../content/links';
import { Button, CopyLine, ExtLink, Step } from './primitives';

const SETUP = `git clone --branch ${PUBLISHED.branch} ${REPO}.git
cd zk-bridge`;

const RPC = `export SEPOLIA_EXECUTION_RPC='YOUR_EXECUTION_RPC_URL'
export SEPOLIA_CONSENSUS_RPC='YOUR_BEACON_API_URL'`;

/** Local proof preparation, followed by browser-built updates and claims. */
export function ManualGuide({ onUpdate, onClaim, onRedeem }: {
  onUpdate: () => void;
  onClaim: () => void;
  onRedeem: () => void;
}) {
  const { instance } = useBridge();

  return (
    <section className="tray" id="guide" aria-labelledby="guide-title">
      <div className="panel-head">
        <h2 className="tray-title" id="guide-title">Bridge guide</h2>
        <p className="hint">Anyone can prove, claim and relay. Already proven? <a href="#claim" onClick={() => onClaim()}>Skip to claim</a>.</p>
      </div>
      {!instance ? <p className="help">No bridge instance is available.</p> : (
        <ol className="steps-form">
          <Step n={1} title="Deposit">
            <p className="help">Use an Ethereum wallet on Sepolia and desktop Humid on Liquid testnet. Humid signing is unavailable on mobile.
              Choose Use Humid address when depositing, or paste its Receive → Unconfidential address. Keep SepETH for gas.</p>
            <p className="help">Get <ExtLink href={LIQUID_FAUCET}>testnet tL-BTC</ExtLink> at Humid's Receive → Confidential address for fees.
              Wait for Ethereum finality after depositing.</p>
            <p className="warn">Your deposit stays locked until proven and claimed. There is no refund.</p>
          </Step>
          <Step n={2} title="Prepare the proof">
            <p className="help">Only unproven deposits need this local step.</p>
            <details className="aside-form">
              <summary>Local setup</summary>
              <p className="help">Install Git, Rust/Cargo, Python 3.9+, Node.js 22.13+ in the 22.x series, just, Go, protoc, CMake,
                LLVM/libclang, pkg-config, OpenSSL 3 and Docker. On macOS, install Xcode Command Line Tools. Keep Docker running during setup.</p>
              <div style={{ whiteSpace: 'pre-wrap' }}>
                <CopyLine label="Clone repository" value={SETUP} />
                <CopyLine label="Choose bridge instance" value={`export BRIDGE_INSTANCE='${instance.record.replace(/\/$/, '')}'`} />
                <CopyLine label="Configure Sepolia RPCs" value={RPC} />
                <CopyLine label="Build proof tools" value="just deps tools prover check-elf" />
              </div>
              <p className="help">Replace both RPC placeholders. The execution RPC must serve logs, calls and <code className="mono">eth_getProof</code> at
                finalized blocks; the beacon API must serve light-client updates. Keep RPC credentials private.</p>
              <p className="help">Proving can exceed 16 GB RAM. Use a larger machine if needed; wallet signing stays in your browser.</p>
            </details>
            <CopyLine label="Check deposits" value="just status" />
            <p className="help">Find your deposit number from Activity. If it is proven, skip to claim. If its store is missing, run
              <code className="mono"> just reconstruct</code>. Once final, run:</p>
            <CopyLine label="Generate proof" value="just inputs execute prove" />
            <details className="aside-form">
              <summary>Low on memory?</summary>
              <p className="help">Run <code className="mono">just inputs execute</code> first, then use this instead of <code className="mono">just prove</code>:</p>
              <CopyLine label="Generate proof with less memory" value="RUST_LOG=info just prove low-memory" />
              <p className="help">Fewer workers and smaller batches reduce memory use, but proving takes longer and can still exceed 16 GB RAM.</p>
            </details>
            <p className="help">This writes <code className="mono">target/takeover/proof.browser.json</code>. Before generating another proof,
              move any existing <code className="mono">proof.json</code> and matching <code className="mono">proof.store.json</code> aside.</p>
          </Step>
          <Step n={3} title="Send the update">
            <p className="help">Load <code className="mono">proof.browser.json</code> in Send update, prepare the fee, then review and sign in Humid. The page builds the transaction. Wait for confirmation.</p>
            <div className="actions">
              <Button onClick={onUpdate}>Open update</Button>
            </div>
            <p className="help">If another claim changes the state first, run <code className="mono">just proof-bundle</code> and reload the file.
              If another update makes the proof stale, check <code className="mono">just status</code> before proving again.</p>
            <details className="aside-form">
              <summary>Optional: publish the store</summary>
              <p className="help">After the update confirms, stage your local <code className="mono">proof.store.json</code>.
                This finds its transaction on Liquid and checks the store before copying it into the instance record.</p>
              <CopyLine label="Stage generated store" value="just stage-generated" />
              <p className="help">Review the files, then commit them:</p>
              <CopyLine label="Review store files" value={`git add -- ${instance.record}lc_stores ${instance.record}lc_preimages.json\ngit diff --cached --check\ngit diff --cached`} />
              <CopyLine label="Commit store files" value={'git commit -m "Publish light-client store"'} />
              <p className="help">With write access to the project, push to its publication branch:</p>
              <CopyLine label="Push store files" value={`git push ${REPO}.git HEAD:${PUBLISHED.branch}`} />
              <p className="help">Otherwise push to your fork and open a pull request in the <ExtLink href={REPO}>repository</ExtLink>.
                The site serves the store after its next deployment. You can also share the file directly with the next prover.
                Uploading it here does not publish it.</p>
              <p className="warn">Withholding the store can stall later proofs. Recovery needs matching retained beacon data or saved proof inputs;
                without either, recovery may be impossible.</p>
            </details>
          </Step>
          <Step n={4} title="Claim on Liquid">
            <p className="help">Once proven, enter the deposit number in Claim, prepare its fee, and review and sign in Humid.
              The page builds the claim; no new proof is needed. It pays the original Liquid recipient. Wait for confirmation.</p>
            <p className="help">Connect a Sepolia wallet or set a custom RPC in Settings. Claim preparation reads deposit logs since deployment.</p>
            <p className="warn">Update and claim each spend their entire selected fee coin. Check the fee before signing.
              If a broadcast is uncertain, check its transaction before retrying.</p>
            <div className="actions">
              <Button onClick={onClaim}>Open claim</Button>
            </div>
          </Step>
          <Step n={5} title="Redeem on Sepolia">
            <p className="help">In Redeem, enter the ETH recipient and amount, burn through Humid, then track the burn.
              After confirmations, relay any missing headers and redeem. Anyone can submit the proof; the named recipient receives the ETH.</p>
            <p className="warn">Burning is irreversible. Use the exact script shown and review the recipient.</p>
            <div className="actions">
              <Button onClick={onRedeem}>Open redeem</Button>
            </div>
          </Step>
        </ol>
      )}
    </section>
  );
}
