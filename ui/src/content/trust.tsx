// "What you are trusting": how the bridge works, what anyone can do without asking anyone and what each step needs,
// what each step costs, then each assumption with how it stands on the instance this page serves. The Humid fee
// figures come from lib/humid.js, so they cannot drift from the code.
//
// Each "On this instance" line is built from what the page already holds, so no copy has to be rewritten for a new
// deployment: the pins of config.js INSTANCE (escrow, code hash, bootstrap, state address), the escrow's own settings
// once its code hash matches the pin (BridgeState.bridge), the bootstrap check, and the Liquid API's tip. Pins the
// page does not read (anchor, guest, covenant leaves, light-client stores) are named by the record file that holds
// them, which the site publishes beside the page. With no instance, or an escrow the page refuses, the line says so
// and shows none of the escrow's settings.
import { DEFAULTS, type Instance } from '@bridge/core/config.js';
import type { ReactNode } from 'react';
import { HUMID_FEE } from '../bridge/approval';
import { admission, burnAsset, relayLag, signersAhead } from '../bridge/derive';
import { plural, short } from '../bridge/format';
import type { BridgeReads, BridgeState } from '../bridge/types';
import { ExtLink } from '../components/primitives';
import { LIMITS, REPO, SITE, TAKEOVER } from './links';

const Code = ({ children }: { children: ReactNode }) => <code className="mono">{children}</code>;

export const HOW_IT_WORKS = 'A deposit locks SepETH in the escrow on Sepolia and names a Liquid script. Once Sepolia finalizes it, anyone can prove that '
  + 'to Liquid with an SP1 proof of Sepolia\'s light client, which the Liquid covenant verifies, and then claim it: the covenant pays the bridge asset to '
  + 'exactly the script the deposit named, once, in any order. To come back, the holder burns the asset on Liquid in an output whose script names an '
  + 'Ethereum recipient. Once the burn has the escrow\'s required Liquid confirmations and Liquid\'s signed headers up to them are relayed to the escrow, '
  + 'anyone can prove the burn, and the escrow pays that recipient. No admin key can move or rescue funds on either side; the points below say whose '
  + 'failure could still cost them.';

const NONE = 'No instance is published yet.';

/** `f` of the published instance, or that none is published, followed by `none`. */
const on = (s: BridgeState, f: (i: Instance) => ReactNode, none = '') => (s.instance ? f(s.instance) : none ? `${NONE} ${none}` : NONE);

/**
 * `f` of the escrow's settings once the page has read them, which it does only after the escrow's code hash matched
 * the pin; otherwise why there are none, so nothing here comes from an unchecked or unreadable contract.
 */
function escrowSays(s: BridgeState, f: (b: BridgeReads) => ReactNode): ReactNode {
  if (s.bridgeError) return `The escrow is ${s.bridgeError}, so this page shows none of its settings.`;
  if (!s.bridge) return 'Connect a wallet on Sepolia, or set a Sepolia RPC in Settings, to see the escrow\'s settings here.';
  return f(s.bridge);
}

const n = (x: number) => x.toLocaleString('en');
const utc = (seconds: number) => `${new Date(seconds * 1000).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
const span = (seconds: number) => (seconds % 3600 === 0 ? plural(seconds / 3600, 'hour') : plural(Math.round(seconds / 60), 'minute'));

const Escrow = ({ i }: { i: Instance }) => (
  <>escrow <ExtLink href={`${DEFAULTS.ethExplorer}/address/${i.escrow}`}><Code>{short(i.escrow)}</Code></ExtLink></>
);
const Bootstrap = ({ i }: { i: Instance }) => (
  <>bootstrap <ExtLink href={`${DEFAULTS.liquidExplorer}/tx/${i.bootstrap}`}><Code>{short(i.bootstrap)}</Code></ExtLink></>
);
/** A file of the instance record, as this site publishes it beside the page. */
const RecordFile = ({ i, file }: { i: Instance; file: string }) => <a href={`${i.record}${file}`}><Code>{i.record}{file}</Code></a>;
/** The asset a burn may hold, once the bootstrap check confirms the escrow's (derive.burnAsset). */
const asset = (s: BridgeState) => (burnAsset(s) ? short(s.bridge!.assetDisplay) : null);
/** The Liquid API in use, by its host only: a URL may carry an API key. */
const esplora = (s: BridgeState) => (s.settings.esplora === DEFAULTS.esplora ? 'Blockstream\'s public API' : `the Esplora API at ${new URL(s.settings.esplora).host}`);

export interface SelfServe {
  name: 'relay' | 'fork-proof' | 'burn' | 'redeem' | 'prove-claim' | 'audit' | 'sources';
  title: string;
  body: ReactNode;
  needs: ReactNode;
  /** Where the step stands on the instance this page serves. */
  here: (s: BridgeState) => ReactNode;
}

export const SELF_SERVE: SelfServe[] = [
  {
    name: 'relay',
    title: 'Relay Liquid headers to the escrow',
    body: 'You can send them from a redemption\'s row, or from the deposit form when relaying is all that keeps deposits closed. The page sends batches of up to 100 headers, and the escrow checks Liquid\'s block signatures in each, so a relayer cannot lie.',
    needs: <>A Sepolia wallet and gas. Without the page: <Code>bridge-operator relay</Code>, from the repository's <Code>tools/bridge-operator</Code>, builds each batch's calldata from public data.</>,
    here: (s) => on(s, (i) => escrowSays(s, (b) => (
      <>The <Escrow i={i} /> has Liquid's headers up to block {n(b.lcTip)}
        {s.liquid ? `, ${plural(relayLag(s), 'block')} behind the tip the Liquid API reports` : ''}{b.lcTime ? `; the newest is timestamped ${utc(b.lcTime)}` : ''}.
        {admission(s)!.relayReopens ? ' Relaying now reopens deposits.' : ''}</>
    ))),
  },
  {
    name: 'fork-proof',
    title: 'Reopen deposits with a fork proof',
    body: 'You can paste a proof in the deposit form when a stale fork check is what closes deposits. The page checks it against the beacon block root Ethereum itself holds, and the escrow checks it again.',
    needs: <>To build it: a Sepolia beacon node API and <Code>tools/liquid-relay/fork_proof.py</Code>. To send it: a Sepolia wallet and gas.</>,
    here: (s) => on(s, (i) => escrowSays(s, ({ admission: { forkCheckedAt: at, maxForkCheckAge: age } }) => (
      <>{at ? <>The <Escrow i={i} /> last recorded a fork check from {utc(at)}; it counts until {utc(at + age)}, and then deposits pause until another arrives.</>
        : <>The <Escrow i={i} /> has recorded no fork check yet.</>}
        {admission(s)!.forkReopens ? ' A fork proof now reopens deposits.' : ''}</>
    ))),
  },
  {
    name: 'burn',
    title: 'Burn on Liquid',
    body: <>If you hold the units, you can burn them yourself: an explicit (unblinded) output of the bridge asset whose script is exactly the 72-byte <Code>OP_RETURN</Code> the
      Redeem tab shows for your recipient. That script has no address, so a wallet's ordinary Send cannot make it. The Redeem tab builds the whole transaction for
      Humid to review and sign; any other tool that can pay an exact script works too. The Redeem tab shows a burn only after the published bootstrap confirms the
      escrow's asset.</>,
    needs: <>The units at an address the wallet can spend explicit coins from (with Humid, its unconfidential address), and a little tL-BTC for the fee: with Humid,
      at least {HUMID_FEE.minCoin} tL-BTC received at its confidential address and confirmed, of which {HUMID_FEE.sats.toString()} sats pay the fee. No Ethereum
      transaction: the page needs your wallet, or a Sepolia RPC in Settings, only to read the escrow.</>,
    here: (s) => on(s, (i) => (asset(s)
      ? <>A burn holds asset <Code>{asset(s)}</Code>, which the <Bootstrap i={i} /> issues, in a script that names the <Escrow i={i} />.</>
      : <>The Redeem tab shows no burn until this page has read the <Escrow i={i} /> and the <Bootstrap i={i} /> confirms its asset (Bridge checks). Burn nothing until then.</>)),
  },
  {
    name: 'redeem',
    title: 'Redeem a burn on Sepolia',
    body: <>You can submit the proof this page builds from public Liquid data, even for someone else's burn. The escrow pays only the recipient the burn names,
      once per burn output; only that recipient can have it paid elsewhere (<Code>redeemTo</Code>).</>,
    needs: <>The burn's Liquid confirmations, as many as the escrow requires (the page footer shows the number), relayed as above, and a Sepolia wallet and gas.
      Without the page: <Code>bridge-operator redeem</Code> (<Code>tools/bridge-operator</Code>).</>,
    here: (s) => on(s, (i) => escrowSays(s, (b) => (
      <>The <Escrow i={i} /> pays a burn once it has {plural(b.minConf, 'Liquid confirmation')}, counted in the blocks relayed to it.</>
    ))),
  },
  {
    name: 'prove-claim',
    title: 'Prove and claim a finalized deposit',
    body: 'You can prove and claim your deposit, or someone else\'s, in any order. The covenant checks the proof and pays only the script each deposit committed. This page cannot do it: it runs no prover. Once you have built an update and its light-client store is published here, the page can send it with Humid paying the fee (Send a proven update with Humid, below the bridge).',
    needs: <>A computer with Docker and the SP1 6.8.1 toolchain (a proof is about 50 million guest cycles), a Sepolia execution RPC that serves <Code>eth_getProof</Code> at
      the finalized block, a Sepolia beacon node's light-client updates, the anchor store published with this instance for its first proof (and each later store
      published with its update), a clone of the repository, and a little tL-BTC for the update and claim
      fees. If a later update has already proven a deposit, only its claim is left, and that needs no prover. <ExtLink href={TAKEOVER}>The steps are in OPERATOR.md</ExtLink>.</>,
    here: (s) => on(s, (i) => (
      <><Code>BRIDGE_INSTANCE={i.record.replace(/\/$/, '')} just status</Code> recovers this instance's state from Liquid and names the next step. The anchor
        is in <RecordFile i={i} file="instance.json" />, and each published light-client store is listed in <RecordFile i={i} file="lc_preimages.json" />.</>
    )),
  },
  {
    name: 'audit',
    title: 'Check this instance',
    body: <>You can rebuild the Liquid state address from the instance record (<Code>assemble.py verify-bootstrap</Code>), compile the escrow to its published code
      hash, and rebuild the live Liquid state from public transactions (<Code>assemble.py recover</Code>).</>,
    needs: 'A clone of the repository, Python and Foundry, and public chain data.',
    here: (s) => on(s, (i) => (
      <>Its pins are in <RecordFile i={i} file="instance.json" /> (escrow, code hash <Code>{short(`0x${i.codeHash}`)}</Code>, guest and anchor) and
        {' '}<RecordFile i={i} file="manifest.json" /> (asset, state address <Code>{short(i.state, 8)}</Code> and covenant leaves). Give both to
        {' '}<Code>verify-bootstrap</Code>, with the public bytes of the <Bootstrap i={i} />.</>
    )),
  },
  {
    name: 'sources',
    title: 'Choose where this page reads',
    body: 'You can set your own Liquid Esplora API and Sepolia RPC in Settings.',
    needs: 'Nothing else; your wallet still signs every Sepolia transaction.',
    here: (s) => <>This page reads Sepolia through {s.settings.ethRpc ? 'the RPC you set' : 'your wallet'} and Liquid through {esplora(s)}.</>,
  },
];

export const SELF_SERVE_NOTE = 'You need no operator permission for any step above. The page can send relay, fork-check and redemption transactions from your '
  + 'wallet; proving a deposit needs the local tools and services listed above. The deposit closer can end deposits early; it can never reopen them or touch funds.';

export const COSTS: { name: 'deposit' | 'sepolia' | 'burn' | 'prove-claim'; title: string; body: string }[] = [
  {
    name: 'deposit',
    title: 'Deposit',
    body: 'SepETH from your Sepolia wallet: at least 0.001, in steps of 0.00000001 (one bridge unit each), plus gas. The claim pays the same number of units explicitly to the Liquid script you name, so name one your wallet can spend open coins from: with Humid, its unconfidential address.',
  },
  {
    name: 'sepolia',
    title: 'Relay, fork proof, redemption',
    body: 'Sepolia gas, paid by whoever sends them; your wallet shows each cost before you sign. A relay batch of 100 headers is the largest. A redemption pays the recipient the burned units as SepETH, at 0.00000001 ETH each, with no bridge fee.',
  },
  {
    name: 'burn',
    title: 'Burn',
    body: `No Ethereum transaction. The bridge-asset input is the claim's own open output; the units you burn must be there and confirmed. With Humid, the fee is ${HUMID_FEE.sats} sats from one of Humid's tL-BTC coins of at least ${HUMID_FEE.minCoin} tL-BTC (fee plus ${HUMID_FEE.change} sats of change), received at its confidential address and confirmed. Humid's balance does not count the open claim, and its coin list can leave open coins out, so a fee received at the unconfidential address may not be found.`,
  },
  {
    name: 'prove-claim',
    title: 'Proof and claim',
    body: 'tL-BTC for the Liquid update and claim fees, paid by whoever sends them, and the prover\'s own machine time; no bridge fee.',
  },
];

export interface Assumption {
  title: string;
  body: ReactNode;
  /** How it stands on the instance this page serves. */
  here: (s: BridgeState) => ReactNode;
}

/** The bootstrap check's outcome (BridgeState.bootstrap), as Bridge checks lists it. */
function bootstrapChecked(s: BridgeState): string {
  const b = s.bootstrap;
  if (s.bridgeError) return 'This page does not check it while it refuses the escrow.';
  if (!s.bridge) return 'This page checks it once it has read the escrow.';
  if (!b) return 'This page is checking it.';
  if (b.ok) return 'This page checked it against the escrow\'s asset; Bridge checks lists each check.';
  if (b.unavailable) return 'The Liquid API has not served it to this page yet; the page tries again, and shows no burn until the check passes.';
  return `It failed this page's check (${b.error}), so the page takes no deposit and shows no burn.`;
}

export const ASSUMPTIONS: Assumption[] = [
  {
    title: 'Liquid\'s block signer: one key.',
    body: 'The escrow pays for a burn in any block signed under Liquid\'s signing script, so it trusts the signers not to sign an invalid block.',
    here: (s) => <>{on(s, (i) => escrowSays(s, (b) => (
      <>The <Escrow i={i} /> expects the signing script with hash <Code>{short(b.sbsHash)}</Code>
        {!s.liquid ? '.' : signersAhead(s) ? '; Liquid\'s latest block signs under a newer one, which the escrow follows once the headers that elected it are relayed.'
          : ', the one Liquid\'s latest block signs under.'}</>
    )))} Liquid testnet blocks are signed by a 1-of-1 script: one Blockstream key. If that key signs a false block, or is stolen, the escrow can pay for a
      burn that never happened. Testnet keeps that one key in every epoch, so the retired-key risk of the next point adds nothing here.</>,
  },
  {
    title: 'A light client of Liquid, relayed by anyone.',
    body: 'The escrow follows Liquid\'s signed headers block by block, including DynaFed key changes decided by Liquid\'s 4/5 vote. Each epoch\'s keys are trusted for the blocks of that epoch it has not yet seen, even after Liquid retires them. A vote the contract cannot decide stops it for good.',
    here: (s) => <>{on(s, (i) => escrowSays(s, (b) => (
      <>The <Escrow i={i} /> started from a Liquid checkpoint fixed at its deployment and follows DynaFed epochs of {n(b.epochLength)} blocks.</>
    )))} This page relays from your wallet; Relay Liquid headers, above, says how far relaying has reached.</>,
  },
  {
    title: 'An Ethereum light client on Liquid, through SP1.',
    body: 'The covenant mints only with an SP1 Groth16 proof that Sepolia finalized the deposit. That trusts Sepolia\'s sync committee, as any Ethereum light client does, SP1 and its proving setup, the guest program, and an unaudited Simplicity Groth16 verifier.',
    here: (s) => on(s, (i) => (
      <>The covenant keeps its state at address <Code>{short(i.state, 8)}</Code>. <RecordFile i={i} file="instance.json" /> pins the Sepolia anchor, a finalized slot whose sync
        committee the first proof starts from, and the guest ELF and program vkey; <Code>just prover check-elf</Code> rebuilds the last two in SP1's pinned Docker image.</>
    )),
  },
  {
    title: 'Sepolia\'s fork schedule.',
    body: 'The guest and the escrow know Sepolia\'s forks up to the one the escrow pins. Past a fork they do not know, deposits could no longer be proven.',
    here: (s) => <>{on(s, (i) => escrowSays(s, (b) => <>The <Escrow i={i} /> takes no deposit after {utc(b.admission.depositsEnd)}.</>))} An escrow pins the latest
      fork scheduled at its deployment and ends deposits at a fixed time in any case, at most 180 days later. If another fork is announced first, only the deposit
      closer the escrow names (<Code>DEPOSIT_CLOSER</Code>) can end deposits before it, and only if someone holds its key and pays its gas. Deposits made shortly
      before an unannounced fork may never be claimable.</>,
  },
  {
    title: 'An operator to finish deposits.',
    body: 'After Ethereum finality someone must prove your deposit to Liquid and claim it. Until then your ETH stays in the escrow, with no refund. The covenant checks the proof and pays only the script you committed, so an operator can delay a claim but not redirect it. It accepts both steps from anyone.',
    here: (s) => <>{on(s, (i) => <>Deposits to the <Escrow i={i} /> wait for someone to prove and claim them.</>, 'So no deposit has been proven or claimed.')} This
      page and its static host run no prover or background relay or fork check; you can submit the relay and fork-check transactions from the page. Anyone can
      prove and claim a finalized, unclaimed deposit by following <ExtLink href={TAKEOVER}>OPERATOR.md</ExtLink>.</>,
  },
  {
    title: 'Someone to keep deposits open.',
    body: 'Deposits pause unless a fresh fork-check proof arrives and Liquid headers are relayed often enough. Anyone may send either: this page relays from your wallet and sends a pasted fork proof, but building that proof needs a beacon node. Redemptions never wait for this.',
    here: (s) => <>{on(s, (i) => escrowSays(s, (b) => (
      <>The <Escrow i={i} /> takes a fork check up to {span(b.admission.maxForkCheckAge)} old and a last relayed Liquid block up to {span(b.maxRelayLag)} old;
        deposits are {admission(s)!.deposit ? 'open' : 'closed'} now.</>
    )))} Both age out unless someone repeats them. The deposit closer can end deposits early; it cannot move funds, reopen deposits or stop redemptions.</>,
  },
  {
    title: 'Public records, including the light-client store.',
    body: 'Liquid holds only hashes of the bridge state. Whoever proves next needs the state\'s fields and the full light-client store behind them, and must find both in public data.',
    here: (s) => <>{on(s, (i) => (
      <><RecordFile i={i} file="lc_preimages.json" /> lists each light-client store this site publishes, before the update that reaches it is sent. While it is
        missing a later head, its updater did not publish the store needed by the next proof. The first proof starts from the anchor store in this instance.</>
    ), 'No update has been made on it, so its live state is the one its bootstrap creates, at the anchor. Its first proof starts from the published anchor store.')} The
      tools refuse a store unless it hashes to the state on Liquid. The covenant cannot enforce publication. If an updater withholds a later store, anyone can
      reconstruct it from a matching public beacon header and sync-committee update while those are available, or use archived proof inputs. Once those sources
      disappear, further proofs can stall. <ExtLink href={LIMITS}>Recovery instructions</ExtLink> explain the limits.</>,
  },
  {
    title: 'An honest bootstrap.',
    body: 'The escrow knows its Liquid asset, but not where that asset\'s minting token went. This page checks the public bootstrap: one token, no coins, all in the published state address. Whether that address holds the reviewed covenant is checked by rebuilding it from source.',
    here: (s) => on(s, (i) => (
      <>The <Bootstrap i={i} /> names state address <Code>{short(i.state, 8)}</Code>. {bootstrapChecked(s)} <Code>assemble.py verify-bootstrap</Code> rebuilds
        that address, with its claim and update leaves, from <RecordFile i={i} file="manifest.json" />; this page does not.</>
    )),
  },
  {
    title: 'Fixed code, no upgrade path.',
    body: 'A bug in the contracts or covenants strands the funds; no admin key can change them or rescue anything.',
    here: (s) => on(s, (i) => (
      <>This page uses the <Escrow i={i} /> only while the hash of its code is <Code>{short(`0x${i.codeHash}`)}</Code>, the one
        {' '}<RecordFile i={i} file="instance.json" /> pins{s.bridgeError ? `; it is ${s.bridgeError}, so the page uses it for nothing.` : s.bridge ? ', and it matched.' : '.'} Anyone
        can compile <Code>contracts/solidity/</Code> and compare. No audit is claimed.</>
    )),
  },
  {
    title: 'A burn\'s exact script.',
    body: 'The escrow pays only for an explicit (unblinded) output of its asset whose script is exactly the one naming the recipient. A blinded output, a wallet\'s Burn or Destroy control, or a payment to any other script redeems nothing. The page builds that script from its own source, and only checks it against the escrow. It shows a burn, and has Humid make one, only of the asset the record\'s bootstrap transaction issues, whatever an RPC reports.',
    here: (s) => <>The escrow redeems an explicit output of its asset whose script is exactly 72 bytes: <Code>OP_RETURN</Code>, then one 70-byte push of the tag
      {' '}<Code>liquid-bridge-poc/burn</Code>, Sepolia's chain id, the escrow and the recipient, in plain bytes. Consensus alone makes it unspendable, and anyone can
      read what it names on a Liquid explorer. The Redeem tab shows that script for your recipient and requires the escrow's own <Code>burnScriptPubKey</Code> to
      answer exactly the script this page builds. {on(s, (i) => (
        <>Here it names chain id {DEFAULTS.chainId.toString()} and the <Escrow i={i} />{asset(s) ? <>, and the asset is <Code>{asset(s)}</Code></> : ''}.</>
      ), 'So no burn has been made.')}</>,
  },
  {
    title: 'Recipients that refuse ETH.',
    body: 'If the Ethereum recipient rejects the payment, the redemption does not happen and the burn stays unspent; the recipient itself can then redeem to another address. An address that can neither receive ETH nor make calls could never redeem.',
    here: (s) => <>Redeem step 4 builds <Code>redeemTo</Code>, which the recipient sends to have the ETH paid to another address.
      {' '}{on(s, (i) => <>It is a call to the <Escrow i={i} />.</>, 'So nothing has been redeemed.')}</>,
  },
  {
    title: 'What this page reads, and this page itself.',
    body: 'The page reads Sepolia through your wallet, or the RPC you set in Settings, and Liquid through an Esplora API. A false answer can make it show the wrong state or refuse to act. It cannot make the escrow or the covenant pay anyone else, because both check on chain, and it does not choose where your funds go or what a burn destroys: the page builds deposits and burn scripts from its own source and the instance record, and burns only the asset the record\'s bootstrap transaction issues. You do trust the copy of the page you loaded, as with any web wallet interface; your wallet and Humid show each transaction before you sign.',
    here: (s) => <>Sepolia: {s.settings.ethRpc ? 'the RPC you set in Settings' : 'your wallet\'s RPC'}; the page does not read through an RPC whose chain id is
      not Sepolia's. Liquid: {esplora(s)}, whose word the page takes that a transaction is confirmed; the escrow checks every relayed header. The page is static
      files built from the repository, serving {s.instance ? <>only the instance <Code>{s.instance.name}</Code> its <Code>bridge-core/config.js</Code> names</> : 'no instance yet'};
      it holds no key and runs no relayer or prover. {s.published
        ? `This copy is the published site, ${SITE}, built from ${REPO}.`
        : 'This copy is not the published site named at the top of the page, so no store its record lists counts as published.'}</>,
  },
  {
    title: 'Test networks.',
    body: 'SepETH and the bridge asset have no value. This is a proof of concept.',
    here: (s) => <>{on(s, (i) => (
      <>The SepETH in the <Escrow i={i} /> and {asset(s) ? <>asset <Code>{asset(s)}</Code></> : 'its asset'} on Liquid testnet have no value.</>
    ))} Public data shows each transaction and its sender, not which page or wallet software built it.</>,
  },
];
