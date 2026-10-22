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
import { LIMITS, REPO, SITE } from './links';

const Code = ({ children }: { children: ReactNode }) => <code className="mono">{children}</code>;

export const HOW_IT_WORKS = 'Deposit SepETH, wait for finality, then prove and claim bridge units on Liquid. To return, burn the units for a named '
  + 'Ethereum recipient, wait for confirmations and relay the headers, then redeem. You or anyone else can prove, claim and relay. '
  + 'Proofs cannot redirect the committed payment. There is no admin rescue.';

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
    title: 'Relay Liquid headers',
    body: 'Relay from a burn row, or the deposit form when needed to reopen deposits. The escrow checks signed headers in batches of up to 100.',
    needs: 'A Sepolia wallet and gas.',
    here: (s) => on(s, (i) => escrowSays(s, (b) => (
      <><Escrow i={i} /> has headers through block {n(b.lcTip)}
        {s.liquid ? `, ${plural(relayLag(s), 'block')} behind Liquid` : ''}{b.lcTime ? `, timestamped ${utc(b.lcTime)}` : ''}.
        {admission(s)!.relayReopens ? ' Relaying now reopens deposits.' : ''}</>
    ))),
  },
  {
    name: 'fork-proof',
    title: 'Refresh the fork check',
    body: 'Paste a fork proof in the deposit form to reopen deposits. The page and escrow check it against Ethereum\'s beacon root.',
    needs: <>A Sepolia beacon node and <Code>tools/liquid-relay/fork_proof.py</Code> to build it; a Sepolia wallet and gas to send it.</>,
    here: (s) => on(s, (i) => escrowSays(s, ({ admission: { forkCheckedAt: at, maxForkCheckAge: age } }) => (
      <>{at ? <><Escrow i={i} /> fork check: {utc(at)}, valid until {utc(at + age)}.</>
        : <><Escrow i={i} /> has no fork check.</>}
        {admission(s)!.forkReopens ? ' A fork proof now reopens deposits.' : ''}</>
    ))),
  },
  {
    name: 'burn',
    title: 'Burn on Liquid',
    body: <>Use Redeem to build an unblinded burn with the exact <Code>OP_RETURN</Code> script for your recipient. Humid signs and sends it.
      Ordinary Send cannot create this output.</>,
    needs: <>Confirmed bridge units and one confirmed coin of at least {HUMID_FEE.minCoin} tL-BTC at Humid's confidential address for the fee.
      Connect an Ethereum wallet or set a Sepolia RPC to read the escrow.</>,
    here: (s) => on(s, (i) => (asset(s)
      ? <>Burn asset <Code>{asset(s)}</Code>, issued by the <Bootstrap i={i} />, for the <Escrow i={i} />.</>
      : <>Burns are disabled until the <Bootstrap i={i} /> confirms the <Escrow i={i} /> asset. Burn nothing until verification passes.</>)),
  },
  {
    name: 'redeem',
    title: 'Redeem on Sepolia',
    body: <>Submit a burn proof from Redeem. Each burn pays once to its named recipient. Only that recipient can redirect payment with <Code>redeemTo</Code>.</>,
    needs: 'A confirmed burn, relayed headers, a Sepolia wallet and gas.',
    here: (s) => on(s, (i) => escrowSays(s, (b) => (
      <><Escrow i={i} /> requires {plural(b.minConf, 'Liquid confirmation')} in relayed blocks.</>
    ))),
  },
  {
    name: 'prove-claim',
    title: 'Prove and claim deposits',
    body: <>Anyone can prove finalized deposits, then claim them in any order. A proven deposit needs only a claim, with no new proof.
      Generate proofs locally; send updates and claims here. <a href="#guide">Follow the guide</a>.</>,
    needs: <>Repository tools, Docker and SP1, an execution RPC with <Code>eth_getProof</Code>, a beacon node with light-client updates,
      the current store, and tL-BTC for fees.</>,
    here: (s) => on(s, (i) => (
      <>Read the live state with <Code>BRIDGE_INSTANCE={i.record.replace(/\/$/, '')} just status</Code>.
        Anchor: <RecordFile i={i} file="instance.json" />. Published stores: <RecordFile i={i} file="lc_preimages.json" />.
        A shared file or recoverable beacon data can also supply the store.</>
    )),
  },
  {
    name: 'audit',
    title: 'Verify the instance',
    body: <>Rebuild the covenant address with <Code>assemble.py verify-bootstrap</Code>, compare the compiled escrow hash,
      and recover Liquid state with <Code>assemble.py recover</Code>.</>,
    needs: 'Repository tools, Python, Foundry and public chain data.',
    here: (s) => on(s, (i) => (
      <>Deployment pins: <RecordFile i={i} file="instance.json" /> and <RecordFile i={i} file="manifest.json" />.
        State: <Code>{short(i.state, 8)}</Code>. Bootstrap: <Bootstrap i={i} />.</>
    )),
  },
  {
    name: 'sources',
    title: 'Choose data sources',
    body: 'Set a Liquid Esplora API and Sepolia RPC in Settings.',
    needs: 'Your wallet still signs Sepolia transactions.',
    here: (s) => <>Sepolia: {s.settings.ethRpc ? 'your custom RPC' : 'your wallet'}. Liquid: {esplora(s)}.</>,
  },
];

export const SELF_SERVE_NOTE = 'Every action is open to you or anyone else. Proof generation runs locally. '
  + 'The deposit closer can only end deposits early; it cannot reopen them or move funds.';

export const COSTS: { name: 'deposit' | 'sepolia' | 'burn' | 'prove-claim'; title: string; body: string }[] = [
  {
    name: 'deposit',
    title: 'Deposit',
    body: 'At least 0.001 SepETH plus gas. One bridge unit equals 0.00000001 ETH. Claims pay public, unblinded outputs; use a wallet that can spend them.',
  },
  {
    name: 'sepolia',
    title: 'Relay, fork check, redeem',
    body: 'The sender pays Sepolia gas. Redemption returns 0.00000001 ETH per burned unit, with no bridge fee.',
  },
  {
    name: 'burn',
    title: 'Burn',
    body: `Humid burn fee: ${HUMID_FEE.sats} sats. It needs one confirmed coin of at least ${HUMID_FEE.minCoin} tL-BTC at its confidential address, covering the fee and ${HUMID_FEE.change} sats of change. Its balance omits unblinded bridge units; this page can spend them.`,
  },
  {
    name: 'prove-claim',
    title: 'Proof, update and claim',
    body: 'The sender pays tL-BTC for update and claim fees. The prover supplies computing time. No bridge fee.',
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
  if (s.bridgeError) return 'Not checked: escrow rejected.';
  if (!s.bridge) return 'Waiting to read the escrow.';
  if (!b) return 'Checking bootstrap.';
  if (b.ok) return 'Bootstrap matches the escrow asset.';
  if (b.unavailable) return 'Bootstrap unavailable. Retrying; burns stay disabled.';
  return `Bootstrap rejected: ${b.error}. Deposits and burns are disabled.`;
}

export const ASSUMPTIONS: Assumption[] = [
  {
    title: 'Liquid signers',
    body: 'The escrow trusts Liquid\'s block signatures. Liquid testnet uses one Blockstream key. A compromised or dishonest signer can authorize a false burn and drain escrow funds.',
    here: (s) => on(s, (i) => escrowSays(s, (b) => (
      <><Escrow i={i} /> expects signing script hash <Code>{short(b.sbsHash)}</Code>.
        {s.liquid ? signersAhead(s) ? ' New signing keys await relaying.' : ' It matches the latest Liquid block.' : ''}</>
    ))),
  },
  {
    title: 'Liquid checkpoint and key changes',
    body: 'The escrow starts at a fixed checkpoint and follows DynaFed\'s 4/5 votes. Retired keys remain trusted for unseen blocks in their epochs. An undecidable vote permanently stops the client.',
    here: (s) => on(s, (i) => escrowSays(s, (b) => (
      <><Escrow i={i} /> uses DynaFed epochs of {n(b.epochLength)} blocks. Anyone can relay headers.</>
    ))),
  },
  {
    title: 'Ethereum proofs and setup',
    body: 'Minting relies on Sepolia\'s sync committee, SP1 and its Groth16 setup, the guest program, and an unaudited Simplicity verifier.',
    here: (s) => on(s, (i) => (
      <>State: <Code>{short(i.state, 8)}</Code>. <RecordFile i={i} file="instance.json" /> pins the Sepolia anchor, guest ELF and program key.
        Verify the build with <Code>just prover check-elf</Code>.</>
    )),
  },
  {
    title: 'Ethereum forks',
    body: 'An unknown Sepolia fork can make deposits unprovable. Deposits close on a fixed date, at most 180 days after deployment. Only the designated deposit closer can end them earlier, requiring its key and gas.',
    here: (s) => <>{on(s, (i) => escrowSays(s, (b) => <><Escrow i={i} /> closes deposits at {utc(b.admission.depositsEnd)}.</>))}
      {' '}Deposits made before an unannounced fork may never be claimable.</>,
  },
  {
    title: 'Proving and claiming',
    body: 'After finality, you or anyone else must prove and claim the deposit. These steps are not automatic. Until then, ETH stays in escrow with no refund. Proofs and claims cannot change the recipient.',
    here: (s) => <>{on(s, (i) => <>Deposits use the <Escrow i={i} />.</>)}{' '}
      This site runs no background prover or relay. <a href="#guide">Prove and claim guide</a>.</>,
  },
  {
    title: 'Keeping deposits open',
    body: 'Anyone can refresh fork proofs and relay headers. Deposits pause when either grows stale. Redemption ignores the deposit pause, but still needs relayed burn confirmations.',
    here: (s) => on(s, (i) => escrowSays(s, (b) => (
      <><Escrow i={i} /> allows a fork check up to {span(b.admission.maxForkCheckAge)} old and relayed block up to {span(b.maxRelayLag)} old.
        Deposits are {admission(s)!.deposit ? 'open' : 'closed'}.</>
    ))),
  },
  {
    title: 'Store availability',
    body: 'Liquid stores state hashes. The next prover needs the matching state and full light-client store. Publishing a successor store is optional and cannot be enforced by the covenant. Withholding it can stall further proofs.',
    here: (s) => <>{on(s, (i) => <>Published stores: <RecordFile i={i} file="lc_preimages.json" />. Other shared copies also work.</>)}{' '}
      Recovery needs matching beacon headers and sync-committee updates, or archived proof inputs. Once those disappear, recovery may be impossible.
      {' '}<ExtLink href={LIMITS}>Recovery details</ExtLink>.</>,
  },
  {
    title: 'Bootstrap verification',
    body: 'The escrow cannot verify where the minting token went. This page checks one token, no initial coins, and that the token is at the published state address. Verifying the covenant at that address requires a source rebuild.',
    here: (s) => on(s, (i) => (
      <><Bootstrap i={i} /> → <Code>{short(i.state, 8)}</Code>. {bootstrapChecked(s)} Rebuild with <Code>assemble.py verify-bootstrap</Code>
        {' '}and <RecordFile i={i} file="manifest.json" />.</>
    )),
  },
  {
    title: 'Fixed, unaudited code',
    body: 'Contract or covenant bugs can strand funds. No admin key can upgrade the code or rescue funds.',
    here: (s) => on(s, (i) => (
      <><Escrow i={i} /> must match hash <Code>{short(`0x${i.codeHash}`)}</Code> from <RecordFile i={i} file="instance.json" />.
        {s.bridgeError ? ` Rejected: ${s.bridgeError}.` : s.bridge ? ' Hash matched.' : ' Not checked yet.'}
        {' '}Compare a local build of <Code>contracts/solidity/</Code> to verify the source.</>
    )),
  },
  {
    title: 'Exact burn script',
    body: 'Burns are irreversible. Only an unblinded output of the verified bridge asset with the exact recipient script can redeem. A different script, blinded output, or ordinary Burn or Destroy button cannot.',
    here: (s) => <>The script is 72 bytes: <Code>OP_RETURN</Code>, then a 70-byte push of <Code>liquid-bridge-poc/burn</Code>,
      chain ID, escrow and recipient. Its amount and recipient are public. Redeem checks it against the escrow's <Code>burnScriptPubKey</Code>.
      {' '}{on(s, (i) => <><Escrow i={i} /> uses chain {DEFAULTS.chainId.toString()}{asset(s) ? <> and asset <Code>{asset(s)}</Code></> : ''}.</>)}</>,
  },
  {
    title: 'Recipients that reject ETH',
    body: 'A rejected payment leaves the burn unredeemed. Only its recipient can redirect payment. If that address can neither accept ETH nor call redeemTo, redemption is impossible.',
    here: (s) => <>Redeem → Redirect payment uses <Code>redeemTo</Code>. {on(s, (i) => <>The recipient calls the <Escrow i={i} />.</>)}</>,
  },
  {
    title: 'This site and its data sources',
    body: 'False RPC or API data can mislead this page or prevent actions; on-chain checks still enforce payments. You trust the site code you loaded and must review wallet approvals. The page verifies the burn asset against the bootstrap.',
    here: (s) => <>Sepolia: {s.settings.ethRpc ? 'your custom RPC' : "your wallet's RPC"}. Liquid: {esplora(s)}.
      Liquid confirmation status comes from that API; the escrow checks relayed headers. This site holds no keys.
      {s.instance ? <> Instance: <Code>{s.instance.name}</Code>.</> : ''}
      {' '}{s.published ? <>Published site: <ExtLink href={SITE}>zk-bridge</ExtLink>. <ExtLink href={REPO}>Source</ExtLink>.</>
        : 'Unofficial copy; its listed stores do not count as published here.'}</>,
  },
  {
    title: 'Test networks',
    body: 'This is an unaudited proof of concept. SepETH and the bridge asset have no value.',
    here: (s) => on(s, (i) => <>Sepolia <Escrow i={i} /> and Liquid testnet{asset(s) ? <> asset <Code>{asset(s)}</Code></> : ''}.</>),
  },
];
