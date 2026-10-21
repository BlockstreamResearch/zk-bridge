# Testnet Liquid ⇄ Sepolia ZK-Bridge

This repository presents a proof-of-concept bridge using Simplicity and zero-knowledge proofs to bridge ETH
from Ethereum Sepolia to Liquid testnet, with the ability to return SepETH to Sepolia.

## High-level Technical Overview

The concept was inspired by recent research showing that Groth16 proofs can be verified on Liquid using Simplicity.

This allowed us to adapt and reuse the [code for verifying Ethereum's consensus](https://github.com/succinctlabs/sp1-helios) to
enable a trustless experience, subject to certain assumptions, between Ethereum Sepolia and Liquid.

At its heart, the mechanism is simple: prove to Liquid that something happened on Ethereum and take an action
(in our case, issue wrapped SepETH backed by SepETH locked in a contract on Sepolia).

And vice versa: prove to Sepolia that an action happened on Liquid and take an action (in our case, unlock the previously deposited SepETH).

For more details, see [concept](./CONCEPT.md).

Read the [design assumptions](./contracts/README.md) to understand trust assumptions. Each deployment's own trust roots are in its record under `instances/`, created when it is deployed.

## Implementation details

On Sepolia, the contract responsible for managing deposits is [BridgeEscrow](./contracts/solidity/contracts/BridgeEscrow.sol). 
Then a prover runs the [SP1 program](./tools/sg16/bridge-guest/program/src/main.rs) off-chain, starting from a 
trusted [weak-subjectivity checkpoint](https://ethereum.org/developers/docs/consensus-mechanisms/pos/weak-subjectivity/), 
to prove Sepolia finality and the escrow's deposit state. The [Simplicity update covenant](./tools/sg16/bridge-guest/liquid.py) 
verifies this proof on Liquid.

On Liquid, the Simplicity covenants control a reissuance token for wrapped SepETH. 
When the user provides the necessary proofs, namely the [deposit inclusion proof](./contracts/simplicity/simf/claim.simf#L173) 
and [proof that the deposit has not already been claimed](./contracts/simplicity/README.md#the-claimed-tree), 
the [claim covenant](./contracts/simplicity/simf/claim.simf) allows them to issue the exact amount of wrapped 
SepETH to the Liquid recipient recorded in the deposit.

The operation above concludes the first direction of bridging assets from Ethereum to Liquid.

The redemption of SepETH starts with burning wrapped SepETH on Liquid using the bridge's specific burn format, 
which names the chain, escrow and Sepolia recipient. Then the [Solidity contract](./contracts/solidity/contracts/BridgeEscrow.sol) 
verifies that the burn transaction was included in a Liquid block, using [signed block headers](./contracts/solidity/contracts/LiquidLightClient.sol) 
and the required confirmations. After the proof is verified and accepted, the corresponding amount of previously deposited SepETH is released. 
The same burn cannot be redeemed twice.

This concludes the other and final bridge direction that this proof of concept is meant to demonstrate. 
Both directions rely on the documented [trust assumptions](./contracts/README.md).
