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
