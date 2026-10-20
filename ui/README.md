# Bridge protocol modules

`lib/` holds the bridge's browser-side protocol checks and transaction builders, `config.js` pins the one published bridge instance, and `cli.js` reads the escrow's deposits. There is no page here: the bridge interface is the React app in [`../ui-react/`](../ui-react/), which imports `lib/` and `config.js` read-only. Settings may change read-only data sources but cannot change the instance.

```sh
npm --prefix ui test
node ui/cli.js deposits --escrow <escrow> --from <deployment-block> --out <output.json>
```

The tests cover bridge addresses and scripts, Elements transactions, Liquid headers, claim and update files, Humid PSETs, the deposit reader, and the published instance record. The claim and update tests use synthetic transactions, while the record tests check `config.js` against its record; all must pass before publication. The deposit reader uses `SEPOLIA_EXECUTION_RPC`, reduces `eth_getLogs` requests when a provider limits their block range, and writes its output only after checking the complete event count.

The GitHub Pages workflow runs these tests, then publishes `ui-react/dist` with the instance record. [OPERATOR.md](../OPERATOR.md) has the commands for proving, claiming, updating, and operating the testnet instance.
