# Bridge protocol modules for the browser

`lib/` holds the bridge's browser-side protocol checks and transaction builders, and `config.js` pins the one published bridge instance. There is no page here: the bridge interface is the React app in [`../ui/`](../ui/), which imports `lib/` and `config.js` read-only. Settings may change read-only data sources but cannot change the instance. The justfile also runs `lib/update.js` and `lib/claim.js` under Node to build the PSETs Humid signs.

```sh
npm --prefix bridge-core test
```

The tests cover bridge addresses and scripts, Elements transactions, Liquid headers, claim and update files, Humid PSETs, and the published instance record. The claim and update tests use synthetic transactions, while the record tests check `config.js` against its record; all must pass before publication.

The operator commands (federation, checkpoint, burn script, relay and redeem calldata, and the deposit list `assemble.py claim` reads) are the Rust tool [`../tools/bridge-operator/`](../tools/bridge-operator/), not part of this module. Its tests repeat this suite's expected values for the encodings both implement.

The GitHub Pages workflow runs these tests, then publishes `ui/dist` with the instance record. [OPERATOR.md](../OPERATOR.md) has the commands for proving, claiming, updating, and operating the testnet instance.
