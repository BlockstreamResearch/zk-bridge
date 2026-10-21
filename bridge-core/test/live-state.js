// The live Liquid state of the published record, as a reviewed pin: lc-store.test.js checks the record's store
// against it. Only Liquid knows the live state, and this test reads no chain. Check the chain before changing it
// (OPERATOR.md, ordering).
//
// Keyed by instance name: { head, lc }, the head and light-client commitment the next proof starts from. The pin of
// the published instance is added once it is deployed (its anchor), and moved after each confirmed update. None is
// pinned while no instance's record is published.
export const LIVE = {
  'sepolia-liquid-testnet': {
    head: 11403744,
    lc: '18a94d39faf9ef6c917e860fac82926a6bc2ed709f9cc279a4c751562d254588',
  },
};
