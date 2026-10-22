//! Dropping sync-committee updates a proof does not need.
//!
//! The consensus RPC serves every period's update from the anchored store's period on (sp1-helios-script
//! `get_updates`), and the guest verifies each one it is given before the finality update.  Often the anchored
//! committee alone verifies the finality update.  Each unneeded update costs about 24 M guest cycles: executing
//! the SP1 6.8.1 guest on public Sepolia inputs took 49,683,924 cycles with one such update and 25,971,522 without
//! it, and 73,674,429 against 49,873,824 across a period boundary, keeping one update of two; the public values
//! were the same.
//!
//! `minimal` keeps an update only if the guest's outcome needs it.  The outcome is what the guest's public values
//! are computed from: the finalized light-client header and the current sync committee its store ends with.  The
//! full sequence is the reference: it must verify, as before, and a subsequence is accepted only if it verifies
//! and ends with exactly that outcome.  So the proof's public values do not change, and an input whose full
//! sequence fails is refused, never repaired by dropping updates.  The guest verifies whatever it is given either
//! way: this changes the work, not what a proof can show.
//!
//! The successor store file can still differ byte for byte: Helios's participation counters, which only decide
//! optimistic-header updates, follow the updates applied (current_max_active_participants can end at 0 instead of
//! 512).  Its finalized header and committee, hence its lc, are the same, and a store is trusted only through them:
//! the next proof's Helios verification reads the header and committees, not the counters.
//!
//! Guaranteed are that outcome and that no single kept update can be dropped without losing it.  The result is
//! not proven to be the fewest updates of any subsequence, which would need a search over subsets.  A beacon node
//! serves one update per period, in order; there an update is needed as a committee transition towards the
//! finality update's signature period, or to end with the same committee, and the real fixture in main.rs shows
//! one-at-a-time dropping keeping exactly the transition.

/// The indices, ascending, of the updates to keep out of `n`, with the full sequence's outcome.  `outcome(kept)` is
/// the guest's outcome for the updates whose indices are `kept`, in order, or an error if they do not verify.  The
/// empty sequence is tried first; then updates are dropped one at a time, latest first, while the outcome stays
/// the same, until no single kept update can be dropped.  Errors only if the full sequence does.
pub fn minimal<O: PartialEq, E>(
    n: usize,
    mut outcome: impl FnMut(&[usize]) -> Result<O, E>,
) -> Result<Vec<usize>, E> {
    let mut kept: Vec<usize> = (0..n).collect();
    let reference = outcome(&kept)?;
    let mut same = |trial: &[usize]| matches!(outcome(trial), Ok(o) if o == reference);
    if n == 0 || same(&[]) {
        return Ok(vec![]);
    }
    loop {
        let before = kept.len();
        for i in (0..kept.len()).rev() {
            let mut trial = kept.clone();
            trial.remove(i);
            if same(&trial) {
                kept = trial;
            }
        }
        if kept.len() == before {
            return Ok(kept);
        }
    }
}

#[cfg(test)]
mod tests {
    //! The selection alone, over arbitrary outcome functions.  Helios verification of real inputs, across a period
    //! transition and with refusals, is tested in main.rs.
    use super::minimal;

    #[test]
    fn keeps_exactly_what_the_outcome_needs() {
        assert_eq!(minimal(3, |_| Ok::<_, ()>(0)), Ok(vec![]));
        assert_eq!(minimal(0, |_| Ok::<_, ()>(0)), Ok(vec![]));
        assert_eq!(minimal(3, |k| Ok::<_, ()>(k.contains(&1))), Ok(vec![1]));
        // A chain: an update verifies only after every earlier one, as committee transitions do, and the outcome
        // stops changing after the third.
        let chain = |k: &[usize]| {
            if k.iter().enumerate().all(|(j, &i)| i == j) {
                Ok(k.len().min(3))
            } else {
                Err("unverified")
            }
        };
        assert_eq!(minimal(5, chain), Ok(vec![0, 1, 2]));
    }

    #[test]
    fn never_trades_the_outcome_or_repairs_a_failure() {
        // An outcome every update changes: nothing is dropped.
        assert_eq!(minimal(2, |k| Ok::<_, ()>(k.to_vec())), Ok(vec![0, 1]));
        // The full sequence fails: its error is returned, although shorter sequences would verify.
        assert_eq!(
            minimal(2, |k| if k.len() == 2 { Err("full") } else { Ok(()) }),
            Err("full")
        );
    }

    #[test]
    fn the_result_is_a_local_minimum_not_a_proven_fewest() {
        // Update 2 alone keeps the outcome with fewer updates, but dropping from the end reaches {0, 1} first,
        // from which no single update can go.  This is the documented limit of the strategy.
        let outcome = |k: &[usize]| Ok::<_, ()>(k == [0, 1, 2] || k == [2] || k == [0, 1]);
        let kept = minimal(3, outcome).unwrap();
        assert_eq!(kept, vec![0, 1]);
        for i in 0..kept.len() {
            let mut less = kept.clone();
            less.remove(i);
            assert_eq!(outcome(&less), Ok(false));
        }
    }
}
