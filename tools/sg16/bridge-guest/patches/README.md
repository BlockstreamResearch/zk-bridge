# Patched dependencies of the bridge guest

`helios-consensus-core/` is helios-consensus-core 0.12.0 from a16z/helios commit
`2af9b41887e069144ee56cd710f3ddca195473f8` (tag `0.12.0`, MIT). The library sources
are copied unchanged, with the manifest normalized by `cargo vendor`. Upstream
test targets and development dependencies are omitted because their fixtures are
not included. The copy isolates the bridge guest's forthcoming changes to this
crate; it is not yet selected by the workspace.
