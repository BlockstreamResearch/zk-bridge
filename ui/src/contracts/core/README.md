# Declarations for the shared `bridge-core/` modules

These `.d.ts` files describe the part of `../bridge-core/config.js` and `../bridge-core/lib/*.js` that this app calls. They are not
implementations. At build and test time `@bridge/core/...` resolves to the real files in `../bridge-core/` (the Vite alias in
`vite.config.ts`); only TypeScript resolves it here (`paths` in `tsconfig.json`).

So they are a contract. If a shared module changes a signature this app uses, update the declaration here. The
behavioural tests in `src/**/*.test.ts(x)` run against the real modules, so a declaration that drifts from the code
still fails at test time where it matters. Only members this app uses are declared.
