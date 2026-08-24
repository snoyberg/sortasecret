# Deploying Sorta Secret

Sorta Secret is deployed as a Cloudflare Worker. The Rust/Wasm bundle embeds
three values at build time, so they must be supplied by the deployment
environment:

- `SORTASECRET_RECAPTCHA_SECRET`
- `SORTASECRET_RECAPTCHA_SITE`
- `SORTASECRET_KEYPAIR`

Provide these as protected CI variables or from a secure local shell. Do not
commit them, put them in a checked-in dotenv file, or pass them on a command
line that is recorded in build logs.

Install the pinned Wrangler CLI once:

```sh
npm install
```

Then validate and deploy from the repository root:

```sh
npm run deploy:dry-run
npm run deploy
```

The build script downloads and verifies the pinned `wasm-bindgen` release,
compiles the Rust Worker for `wasm32-unknown-unknown`, and prepares the module
bundle consumed by Wrangler. Generated files under `worker/pkg/` and
`target/worker-build/` are ignored by Git.
