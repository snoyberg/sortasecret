# Deploying Sorta Secret

Sorta Secret is deployed as a Cloudflare Worker. The Worker reads three values
from Cloudflare secret bindings at request time:

- `SORTASECRET_RECAPTCHA_SECRET`
- `SORTASECRET_RECAPTCHA_SITE`
- `SORTASECRET_KEYPAIR`

Set each value once for the target Worker/environment with Wrangler. Wrangler
prompts for the value and stores it with Cloudflare rather than in this
repository:

```sh
npx wrangler secret put SORTASECRET_RECAPTCHA_SECRET
npx wrangler secret put SORTASECRET_RECAPTCHA_SITE
npx wrangler secret put SORTASECRET_KEYPAIR
```

Do not commit secret values or put them in a checked-in dotenv file. The
bindings are available to the Worker as `env.SORTASECRET_*`.

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
`target/worker-build/` are ignored by Git. A dry run only validates the bundle;
it does not need access to the production secret values.
