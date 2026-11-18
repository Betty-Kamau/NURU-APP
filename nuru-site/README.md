# Nuru website

- `public/index.html` is the whole app.
- `wrangler.jsonc` tells Cloudflare to publish the `public` folder. Without it the Cloudflare build stops with
  "Missing entry-point to Worker script or to assets directory".
- `public/_headers` lets the "Continue with Google" pop-up talk back to the app.

To update the app: replace `public/index.html` and push to GitHub. Cloudflare rebuilds by itself.
