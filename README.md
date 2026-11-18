# Nuru

Everything in this folder goes at the TOP of the GitHub repo (no sub-folders).

| File | What it is |
|---|---|
| index.html | the whole app |
| worker.js | the Nuru server: Google sign-in, saving, the shared community, photos |
| wrangler.jsonc | Cloudflare settings (name, database, Google Client ID, admin emails) |
| privacy.html, terms.html | Privacy Policy and Terms pages (linked from Google sign-in) |
| manifest.webmanifest, sw.js, icon-*.png, apple-touch-icon.png, favicon.png | install on phones and work offline |
| robots.txt, sitemap.xml | help Google Search find the site |
| _headers, .assetsignore | web settings; .assetsignore keeps worker.js, wrangler.jsonc and this file off the public site |

Cloudflare creates the database (D1, "nuru-db") on the first deploy. To update the app, replace index.html and commit.
