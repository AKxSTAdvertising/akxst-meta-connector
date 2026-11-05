# AKxST Meta Connector — Phase 1

An independent Cloudflare Worker connector for **AKxST Advertising — Social Command Center**. This is a working **code starter**, not a deployed service or a preexisting Base44 plugin.

It implements:

- Facebook Login OAuth authorization-code callback, with 10-minute, single-use state and browser nonce.
- Cloudflare Access authentication for every endpoint (Cloudflare-verified identity, no trust in client-supplied emails).
- Server-side D1 workspaces and membership/role checks.
- Meta `/me/accounts` discovery and page-token encryption at rest (AES-GCM).
- A small private web UI to create workspaces and connect Facebook Pages.
- Page connection status retrieval and API deletion endpoints (disconnect deletes stored token; for revocation at Meta, use Facebook settings).

**Not implemented:** direct Base44 app integration, Instagram login/publishing, scheduled publishing, analytics ingestion, automatic token renewal, App Review, or a hosted deployment. The phase-1 app stores Page tokens but has no posting API or frontend feature. Client onboarding beyond Meta test roles requires Meta approval and additional testing.

## Requirements

- Node.js 20+ and npm.
- A Cloudflare account with Workers + D1.
- Cloudflare Zero Trust enabled and an **Access policy protecting the whole deployed Worker**, with your admin email permitted. This is essential: the Worker rejects any request without an Access-authenticated identity. All application members will also need authorization in Cloudflare Access.
- Meta Developer App with Facebook Login for Business (and appropriate Pages scopes). For the initial test, the Facebook user needs a role on the unpublished Meta app.

## Deploy — copy these commands in a terminal

### 1. Log in and create the database

```bash
npm install
npx wrangler login
npx wrangler d1 create akxst-meta-db
```

Copy the `database_id` UUID printed by Cloudflare and **replace `REPLACE_WITH_ID`** in `wrangler.toml`.

Then:

```bash
npx wrangler d1 migrations apply akxst-meta-db --remote
```

Confirm you are applying to the newly created `akxst-meta-db` database.

### 2. Store secrets — NEVER paste them in chat or GitHub

```bash
npx wrangler secret put META_APP_SECRET
npx wrangler secret put TOKEN_ENCRYPTION_KEY
npx wrangler secret put ADMIN_EMAIL
```

- `META_APP_SECRET`: copy from Meta Developers → Social Command Center → App settings → Basic → App Secret. Paste into terminal prompt, not source code.
- `TOKEN_ENCRYPTION_KEY`: a strong random secret of **at least 32 characters**, unique to this connector. You can generate locally with `openssl rand -base64 48`, and paste that output into the Wrangler secret prompt. **Back it up securely**; if lost, stored Page tokens cannot be decrypted.
- `ADMIN_EMAIL`: the exact email you will use to log into Cloudflare Access (lowercase is recommended). Only this user can create workspaces. Other users can be invited to workspace membership using the owner's API, but must also be allowed by your Access policy.
- `META_APP_ID`: already set in `wrangler.toml` to your public App ID `3704754689693350`.

### 3. Deploy and protect the Worker

```bash
npx wrangler deploy
```

Cloudflare will print the **actual** URL. For example **only**, it might look like:

`https://akxst-meta-connector.YOUR-SUBDOMAIN.workers.dev`

**Do not use the example as your real URL.** Use the actual URL Cloudflare prints.

In Cloudflare dashboard, open **Workers & Pages → akxst-meta-connector → Access** (or Zero Trust → Access → Applications), enable an Access policy that protects **the entire Worker**. Restrict it to your own email at first. Cloudflare Access can be configured at the Worker level; the exact menu may vary. Follow [Cloudflare's current Access setup instructions](https://developers.cloudflare.com/workers/configuration/cloudflare-access/).

### 4. Set the actual Worker origin

```bash
npx wrangler secret put PUBLIC_BASE_URL
```

Enter the deployed URL **without trailing slash or path**. For example, if `wrangler deploy` printed `https://akxst-meta-connector.example.workers.dev`, enter precisely that origin.

`wrangler secret put` updates the deployed Worker; if necessary, run `npx wrangler deploy` again.

**Your exact Meta OAuth Redirect URI is:**

`<ACTUAL_WORKER_HTTPS_ORIGIN>/auth/meta/callback`

This cannot be known in advance of deployment. You can also visit your authenticated connector home screen, which displays the exact URI after configuration.

### 5. Add the redirect URI in Meta

Meta Developers → your **Social Command Center** app → **Facebook Login for Business → Settings** → **Valid OAuth Redirect URIs** → paste the exact URL and Save. Make sure web/client OAuth login settings support your flow. If you use a **Facebook Login for Business configuration ID**, optionally store it with:

```bash
npx wrangler secret put META_LOGIN_CONFIG_ID
```

When `META_LOGIN_CONFIG_ID` is provided, login uses `config_id` rather than requesting scopes individually via the `scope` parameter; configure required permissions in that Meta login configuration. Otherwise the connector requests `pages_show_list,pages_read_engagement,pages_manage_posts,read_insights`.

The `META_API_VERSION` setting defaults to `v27.0`, matching your recent Graph API Explorer test; update it as Meta requires. Meta permissions and approval requirements change by use case.

### 6. Test

1. Open your actual Worker URL in a browser.
2. Complete Cloudflare Access sign-in with `ADMIN_EMAIL`.
3. Create workspace (e.g., `Unbboxedthinking`).
4. Click **Connect Facebook Pages**.
5. Approve Meta's login and Page permissions, then check that the Page appears in the same workspace.
6. Test with a second Access-allowed user who is not a workspace member: they must not see the first workspace.

If the connector returns `403 Cloudflare Access sign-in required`, your Access policy is not configured for the deployed Worker. If it returns `503 Configuration incomplete`, a required secret or database binding is missing.

## API for future integration

All endpoints require a valid Cloudflare Access identity; never call these from public browser apps with secret tokens. Direct Base44 integration will need a supported, authenticated backend-to-backend bridge. Base44 cannot simply share this Worker's client session or token database.

| Method | Route | Required role |
|---|---|---|
| GET | `/api/me` | Authenticated user |
| GET | `/api/workspaces` | Authenticated user (membership-filtered) |
| POST | `/api/workspaces` | Agency admin |
| GET | `/api/workspaces/:id/connections` | Workspace viewer+ |
| POST | `/api/workspaces/:id/members` | Workspace owner |
| DELETE | `/api/workspaces/:id/connections/:connectionId` | Workspace admin+ |
| GET | `/auth/meta/start?workspace_id=:id` | Workspace admin+ |
| GET | `/auth/meta/callback` | Verified state + same user |

JSON writes require `Origin` matching `PUBLIC_BASE_URL`, with content-type `application/json`. No permissive CORS is enabled. Example workspace creation (from the same-site browser UI):

```json
{"name":"Unbboxedthinking"}
```

To add a member (from a same-origin authorized client), post:

```json
{"email":"editor@example.com","role":"editor"}
```

Do not give a client the `owner` or `admin` role unless they need to connect/disconnect accounts or manage members.

## Security notes

- `TOKEN_ENCRYPTION_KEY` and `META_APP_SECRET` must be Wrangler secrets, never `[vars]` or committed files.
- Access controls must cover **every public route to this Worker**, including aliases, previews, and `workers.dev`; unprotected alternate domains should not exist.
- Every OAuth flow stores a 10-minute random state and nonce (nonce in HTTP-only, Secure, SameSite=Lax cookie); it is bound to the signed-in email and workspace and consumed once before code exchange.
- The Worker stores only encrypted Page tokens; it does not put access tokens in response JSON, URLs displayed to users, HTML or client storage.
- Avoid sending sensitive values, auth codes, state parameters, or query strings in screenshots and support messages. Cloudflare request logging/observability should avoid full query strings for OAuth callbacks.
- Enabling Facebook Login in your own Meta app does **not** grant approval for arbitrary client accounts; App Review/Advanced Access may be needed.
- Use separate staging and production databases and test role isolation, token rotation/revocation, webhook signing, audit logs and rate limiting before production rollout. Privacy policy and data deletion arrangements may also be required by Meta.

## Run the included checks

```bash
npm test
```

These are local safety/smoke tests only. Full live OAuth integration must still be tested on the deployed HTTPS endpoint with a test Facebook Page.
