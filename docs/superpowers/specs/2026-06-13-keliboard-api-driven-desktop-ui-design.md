# Keliboard API Driven Desktop UI Design

## Goal

Turn the Windows desktop shell from a local core control panel into a real Keli client whose UI is driven by the `keliboard` client API and the native core state together.

The client should let a normal user log in to a panel, discover the correct API endpoint, see account/subscription/node/store status, pull sing-box config, start or stop the native core, and recover from common errors without using the command line.

## Current Context

`keli-native-client` already has a usable Windows shell around the native core:

- Chinese shell copy is in place.
- The main window is constrained to the default viewport with `body` overflow hidden.
- Existing views are `概览`, `节点`, `诊断`, and `设置`.
- The current data source is local runtime state plus imported subscription URL/config.
- `keli-desktop` exposes typed DTOs such as `DesktopShellState`, `DesktopSubscriptionSummary`, dependency reports, runtime status, node health, and support export.

`keliboard` already exposes the client-facing API surface the desktop UI needs:

- `/.well-known/keli-client.json` returns discovery data with `api_base`, `api_prefix`, backup bases, bootstrap URLs, TTL, and optional Ed25519 signature.
- `/api/v2/passport/auth/login` returns account auth data.
- `/api/v1/app/bootstrap` returns app metadata, user profile, subscription summary, and servers.
- Legacy fallback endpoints exist for `/api/v1/user/info`, `/api/v1/user/getSubscribe`, and `/api/v1/user/server/fetch`.
- Store/account endpoints exist under `/api/v1/user/plan/fetch`, `/api/v1/user/order/*`, `/api/v1/user/notice/fetch`, `/api/v1/user/ticket/*`, `/api/v1/user/knowledge/*`, `/api/v1/user/comm/config`, and `/api/v1/app/config`.

The old Flutter `keli-client` already contains a useful contract reference:

- `RealKeliApi` implements login, bootstrap, fallback bootstrap, plans, orders, payments, coupons, upgrade preview/confirm, checkout, order check/cancel, announcements, and sing-box config fetch.
- `EndpointResolver` implements manual, cache, well-known, TXT, backup, and bootstrap endpoint candidates.
- Contract tests already describe the expected HTTP paths and response parsing.

## Design Brief

Build a Chinese desktop client UI based on real `keliboard` API domains, while preserving the native core as the runtime authority.

The UI should be compact, operational, and default-viewport first. Page-level scrolling should be avoided. Long lists may use contained table/list scrolling inside fixed-height regions.

The app should keep subscription URL import as a compatibility path, but the primary experience should be panel login.

## Approaches

### Recommended: typed panel client plus desktop panel snapshot

Port the useful parts of Flutter `RealKeliApi` and `EndpointResolver` into Rust as a typed panel API boundary. `keli-client-core` should own the panel API models and HTTP client contracts. `keli-desktop` should compose those panel models with local core state into a `DesktopPanelSnapshot`. The shell should render the snapshot and emit typed user events.

This keeps HTML/simple shell code from knowing Laravel routes, keeps tests close to the API contract, and keeps any future visual-shell replacement independent from panel logic.

### Alternative: call keliboard directly from shell UI

The HTML shell could issue API requests directly from JavaScript and update the DOM. This is fast for a demo, but it spreads auth, endpoint discovery, error handling, and response parsing into the most fragile layer. It also makes token storage and test coverage weaker.

### Alternative: revive the Flutter client UI

The Flutter app already has many screens and API tests. It could become the UI basis. That would move faster for store/order flows, but it would split effort away from the native Rust desktop shell and does not directly reuse the current Windows packaging/runtime work.

## Recommendation

Use the typed Rust panel client approach.

The next implementation should not try to finish every store/support workflow. It should first create the panel-aware foundation:

1. Discovery and login.
2. Bootstrap profile/subscription/server data.
3. Native core config pull from `/api/v1/app/config`.
4. A compact Chinese UI shell that combines account state and local core state.
5. Store/support surfaces as read-capable foundations, with payment/ticket actions added after the main connection loop is stable.

## Information Architecture

The shell should move from purely local pages to product pages that match the API domains:

- `概览`: account, plan, traffic, expiry, selected node, local core status, primary start/stop action, newest announcement.
- `节点`: panel servers plus local health/probe state, recommended/selected node, config pull/import status, reload action.
- `订阅`: subscribe URL, accelerated subscribe URL when present, subscription token metadata redacted, compatibility URL import/update.
- `商店`: plans, current pending order, payment methods, order history summary. In the first panel UI slice this can be read-first plus create-order contract tests.
- `支持`: notices first; knowledge and ticket list can follow after the main loop.
- `诊断`: existing runtime events, dependencies, TUN/Wintun, support export, API endpoint/session diagnostics.
- `设置`: panel endpoint, account session, traffic mode, ports, startup options, local core defaults.

Navigation should remain left-rail based. The default `概览` should answer four questions without scrolling:

1. Who is logged in?
2. Is the subscription usable?
3. Which node/mode will start?
4. What action is available now?

## API Map

### Discovery

- `GET /.well-known/keli-client.json`
- Inputs: panel URL.
- Output: `api_base`, `api_prefix`, `backup_api_bases`, `bootstrap_urls`, `panel_host`, `source`, `ttl`, `updated_at`, optional `signature`.
- Client behavior: normalize base URL and API prefix, cache by panel host, honor TTL, try backups when login/bootstrap fails.

### Auth

- `POST /api/v2/passport/auth/login`
- Body: `email`, `password`.
- Output: `auth_data`, optional `token`.
- Client behavior: store auth data through a typed session-store boundary. For the first implementation, the backing store may be local-file based, but UI and API call sites must not depend on that storage choice.

### Bootstrap

- `GET /api/v1/app/bootstrap`
- Output domains: app metadata, user profile, servers, subscribe payload.
- Fallbacks: `GET /api/v1/user/info`, `GET /api/v1/user/getSubscribe`, `GET /api/v1/user/server/fetch`.
- Client behavior: prefer bootstrap; if missing or older deployment, use legacy endpoints and expose a warning in diagnostics.

### Runtime Config

- `GET /api/v1/app/config?core=sing-box&platform=windows&server_id={id}&core_version={version}`
- Batch mode omits `server_id`.
- Client behavior: fetch config only after account/subscription are usable; validate through existing native core preflight before replacing active runtime config.

### Store

- `GET /api/v1/user/plan/fetch`
- `GET /api/v1/user/order/getPaymentMethod`
- `GET /api/v1/user/order/fetch`
- `POST /api/v1/user/order/save`
- `POST /api/v1/user/order/recharge`
- `POST /api/v1/user/coupon/check`
- `POST /api/v1/user/order/upgrade/preview`
- `POST /api/v1/user/order/upgrade/confirm`
- `POST /api/v1/user/order/checkout`
- `GET /api/v1/user/order/check`
- `POST /api/v1/user/order/cancel`
- Client behavior: first slice should parse and show plans/orders/payment methods; payment browser/QR flows can follow once account and config flows are working.

### Support

- `GET /api/v1/user/notice/fetch`
- `GET /api/v1/user/knowledge/fetch`
- `GET /api/v1/user/knowledge/getCategory`
- `GET /api/v1/user/ticket/fetch`
- `POST /api/v1/user/ticket/save`
- `POST /api/v1/user/ticket/reply`
- Client behavior: show latest notices in this foundation. Ticket create/reply/close actions are outside this foundation and need their own interactive support plan after the main connection loop is stable.

## Rust Boundary

Add a panel API module under `keli-client-core` for this foundation. Evaluate a dedicated crate only when the panel module has grown beyond a focused API/model/client boundary.

Suggested units:

- `panel::endpoint`: endpoint config, candidate resolution, URL normalization, discovery payload parsing.
- `panel::auth`: login request/result, session model, auth header construction.
- `panel::models`: profile, subscription, node, plan, order, payment method, announcement.
- `panel::client`: trait for panel API operations and an HTTP-backed implementation.
- `panel::fixtures`: test helpers modeled after the old Flutter contract tests.

Extend `keli-desktop` with panel-aware DTOs:

- `DesktopPanelAccountSummary`
- `DesktopPanelSubscriptionSummary`
- `DesktopPanelEndpointSummary`
- `DesktopPanelNodeSummary`
- `DesktopPanelStoreSummary`
- `DesktopPanelNoticeSummary`
- `DesktopPanelSnapshot`

`DesktopShellState` should include an optional `panel: Option<DesktopPanelSnapshot>` field. Existing local-only behavior should still work when `panel` is `None`.

## Data Flow

1. User enters panel URL, email, and password.
2. Endpoint resolver creates candidates from manual URL, cached discovery, well-known, TXT, and bootstrap data.
3. Login tries candidates until one succeeds or all fail.
4. The panel session is stored through a narrow session store boundary.
5. Bootstrap loads profile, subscription, servers, and app metadata.
6. Desktop composes panel data with local dependency/core status.
7. User selects a node.
8. Desktop fetches sing-box config for that server from `/app/config`.
9. Existing native subscription/config preflight validates the config.
10. Start/reload/stop remains owned by the native core service.

## Default View Rules

- No body/page scroll in the main shell.
- Each view uses a fixed header plus a bounded content grid.
- Lists/tables may scroll inside their own region only.
- Primary actions stay visible in `概览` and `节点`.
- Copy must be Chinese.
- Labels should describe user state, not implementation details.
- Long URLs, tokens, and emails must truncate or wrap safely without changing layout height.
- Subscription tokens and auth data must always be redacted.

## Error Handling

- Discovery failure: show candidate source and last network error; allow manual API prefix.
- Login failure: keep the user on login state; do not clear existing working local subscription.
- Bootstrap missing: use legacy fallback and show diagnostics note.
- Account unavailable: show blocked account state and disable start/config pull.
- Config pull failure: preserve current runtime config and selected node.
- Bad sing-box config: reject before applying and surface the panel/core error.
- Running core update failure: preserve active runtime and selected node.
- Store/payment failure: keep order state visible and retryable.

## Test Strategy

Contract tests should come before UI changes:

- Endpoint normalization and discovery payload parsing.
- Login path and auth header behavior.
- Bootstrap success and legacy fallback.
- Server/node parsing.
- `/app/config` query construction for Windows sing-box.
- Plans/orders/payment parsing.
- Announcement pagination.
- `DesktopShellState` can render with `panel = None` and with a populated `DesktopPanelSnapshot`.
- UI HTML tests verify Chinese nav labels, default-view panels, fixed viewport CSS, redaction, and no page-level scrolling.

Manual verification should include:

- Launch desktop shell in smoke mode.
- See login/setup state.
- Load a fixture panel snapshot.
- Switch every view without page scroll.
- Select a node, pull config, start, stop, and export diagnostics.

## Completion Criteria

The API-driven UI foundation is complete when:

- Rust contract tests cover the client API map above.
- The desktop shell can represent logged-out, logged-in/bootstrap-loaded, blocked account, and config-ready states.
- `概览` shows account, subscription, selected node, traffic mode, and local core status in the default window.
- `节点` can show panel nodes and local health without depending on a pasted subscription URL.
- Existing subscription URL import/update still works.
- Existing desktop tests and smoke pass.
- No auth token, subscribe token, or full sensitive URL appears in UI snapshots, logs, or support export.
