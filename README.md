# PeerChat — Signaling Server (Backend, v2.3.0)

The Node half of **PeerChat**, a decentralised chat application. This
service is **"a post box, not a service"** (SRS §2.2): its only job is to
introduce peers to each other. Every peer registers against their public
key as a channel ("room"); the server routes **knock** handshakes and
WebRTC **SDP/ICE** payloads between rooms — and then steps out entirely.
Once a DataChannel is open, the server has no role: chats keep flowing
even if this process is killed mid-session.

**It never sees message content.** All messages are end-to-end encrypted
(ECDSA P-256 identities, ECDH-derived AES-GCM session keys) between the
browsers. This server stores nothing, logs no payloads, keeps no state
after peers disconnect, and authenticates nobody — by design.

```
peer A ──knock/SDP/ICE──▶ this server ──▶ peer B     (introduction only)
peer A ◀═════════ WebRTC DataChannel, E2E encrypted ═════════▶ peer B
```

## Run it

```bash
npm install
npm start          # → http://localhost:3000
```

- **Combined layout** (this folder sits inside `peerchat/` with `frontend/`
  next to it): the server also serves the static frontend — one port for
  everything.
- **Standalone** (deployed alone, e.g. Render): boots in
  `signaling-only mode` — no static layer, `/` answers with a plain-text
  note so host health checks see a clean 200. Signaling is unaffected.

## Endpoints

| Route | What it does |
|---|---|
| `/` | combined: serves the frontend · standalone: plain-text status note (200) |
| `/healthz` | `{"ok":true,"peers":N,"pairs":M}` — registered peers + live/pending pairs |
| `/socket.io/` | the signaling transport (WebSocket with polling fallback) |

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `3000` | listen port — service hosts (Render) inject it automatically |
| `SIGNALING_CORS` | reflect requester's origin | `"https://my-frontend"` single origin · `"https://a.example,https://b.example"` allow-list · `"*"` wildcard |

Cross-origin frontends (Netlify, Vercel, Live Server …) work out of the
box because the default reflects whoever is asking; restrict to your
frontend's origin once it is deployed.

## Deploy to Render

This repo is a ready-made Render Web Service:

1. Push this repo to GitHub/GitLab.
2. Render → **New → Web Service** → connect the repo.
3. Runtime **Node** · Build command **`npm install`** ·
   Start command **`npm start`** · Health check path **`/healthz`**.
4. Deploy — `node index.js` honours Render's `PORT`, and with no
   `frontend/` next to it the service runs signaling-only.

Then point the frontend at it: in the frontend repo's `js/config.js` set

```js
window.APP_CONFIG = { signalingPath: "https://your-service.onrender.com", statusSuffix: "" };
```

## How the signaling works (SRS v2.8 §3.3/§3.5, §19)

- **Rooms** — each socket registers under the peer's public key; that key
  *is* the address.
- **Knock** — a peer knocks on another key: the payload (ECDSA public key
  + ECDH session public key) is forwarded; the target accepts or rejects.
- **Pairs, not links (mesh)** — a peer may hold any number of simultaneous
  sessions. `pairSessions` tracks pairs (pending → open); the room-full
  answer fires only when the *same pair* already has a session or
  handshake in flight, so parallel handshakes can't interleave their SDP.
- **Lifecycle** — `session-open` confirms a live DataChannel;
  `session-end` (clean disconnect), knock-reject, socket disconnect or
  the 75 s stale-pending sweep clears the pair. Either side going away
  notifies the other.
- **In memory only** — all state dies with the process (SRS §3.4:
  nothing persists).

## The other halves

- **`frontend/`** — the static browser app (deploy that one to Netlify).
- **Root `peerchat/` archive** — full docs: SRS v2.8, DOCUMENTATION.md,
  WORKLOG.md, UML diagrams, screenshots, and the 59-check test suite.

## Stack & license

Node.js ≥ 18 · Express 4 · Socket.io 4 · zero storage.
`npm audit` clean (vulnerable transitive deps pinned via `overrides`).
MIT
