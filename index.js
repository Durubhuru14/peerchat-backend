/**
 * ============================================================================
 * PEERCHAT — SIGNALING SERVER
 * SRS v2.8 — Sections 3.3, 3.4, 3.5, 8.7, 15.4 + v2.2 §19 (mesh sessions)
 * ----------------------------------------------------------------------------
 * "The signaling server is a post box, not a service."        (SRS §2.2)
 *
 * Responsibilities (SRS §3.3, revised for v2.2 mesh):
 *   - Accept peer socket connections
 *   - Register each peer against their public key as a channel ("room")
 *   - Route WebRTC offer, answer, and ICE candidates between channels
 *   - Route knock payloads (ECDSA public key + ECDH session public key)
 *   - Notify a peer when the other side of ANY of its sessions goes away
 *
 * MESH SESSIONS (v2.2, SRS v2.6 §19 / FR-51):
 *   V1 allowed ONE live session per peer (`connectedTo`, single string) and
 *   answered any further knock with `room-full` (E-06). v2.2 removes that
 *   limit: a peer may hold any number of simultaneous DataChannels — one per
 *   remote peer. The server therefore tracks PAIRS, not single links:
 *
 *     rooms:        Map<publicKey, { socketId }>          — channel ownership
 *     pairSessions: Map<pairId, { a, b, state, createdAt }>
 *
 *   Pair states: "pending" (knock forwarded, handshake running) → "open"
 *   (client confirms via `session-open` once the DataChannel is live).
 *   A pair is removed on `knock-reject`, `session-end` (clean disconnect),
 *   socket disconnect of either side, or the stale-pending sweep (§15.4
 *   successor: handshakes that never complete are reaped lazily).
 *
 * `room-full` survives with NARROWER meaning (E-06, revised): the SAME pair
 * already has a session or handshake in flight — the knock is dropped so two
 * parallel handshakes between two peers cannot interleave their SDP. A third
 * peer knocking a busy-looking target is now ALWAYS forwarded: busy is no
 * longer a server-side concept. The target still receives `knock-blocked`
 * as a transient "someone tried to reach you on an existing pair" notice.
 *
 * Explicitly NOT done here (SRS §3.4):
 *   - No storage, reading, or logging of messages
 *   - No interpretation of what the keys mean
 *   - No state persisted after peers disconnect
 *   - No role once the DataChannel is open
 * ============================================================================
 */

const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;

/* A handshake that never completes is reaped after this long (§15.4 successor:
 * knock 30s + ICE 15s + slack). "open" pairs are exempt — they end only via
 * session-end, knock-reject or socket disconnect. */
const PENDING_PAIR_TTL_MS = 75_000;
const SWEEP_INTERVAL_MS = 30_000;

/* ----------------------------------------------------------------------------
 * HTTP layer — serves the static vanilla frontend (local dev convenience).
 * In production the frontend may be hosted anywhere (SRS §3.2 "Vercel (frontend)
 * + any Node host (signaling)"); this server only NEEDS the Socket.io part.
 * -------------------------------------------------------------------------- */
const app = express();
app.use(express.static(path.join(__dirname, '..', 'frontend')));

app.get('/healthz', (_req, res) => {
  res.status(200).json({ ok: true, peers: rooms.size, pairs: pairSessions.size });
});

const httpServer = http.createServer(app);

/* ----------------------------------------------------------------------------
 * CORS (SRS §3.2 deployment shape 2: "frontend hosted anywhere + signaling on
 * any Node host"). Socket.io v4 sends no CORS headers by default, which would
 * break every cross-origin connection (static host / Vercel / Live Server +
 * separate signaling process). We therefore reflect the requester's origin by
 * default — safe here: the server stores nothing and authenticates nobody
 * (SRS §2.2 "post box, not a service"). Restrict via env if required:
 *   SIGNALING_CORS="https://my-frontend.example"   single origin
 *   SIGNALING_CORS="https://a.example,https://b.example"  allow-list
 *   SIGNALING_CORS="*"                              wildcard (any)
 * -------------------------------------------------------------------------- */
function resolveCorsOrigin() {
  const raw = process.env.SIGNALING_CORS;
  if (!raw || raw === "true") return true; // true = reflect requester origin
  if (raw === "*") return "*";
  return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

const io = new Server(httpServer, {
  /* Default path (/socket.io/) — matches the SRS client wiring. */
  cors: { origin: resolveCorsOrigin(), methods: ["GET", "POST"] },
});

/* ----------------------------------------------------------------------------
 * Room model (SRS §3.5 — "Your public key is your room", v2.2 mesh form)
 *
 *   rooms:        Map<publicKeyString, { socketId }>
 *   socketToKey:  Map<socketId, publicKeyString>   (reverse lookup / cleanup)
 *   pairSessions: Map<pairId, { a, b, state, createdAt }>
 *
 * pairId is the two key strings sorted and joined — order-independent, so
 * whichever side knocks, the pair lands under the same id. Each socket may
 * own several pairs at once (mesh). All pair state lives in memory only and
 * dies with the sockets (SRS §3.4 — nothing persists).
 * -------------------------------------------------------------------------- */
const rooms = new Map();
const socketToKey = new Map();
const pairSessions = new Map();

const PAIR_SEP = '\u241E'; // ASCII "Record Separator" — never appears in JWK JSON

function pairIdOf(keyA, keyB) {
  return [keyA, keyB].sort().join(PAIR_SEP);
}

function getPair(keyA, keyB) {
  return pairSessions.get(pairIdOf(keyA, keyB)) || null;
}

function addPair(keyA, keyB) {
  pairSessions.set(pairIdOf(keyA, keyB), {
    a: keyA,
    b: keyB,
    state: 'pending',
    createdAt: Date.now(),
  });
}

function removePair(keyA, keyB) {
  pairSessions.delete(pairIdOf(keyA, keyB));
}

/** Every partner key this peer currently shares a pair with (mesh: many). */
function partnersOf(publicKey) {
  const partners = [];
  for (const pair of pairSessions.values()) {
    if (pair.a === publicKey) partners.push(pair.b);
    else if (pair.b === publicKey) partners.push(pair.a);
  }
  return partners;
}

/** Register (or re-register after refresh/reconnect) a socket in its room. */
function joinRoom(socket, publicKey) {
  if (typeof publicKey !== 'string' || publicKey.length === 0) return;

  // A second tab / page refresh re-joins the same room: the newest socket
  // becomes the owner of the channel. The previous session state dies with
  // the old socket (its disconnect handler notifies every partner).
  rooms.set(publicKey, { socketId: socket.id });
  socketToKey.set(socket.id, publicKey);
}

/** Send an event to the socket currently owning a room, if any. */
function emitToRoom(publicKey, event, payload) {
  const entry = rooms.get(publicKey);
  if (!entry) return false;
  io.to(entry.socketId).emit(event, payload);
  return true;
}

/* §15.4 successor — lazy stale-pending sweep. Handshakes that never completed
 * (peer went silent mid-offer, signaling died during the ladder, …) are
 * removed so a retrying initiator is never wrongly answered room-full. */
setInterval(() => {
  const now = Date.now();
  for (const [id, pair] of pairSessions) {
    if (pair.state === 'pending' && now - pair.createdAt > PENDING_PAIR_TTL_MS) {
      pairSessions.delete(id);
    }
  }
}, SWEEP_INTERVAL_MS).unref?.();

io.on('connection', (socket) => {
  /* -- Client -> server: subscribe to own public key channel (FR-05) ----- */
  socket.on('join-room', (data) => {
    joinRoom(socket, data && data.publicKey);
  });

  /* -- Client -> server: knock on a peer's public key channel (FR-10/11) --
   * Payload from client: { to, ecdhPublicKey, timestamp }
   * `from` is NOT taken from the payload — the server derives it from the
   * sender's registered room key. This makes key spoofing on the routing
   * layer impossible (design decision, documented in DOCUMENTATION.md).
   * Mesh (v2.2): a busy target is no longer a reason to drop a knock — a
   * pair entry only blocks a SECOND handshake between the SAME two peers.
   * ---------------------------------------------------------------------- */
  socket.on('knock', (data) => {
    const initiatorPublicKey = socketToKey.get(socket.id);
    if (!initiatorPublicKey || !data) return;

    const targetPublicKey = data.to;
    if (typeof targetPublicKey !== 'string') return;

    /* Target not listening: the knock goes unanswered (SRS §3.5). The
     * offerer's 30 s knock timeout (SRS §8.3, E-04) surfaces this as
     * `PEER UNAVAILABLE`. No server event is specified for this case. */
    const targetEntry = rooms.get(targetPublicKey);
    if (!targetEntry) return;

    /* E-06, revised for mesh: the SAME pair already has a handshake or a
     * live session in flight. Dropping the knock prevents two parallel
     * handshakes A→B from interleaving their SDP. The busy target also
     * gets a one-way `knock-blocked` notice (v2.1) so a stale-state retry
     * is visible on the other side instead of silently vanishing. */
    const existingPair = getPair(initiatorPublicKey, targetPublicKey);
    if (existingPair) {
      socket.emit('room-full', { to: targetPublicKey });
      io.to(targetEntry.socketId).emit('knock-blocked', {
        from: initiatorPublicKey,
      });
      return;
    }

    /* Forward the knock (SRS §4.5 payload: from, ecdh_public_key, timestamp)
     * and record the pending pair. C-12's intent (state set at forward time,
     * cleaned lazily) survives via the pair map + sweep above. */
    addPair(initiatorPublicKey, targetPublicKey);

    emitToRoom(targetPublicKey, 'knock', {
      from: initiatorPublicKey,
      ecdhPublicKey: data.ecdhPublicKey,
      timestamp: data.timestamp,
    });
  });

  /* -- Client -> server: answerer accepts the knock (SRS §4.5) ------------
   * Client payload: { to, ecdhPublicKey }. The answerer's own key is derived
   * from its registered room. Routed to the initiator as `knock-accepted`
   * with { from, ecdhPublicKey } — the message name in §4.5. */
  socket.on('knock-accept', (data) => {
    const answererPublicKey = socketToKey.get(socket.id);
    if (!answererPublicKey || !data || typeof data.to !== 'string') return;
    emitToRoom(data.to, 'knock-accepted', {
      from: answererPublicKey,
      ecdhPublicKey: data.ecdhPublicKey,
    });
  });

  /* -- Client -> server: answerer rejects the knock (FR-15c, E-05) --------- */
  socket.on('knock-reject', (data) => {
    const answererPublicKey = socketToKey.get(socket.id);
    if (!answererPublicKey || !data || typeof data.to !== 'string') return;

    emitToRoom(data.to, 'knock-rejected', { from: answererPublicKey });

    // Definite end of handshake: clear the pair so a retry is never
    // wrongly answered room-full afterwards.
    removePair(answererPublicKey, data.to);
  });

  /* -- Client -> server: the DataChannel for a pair is OPEN (v2.2) -------- */
  socket.on('session-open', (data) => {
    const from = socketToKey.get(socket.id);
    if (!from || !data || typeof data.to !== 'string') return;
    const pair = getPair(from, data.to);
    if (pair) pair.state = 'open';
  });

  /* -- Client -> server: this side ended the session (v2.2 clean
   * disconnect — FR-53). Remove the pair; if the session had reached
   * "open", tell the far side so its UI can settle immediately instead of
   * waiting for ICE/DC timers to notice. Pending pairs end silently —
   * both sides' own §8.3 timeouts already cover handshake failure. */
  socket.on('session-end', (data) => {
    const from = socketToKey.get(socket.id);
    if (!from || !data || typeof data.to !== 'string') return;

    const pair = getPair(from, data.to);
    removePair(from, data.to);
    if (pair && pair.state === 'open') {
      emitToRoom(data.to, 'session-closed', { from });
    }
  });

  /* -- Client -> server: SDP offer (offerer, SRS §8.2) --------------------- */
  socket.on('offer', (data) => {
    const from = socketToKey.get(socket.id);
    if (!from || !data || typeof data.to !== 'string') return;
    emitToRoom(data.to, 'offer', { from, offer: data.offer });
  });

  /* -- Client -> server: SDP answer (answerer, SRS §8.2) ------------------- */
  socket.on('answer', (data) => {
    const from = socketToKey.get(socket.id);
    if (!from || !data || typeof data.to !== 'string') return;
    emitToRoom(data.to, 'answer', { from, answer: data.answer });
  });

  /* -- Client -> server: trickle ICE candidate (both sides, §8.2) ---------- */
  socket.on('ice-candidate', (data) => {
    const from = socketToKey.get(socket.id);
    if (!from || !data || typeof data.to !== 'string') return;
    emitToRoom(data.to, 'ice-candidate', { from, candidate: data.candidate });
  });

  /* -- Socket teardown: notify EVERY session partner (SRS §3.3, UC-09,
   * mesh generalisation) — one peer may be in many pairs at once. --------- */
  socket.on('disconnect', () => {
    const publicKey = socketToKey.get(socket.id);
    if (!publicKey) return;

    socketToKey.delete(socket.id);

    const entry = rooms.get(publicKey);
    // Only delete the room if THIS socket still owns it (a newer socket may
    // have re-joined the same room after a refresh).
    if (!entry || entry.socketId !== socket.id) return;

    rooms.delete(publicKey);

    for (const partner of partnersOf(publicKey)) {
      removePair(publicKey, partner);
      emitToRoom(partner, 'peer-disconnected', { publicKey });
    }
  });
});

httpServer.listen(PORT, () => {
  console.log(
    `[signal] post box open on :${PORT} — routing public key rooms, seeing no messages`
  );
  console.log(
    `[signal] frontend + Socket.io share this port — open http://localhost:${PORT}`
  );
  console.log(
    `[signal] endpoint /socket.io/ (CORS: ${
      process.env.SIGNALING_CORS || "reflect-requester-origin"
    })`
  );
  console.log(
    `[signal] mesh mode (v2.2): multiple simultaneous sessions per peer, pair-level busy guard only`
  );
});
