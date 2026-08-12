/**
 * ============================================================================
 * DECENTRALISED P2P CHAT — SIGNALING SERVER
 * SRS v2.3 — Sections 3.3, 3.4, 3.5, 8.7, 15.4
 * ----------------------------------------------------------------------------
 * "The signaling server is a post box, not a service."        (SRS §2.2)
 *
 * Responsibilities (SRS §3.3):
 *   - Accept peer socket connections
 *   - Register each peer against their public key as a channel ("room")
 *   - Route WebRTC offer, answer, and ICE candidates between channels
 *   - Route knock payloads (ECDSA public key + ECDH session public key)
 *   - Notify a peer when the other side disconnects
 *   - Emit `room-full` when the target channel is busy, drop the knock
 *   - v2.3 §15.4: clear stale `connectedTo` state at the top of the knock
 *     handler, before the room-full check
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

/* ----------------------------------------------------------------------------
 * HTTP layer — serves the static vanilla frontend (local dev convenience).
 * In production the frontend may be hosted anywhere (SRS §3.2 "Vercel (frontend)
 * + any Node host (signaling)"); this server only NEEDS the Socket.io part.
 * -------------------------------------------------------------------------- */
const app = express();
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/healthz', (_req, res) => {
  res.status(200).json({ ok: true, peers: rooms.size });
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
 * Room model (SRS §3.5 — "Your public key is your room")
 *
 *   rooms:       Map<publicKeyString, { socketId, connectedTo }>
 *   socketToKey: Map<socketId, publicKeyString>  (reverse lookup, cleanup aid)
 *
 * `connectedTo` is set when a knock is FORWARDED (SRS C-12) and cleared:
 *   - at the top of every new knock by the initiator (§15.4 step 1)
 *   - when the far end is no longer in rooms (§15.4 step 2)
 *   - when a socket disconnects / a knock is rejected (mutual cleanup)
 * -------------------------------------------------------------------------- */
const rooms = new Map();
const socketToKey = new Map();

/** Register (or re-register after refresh/reconnect) a socket in its room. */
function joinRoom(socket, publicKey) {
  if (typeof publicKey !== 'string' || publicKey.length === 0) return;

  // A second tab / page refresh re-joins the same room: the newest socket
  // becomes the owner of the channel. The previous session state dies with
  // the old socket (its disconnect handler notifies the partner).
  rooms.set(publicKey, { socketId: socket.id, connectedTo: null });
  socketToKey.set(socket.id, publicKey);
}

/** Send an event to the socket currently owning a room, if any. */
function emitToRoom(publicKey, event, payload) {
  const entry = rooms.get(publicKey);
  if (!entry) return false;
  io.to(entry.socketId).emit(event, payload);
  return true;
}

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
   * ---------------------------------------------------------------------- */
  socket.on('knock', (data) => {
    const initiatorPublicKey = socketToKey.get(socket.id);
    if (!initiatorPublicKey || !data) return;

    const targetPublicKey = data.to;
    if (typeof targetPublicKey !== 'string') return;

    /* v2.3 §15.4 — stale connectedTo cleanup, runs BEFORE the room-full
     * check, exactly as specified:
     * 1. Clear initiator's stale connectedTo (enables retry after a failed
     *    handshake). If the stale target still points back at us, clear it
     *    too so both sides are consistent.
     * 2. Clear target's stale connectedTo if that peer left rooms entirely. */
    const initEntry = rooms.get(initiatorPublicKey);
    if (initEntry && initEntry.connectedTo) {
      const staleTarget = rooms.get(initEntry.connectedTo);
      if (staleTarget && staleTarget.connectedTo === initiatorPublicKey) {
        staleTarget.connectedTo = null;
      }
      initEntry.connectedTo = null;
    }

    const targetEntry = rooms.get(targetPublicKey);
    if (
      targetEntry &&
      targetEntry.connectedTo !== null &&
      !rooms.has(targetEntry.connectedTo)
    ) {
      targetEntry.connectedTo = null;
    }

    /* Target not listening: the knock goes unanswered (SRS §3.5). The
     * offerer's 30 s knock timeout (SRS §8.3, E-04) surfaces this as
     * `PEER UNAVAILABLE`. No server event is specified for this case. */
    if (!targetEntry) return;

    /* Room-full: target already in a session (SRS §3.3, §8.7, E-06). */
    if (targetEntry.connectedTo !== null) {
      socket.emit('room-full', { to: targetPublicKey });
      return;
    }

    /* Forward the knock (SRS §4.5 payload: from, ecdh_public_key, timestamp).
     * C-12: connectedTo is set when the knock is forwarded, BEFORE WebRTC
     * completes — stale state on failed handshakes is cleaned lazily by the
     * §15.4 logic above on the next knock. */
    targetEntry.connectedTo = initiatorPublicKey;
    if (initEntry) initEntry.connectedTo = targetPublicKey;

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

    // Definite end of handshake: clear the mutual connectedTo marks so the
    // answerer is not wrongly reported busy (room-full) afterwards.
    const answererEntry = rooms.get(answererPublicKey);
    const initiatorEntry = rooms.get(data.to);
    if (answererEntry) answererEntry.connectedTo = null;
    if (initiatorEntry && initiatorEntry.connectedTo === answererPublicKey) {
      initiatorEntry.connectedTo = null;
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

  /* -- Socket teardown: notify the session partner (SRS §3.3, UC-09) ------- */
  socket.on('disconnect', () => {
    const publicKey = socketToKey.get(socket.id);
    if (!publicKey) return;

    socketToKey.delete(socket.id);

    const entry = rooms.get(publicKey);
    // Only delete the room if THIS socket still owns it (a newer socket may
    // have re-joined the same room after a refresh).
    if (!entry || entry.socketId !== socket.id) return;

    rooms.delete(publicKey);

    if (entry.connectedTo) {
      const partnerEntry = rooms.get(entry.connectedTo);
      if (partnerEntry) {
        io.to(partnerEntry.socketId).emit('peer-disconnected', {
          publicKey,
        });
        if (partnerEntry.connectedTo === publicKey) {
          partnerEntry.connectedTo = null;
        }
      }
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
});
