const crypto  = require('crypto');
const http     = require('http');
const https    = require('https');
const express  = require('express');
const cors     = require('cors');
const WebSocket = require('ws');
const db       = require('./db');

const PORT = process.env.PORT || 3748;
const MAX_STATUS_LENGTH = 60;
const MAX_MESSAGE_LENGTH = 5000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 300;
const MAX_REVISIONS_PER_MESSAGE = 20;
const MAX_REPORT_REASON_LENGTH  = 500;
const MAX_DISCORD_WEBHOOK_LENGTH = 500;
const MAX_DISCORD_PREVIEW_LENGTH = 300;
const GROUP_TYPING_THROTTLE_MS = 2500;
const MAX_REACTION_LENGTH = 16;
const MAX_BIO_LENGTH = 500;
const MAX_PRONOUNS_LENGTH = 40;
const MAX_TIMEZONE_LENGTH = 60;
const MAX_BADGE_COUNT = 12;
const MAX_LABEL_LENGTH = 30;
const VALID_PRIVACY_LEVELS = ['public', 'contacts', 'hidden'];
const ALLOWED_DISCORD_WEBHOOK_HOSTS = ['discord.com', 'discordapp.com', 'canary.discord.com', 'ptb.discord.com'];
const DISCORD_WEBHOOK_PATH_RE = /^\/api\/webhooks\/\d+\/[A-Za-z0-9._-]+$/;

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server, path: '/ws' });

// Trust the nginx reverse proxy so req.ip reflects the real client
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());

function createRateLimiter(windowMs, maxRequests) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const expiredKeys = [];
    for (const [k, v] of hits) {
      if (v.resetAt <= now) expiredKeys.push(k);
    }
    for (const k of expiredKeys) hits.delete(k);
    const key = req.ip || req.socket?.remoteAddress || 'unknown';
    const entry = hits.get(key);
    if (!entry || entry.resetAt <= now) {
      hits.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (entry.count >= maxRequests) {
      return res.status(429).json({ error: 'Too many requests' });
    }
    entry.count += 1;
    next();
  };
}
const apiLimiter = createRateLimiter(RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_REQUESTS);
app.use('/api', apiLimiter);

// ── Auth helpers ──────────────────────────────────────────────────────────────

function hashSecret(secret) {
  return crypto.createHash('sha256').update(String(secret)).digest('hex');
}

// Clients currently connected via WebSocket: memberNumber (int) → ws
const clients = new Map();
// Per-member+group typing fanout throttle
const groupTypingSentAt = new Map();

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization' });
  }
  const [memberStr, secret] = header.slice(7).split(':');
  const memberNumber = parseInt(memberStr, 10);
  if (!memberNumber || !secret) {
    return res.status(401).json({ error: 'Invalid authorization format' });
  }
  const user = db.prepare('SELECT * FROM users WHERE member_number = ?').get(memberNumber);
  if (!user || user.auth_token !== hashSecret(secret)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.memberNumber = memberNumber;
  req.user = user;
  next();
}

function normalizeDiscordWebhook(raw) {
  const value = String(raw ?? '').trim();
  if (!value) return '';
  try {
    const parsed = new URL(value);
    const host = parsed.hostname.toLowerCase();
    const allowedHost = ALLOWED_DISCORD_WEBHOOK_HOSTS.includes(host);
    if (parsed.protocol !== 'https:' || !allowedHost) return '';
    if (!DISCORD_WEBHOOK_PATH_RE.test(parsed.pathname)) return '';
    return parsed.href.slice(0, MAX_DISCORD_WEBHOOK_LENGTH);
  } catch {
    return '';
  }
}

function postDiscordWebhook(webhookUrl, payload) {
  return new Promise((resolve) => {
    try {
      const data = JSON.stringify(payload);
      const req = https.request(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
        },
        timeout: 5000,
      }, (res) => {
        // Intentionally consume response chunks so the stream fully drains before resolve.
        res.on('data', () => {});
        res.on('end', () => resolve());
      });
      req.on('timeout', () => { req.destroy(); resolve(); });
      req.on('error', () => resolve());
      req.write(data);
      req.end();
    } catch {
      resolve();
    }
  });
}

function sendDiscordWebhookDmNotification(webhookUrl, { senderName, senderNumber, recipientNumber, content }) {
  if (!webhookUrl) return;
  const escapeDiscordMarkdown = (value) => String(value ?? '').replace(/([\\`*_~|>])/g, '\\$1');
  const trimmed = String(content ?? '').trim();
  const preview = trimmed.length > MAX_DISCORD_PREVIEW_LENGTH
    ? `${trimmed.slice(0, MAX_DISCORD_PREVIEW_LENGTH - 3)}...`
    : trimmed;
  const payload = {
    username: 'BC Messenger',
    content: `📩 New offline DM for #${recipientNumber} from ${escapeDiscordMarkdown(senderName)} (#${senderNumber})\n${escapeDiscordMarkdown(preview || '(empty message)')}`,
  };
  postDiscordWebhook(webhookUrl, payload).catch(() => {});
}

// Returns true if `blockedNumber` has blocked `senderNumber`
function isBlocked(senderNumber, blockedNumber) {
  return !!db.prepare(
    'SELECT 1 FROM blocks WHERE blocker_number = ? AND blocked_number = ?'
  ).get(blockedNumber, senderNumber);
}

function computeGroupReceiptSummary(groupMessageRef, senderNumber) {
  if (!groupMessageRef || !senderNumber) return null;
  const row = db.prepare(`
    SELECT
      COUNT(*) AS total_recipients,
      SUM(CASE WHEN delivered = 1 THEN 1 ELSE 0 END) AS delivered_count,
      SUM(CASE WHEN read_at > 0 THEN 1 ELSE 0 END) AS read_count
    FROM messages
    WHERE group_message_ref = ?
      AND sender_number = ?
      AND recipient_number != sender_number
  `).get(groupMessageRef, senderNumber);
  return {
    totalRecipients: Number(row?.total_recipients || 0),
    deliveredCount: Number(row?.delivered_count || 0),
    readCount: Number(row?.read_count || 0),
  };
}

function pushGroupReceiptUpdateToSender(senderNumber, groupMessageRef) {
  const senderWs = clients.get(senderNumber);
  if (!senderWs || senderWs.readyState !== WebSocket.OPEN) return;
  const receipt = computeGroupReceiptSummary(groupMessageRef, senderNumber);
  if (!receipt || receipt.totalRecipients <= 0) return;
  const senderRow = db.prepare(
    'SELECT id, group_id FROM messages WHERE group_message_ref = ? AND sender_number = ? AND recipient_number = ? LIMIT 1'
  ).get(groupMessageRef, senderNumber, senderNumber);
  senderWs.send(JSON.stringify({
    type: 'group_message_receipt',
    groupMessageRef,
    senderMessageId: senderRow?.id ?? null,
    groupId: senderRow?.group_id ?? null,
    receipt,
  }));
}

function parseMessageRef(rawRef) {
  const messageRef = String(rawRef ?? '').trim();
  if (!messageRef) return null;
  if (/^sid:\d+$/.test(messageRef)) {
    return { type: 'message_id', id: parseInt(messageRef.slice(4), 10) };
  }
  if (messageRef.startsWith('gref:') && messageRef.length > 5) {
    return { type: 'group_ref', groupMessageRef: messageRef.slice(5) };
  }
  return null;
}

function resolveMessageReference(rawRef, memberNumber) {
  const parsed = parseMessageRef(rawRef);
  if (!parsed) return null;

  if (parsed.type === 'message_id') {
    const row = db.prepare(`
      SELECT id, group_id, group_message_ref, sender_number, recipient_number
      FROM messages
      WHERE id = ?
    `).get(parsed.id);
    if (!row) return null;

    if (row.group_id && row.group_message_ref) {
      const membership = db.prepare(
        'SELECT 1 FROM group_members WHERE group_id = ? AND member_number = ?'
      ).get(row.group_id, memberNumber);
      if (!membership) return null;
      const participants = db.prepare(
        'SELECT member_number FROM group_members WHERE group_id = ?'
      ).all(row.group_id).map(m => Number(m.member_number)).filter(Boolean);
      return {
        messageRef: `gref:${row.group_message_ref}`,
        groupId: Number(row.group_id),
        groupMessageRef: row.group_message_ref,
        participants,
      };
    }

    if (row.sender_number !== memberNumber && row.recipient_number !== memberNumber) {
      return null;
    }
    return {
      messageRef: `sid:${row.id}`,
      messageId: Number(row.id),
      participants: [Number(row.sender_number), Number(row.recipient_number)].filter(Boolean),
    };
  }

  const row = db.prepare(`
    SELECT group_id, group_message_ref
    FROM messages
    WHERE group_message_ref = ?
    LIMIT 1
  `).get(parsed.groupMessageRef);
  if (!row?.group_id) return null;
  const membership = db.prepare(
    'SELECT 1 FROM group_members WHERE group_id = ? AND member_number = ?'
  ).get(row.group_id, memberNumber);
  if (!membership) return null;
  const participants = db.prepare(
    'SELECT member_number FROM group_members WHERE group_id = ?'
  ).all(row.group_id).map(m => Number(m.member_number)).filter(Boolean);
  return {
    messageRef: `gref:${row.group_message_ref}`,
    groupId: Number(row.group_id),
    groupMessageRef: row.group_message_ref,
    participants,
  };
}

function listAccessibleReactions(memberNumber) {
  return db.prepare(`
    SELECT mr.message_ref, mr.emoji
    FROM message_reactions mr
    WHERE EXISTS (
      SELECT 1
      FROM messages m
      WHERE m.group_id IS NULL
        AND ('sid:' || m.id) = mr.message_ref
        AND (m.sender_number = ? OR m.recipient_number = ?)
    )
    OR EXISTS (
      SELECT 1
      FROM messages m
      INNER JOIN group_members gm ON gm.group_id = m.group_id
      WHERE m.group_message_ref IS NOT NULL
        AND ('gref:' || m.group_message_ref) = mr.message_ref
        AND gm.member_number = ?
    )
  `).all(memberNumber, memberNumber, memberNumber);
}

function getUserStateRow(memberNumber) {
  return db.prepare(`
    SELECT notes_json, pinned_json, muted_json, disappearing_json, notify_overrides_json, updated_at
    FROM user_state
    WHERE member_number = ?
  `).get(memberNumber);
}

function parseJsonOr(raw, fallback) {
  try {
    const parsed = JSON.parse(raw);
    return parsed == null ? fallback : parsed;
  } catch {
    return fallback;
  }
}

// ── REST routes ───────────────────────────────────────────────────────────────

// Landing page — shown when someone navigates to the relay URL directly
app.get('/', (_req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BC Messenger</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f0d14;
      color: #e8e0f0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      background: #1a1626;
      border: 1px solid #2e2540;
      border-radius: 16px;
      padding: 48px 40px;
      max-width: 520px;
      width: 100%;
      text-align: center;
      box-shadow: 0 8px 40px rgba(0,0,0,.5);
    }
    .icon { font-size: 56px; margin-bottom: 20px; }
    h1 { font-size: 26px; font-weight: 700; color: #fff; margin-bottom: 8px; }
    .sub { font-size: 14px; color: #9b85b8; margin-bottom: 28px; line-height: 1.6; }
    .features {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-bottom: 32px;
      text-align: left;
    }
    .feature {
      background: #241d35;
      border: 1px solid #2e2540;
      border-radius: 10px;
      padding: 12px 14px;
      font-size: 12px;
      color: #c9bde0;
      line-height: 1.5;
    }
    .feature strong { display: block; color: #e8e0f0; margin-bottom: 2px; font-size: 13px; }
    .install-btn {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      background: #7c3aed;
      color: #fff;
      text-decoration: none;
      font-weight: 700;
      font-size: 15px;
      padding: 14px 28px;
      border-radius: 10px;
      transition: background .15s, transform .1s;
      width: 100%;
      justify-content: center;
      margin-bottom: 12px;
    }
    .install-btn:hover { background: #6d28d9; transform: translateY(-1px); }
    .install-btn svg { flex-shrink: 0; }
    .gh-link {
      display: inline-block;
      font-size: 12px;
      color: #7c5fa8;
      text-decoration: none;
      margin-top: 6px;
    }
    .gh-link:hover { color: #a78bcc; text-decoration: underline; }
    .req {
      margin-top: 20px;
      font-size: 11px;
      color: #6b5a87;
    }
    .req a { color: #7c5fa8; text-decoration: none; }
    .req a:hover { text-decoration: underline; }
    .relay-note {
      margin-top: 24px;
      padding: 12px 16px;
      background: #13102080;
      border: 1px solid #2e2540;
      border-radius: 8px;
      font-size: 11px;
      color: #6b5a87;
      line-height: 1.6;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">💬</div>
    <h1>BC Messenger</h1>
    <p class="sub">A private messaging layer for Bondage Club — offline delivery,<br>group chat, rich message controls, and a full inbox UI.</p>

    <div class="features">
      <div class="feature"><strong>📥 Offline delivery</strong>Messages reach recipients even when they're not online.</div>
      <div class="feature"><strong>👥 Group chat</strong>Named groups with admin controls, mentions, and receipts.</div>
      <div class="feature"><strong>🔐 Spoilers &amp; one-time</strong>Hidden-until-revealed and self-destructing messages.</div>
      <div class="feature"><strong>🕐 Disappearing</strong>Per-conversation message TTL on both devices.</div>
      <div class="feature"><strong>📊 Polls</strong>Interactive polls with live vote counts.</div>
      <div class="feature"><strong>🌙 Themes</strong>Light, Dark, Midnight, Lavender &amp; custom accent colours.</div>
    </div>

    <a class="install-btn" href="https://raw.githubusercontent.com/khiles/BC-Messenger/main/bc-offline-messenger.user.js">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
      </svg>
      Install with Tampermonkey
    </a>

    <div>
      <a class="gh-link" href="https://github.com/khiles/BC-Messenger" target="_blank" rel="noopener">
        ★ View on GitHub
      </a>
    </div>

    <p class="req">
      Requires <a href="https://www.tampermonkey.net/" target="_blank" rel="noopener">Tampermonkey</a> or
      <a href="https://www.greasespot.net/" target="_blank" rel="noopener">Greasemonkey</a>.
      Works on <strong>bondageprojects.com</strong> and <strong>bondageprojects.elementfx.com</strong>.
    </p>

    <div class="relay-note">
      You've reached the BC Messenger relay server. This is the backend that enables offline message delivery — there's nothing to do here directly. Install the userscript above to get started.
    </div>
  </div>
</body>
</html>`);
});

// Health check (used by nginx upstreams / monitoring)
app.get('/health', (_req, res) => res.json({ ok: true }));

// Register (or verify existing) user
app.post('/api/register', (req, res) => {
  const { memberNumber, memberName, clientSecret, status = '', discordWebhook = '', hideLastSeen = false } = req.body || {};
  if (!memberNumber || !memberName || !clientSecret) {
    return res.status(400).json({ error: 'memberNumber, memberName, and clientSecret are required' });
  }

  const num    = parseInt(memberNumber, 10);
  const hashed = hashSecret(clientSecret);
  const now    = Date.now();
  const webhook = normalizeDiscordWebhook(discordWebhook);
  const hideLastSeenFlag = hideLastSeen ? 1 : 0;

  const existing = db.prepare('SELECT * FROM users WHERE member_number = ?').get(num);
  if (existing) {
    db.prepare('UPDATE users SET member_name = ?, auth_token = ?, last_seen = ?, status = ?, discord_webhook = ?, hide_last_seen = ? WHERE member_number = ?')
      .run(memberName, hashed, now, String(status).slice(0, MAX_STATUS_LENGTH), webhook, hideLastSeenFlag, num);
  } else {
    db.prepare('INSERT INTO users (member_number, member_name, auth_token, last_seen, status, discord_webhook, hide_last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(num, memberName, hashed, now, String(status).slice(0, MAX_STATUS_LENGTH), webhook, hideLastSeenFlag);
  }

  // Ensure a profile row exists
  db.prepare('INSERT OR IGNORE INTO user_profile (member_number) VALUES (?)').run(num);

  res.json({ success: true });
});

// Check online status of any member
app.get('/api/status/:memberNumber', (req, res) => {
  const num  = parseInt(req.params.memberNumber, 10);
  const user = db.prepare('SELECT member_name, last_seen, status, hide_last_seen, availability FROM users WHERE member_number = ?').get(num);
  const profile = getProfileRow(num) || {};
  const hideLastSeen = Number(user?.hide_last_seen || 0) === 1;
  res.json({
    memberNumber: num,
    isOnline:     clients.has(num),
    memberName:   user?.member_name ?? null,
    lastSeen:     hideLastSeen ? null : (user?.last_seen ?? null),
    status:       user?.status      ?? '',
    avatarUrl:    profile.avatar_url ?? '',
    availability:   user?.availability ?? 'online',
  });
});

// Bulk relay-online status check — accepts a list of member numbers and returns
// which ones are currently connected to the BCM relay WebSocket.
app.post('/api/status/bulk', authMiddleware, (req, res) => {
  const nums = Array.isArray(req.body?.memberNumbers) ? req.body.memberNumbers : [];
  const result = {};
  for (const raw of nums) {
    const n = parseInt(raw, 10);
    if (n) result[n] = clients.has(n);
  }
  res.json({ online: result });
});

// Store an offline message (or deliver live if recipient is connected).
// When `alreadyDelivered` is true the message was already sent via beep/whisper;
// skip WebSocket push to avoid duplicates, and only mark delivered if recipient is online.
// When `whisperDelivered` is true the message was sent as an in-room BC whisper;
// delivery is guaranteed so always mark delivered=1 and never queue for re-delivery.
app.post('/api/messages', authMiddleware, (req, res) => {
  const { recipientNumber, content, alreadyDelivered, whisperDelivered } = req.body || {};
  if (!recipientNumber || !content) {
    return res.status(400).json({ error: 'recipientNumber and content are required' });
  }

  const recipient = parseInt(recipientNumber, 10);
  const now       = Date.now();

  // Reject delivery if the recipient has blocked the sender
  if (isBlocked(req.memberNumber, recipient)) {
    return res.status(403).json({ error: 'Message not delivered' });
  }

  const result = db.prepare(
    'INSERT INTO messages (sender_number, sender_name, recipient_number, content, sent_at, parent_message_ref) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(req.memberNumber, req.user.member_name, recipient, String(content), now, req.body?.parentMessageRef || null);

  const id = result.lastInsertRowid;
  const recipientWs = clients.get(recipient);
  const isRecipientOnline = !!(recipientWs && recipientWs.readyState === WebSocket.OPEN);

  // In-room whisper: delivery is guaranteed via BC — always mark delivered, never queue.
  if (whisperDelivered) {
    db.prepare('UPDATE messages SET delivered = 1 WHERE id = ?').run(id);
    return res.json({ success: true, delivered: true, id });
  }

  // Message sent via beep: skip WebSocket push, but queue if recipient is offline.
  if (alreadyDelivered) {
    if (isRecipientOnline) {
      db.prepare('UPDATE messages SET delivered = 1 WHERE id = ?').run(id);
      return res.json({ success: true, delivered: true, id });
    }
    const recipientUser = db.prepare('SELECT discord_webhook FROM users WHERE member_number = ?').get(recipient);
    if (recipientUser?.discord_webhook) {
      sendDiscordWebhookDmNotification(recipientUser.discord_webhook, {
        senderName: req.user.member_name,
        senderNumber: req.memberNumber,
        recipientNumber: recipient,
        content,
      });
    }
    return res.json({ success: true, delivered: false, id });
  }

  // If recipient is online right now, push immediately and mark delivered
  if (isRecipientOnline) {
    recipientWs.send(JSON.stringify({
      type:         'message',
      id,
      senderNumber: req.memberNumber,
      senderName:   req.user.member_name,
      content,
      sentAt:       now,
      parentMessageRef: req.body?.parentMessageRef || null,
    }));
    db.prepare('UPDATE messages SET delivered = 1 WHERE id = ?').run(id);
    return res.json({ success: true, delivered: true, id });
  }

  const recipientUser = db.prepare('SELECT discord_webhook FROM users WHERE member_number = ?').get(recipient);
  if (recipientUser?.discord_webhook) {
    sendDiscordWebhookDmNotification(recipientUser.discord_webhook, {
      senderName: req.user.member_name,
      senderNumber: req.memberNumber,
      recipientNumber: recipient,
      content,
    });
  }

  res.json({ success: true, delivered: false, id });
});

// Acknowledge (mark delivered) a batch of message IDs
app.post('/api/messages/ack', authMiddleware, (req, res) => {
  const { messageIds } = req.body || {};
  if (!Array.isArray(messageIds) || messageIds.length === 0) {
    return res.status(400).json({ error: 'messageIds must be a non-empty array' });
  }
  const stmt = db.prepare('UPDATE messages SET delivered = 1 WHERE id = ? AND recipient_number = ?');
  for (const id of messageIds) {
    stmt.run(id, req.memberNumber);
  }
  res.json({ success: true });
});

// Fetch authenticated user message history (DM only)
app.get('/api/messages', authMiddleware, (req, res) => {
  const since = Math.max(parseInt(req.query.since, 10) || 0, 0);
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  const rows = db.prepare(`
    SELECT id, sender_number, sender_name, recipient_number, content, sent_at, delivered, read_at, deleted, parent_message_ref
    FROM messages
    WHERE group_id IS NULL
      AND sent_at >= ?
      AND (sender_number = ? OR recipient_number = ?)
    ORDER BY sent_at DESC, id DESC
    LIMIT ?
  `).all(since, req.memberNumber, req.memberNumber, limit);
  res.json({ messages: rows });
});

app.get('/api/state', authMiddleware, (req, res) => {
  const reactionRows = listAccessibleReactions(req.memberNumber);
  const reactions = Object.fromEntries(
    reactionRows
      .filter(r => r?.message_ref)
      .map(r => [String(r.message_ref), String(r.emoji ?? '')])
      .filter(([, emoji]) => !!emoji)
  );
  const starred = db.prepare(
    'SELECT message_ref FROM starred_messages WHERE member_number = ? ORDER BY starred_at DESC'
  ).all(req.memberNumber).map(row => String(row.message_ref));
  const preferences = getUserStateRow(req.memberNumber);
  res.json({
    reactions,
    starred,
    preferences: preferences ? {
      notes: parseJsonOr(preferences.notes_json, {}),
      pinned: parseJsonOr(preferences.pinned_json, []),
      muted: parseJsonOr(preferences.muted_json, []),
      disappearing: parseJsonOr(preferences.disappearing_json, {}),
      notifyOverrides: parseJsonOr(preferences.notify_overrides_json, {}),
      updatedAt: Number(preferences.updated_at || 0),
    } : null,
  });
});

app.post('/api/reactions', authMiddleware, (req, res) => {
  const resolved = resolveMessageReference(req.body?.messageRef, req.memberNumber);
  if (!resolved?.messageRef) {
    return res.status(400).json({ error: 'Invalid or inaccessible messageRef' });
  }

  const emoji = String(req.body?.emoji ?? '').trim().slice(0, MAX_REACTION_LENGTH);
  const now = Date.now();

  if (!emoji) {
    db.prepare('DELETE FROM message_reactions WHERE message_ref = ?').run(resolved.messageRef);
  } else {
    db.prepare(`
      INSERT INTO message_reactions (message_ref, emoji, set_by, reacted_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(message_ref) DO UPDATE SET
        emoji = excluded.emoji,
        set_by = excluded.set_by,
        reacted_at = excluded.reacted_at
    `).run(resolved.messageRef, emoji, req.memberNumber, now);
  }

  const payload = { type: 'reaction_updated', messageRef: resolved.messageRef, emoji };
  for (const participant of new Set(resolved.participants || [])) {
    const ws = clients.get(participant);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(payload));
    }
  }

  res.json({ success: true, messageRef: resolved.messageRef, emoji });
});

app.post('/api/stars', authMiddleware, (req, res) => {
  const resolved = resolveMessageReference(req.body?.messageRef, req.memberNumber);
  if (!resolved?.messageRef) {
    return res.status(400).json({ error: 'Invalid or inaccessible messageRef' });
  }

  if (req.body?.starred) {
    db.prepare(`
      INSERT INTO starred_messages (member_number, message_ref, starred_at)
      VALUES (?, ?, ?)
      ON CONFLICT(member_number, message_ref) DO UPDATE SET starred_at = excluded.starred_at
    `).run(req.memberNumber, resolved.messageRef, Date.now());
  } else {
    db.prepare(
      'DELETE FROM starred_messages WHERE member_number = ? AND message_ref = ?'
    ).run(req.memberNumber, resolved.messageRef);
  }

  res.json({ success: true, messageRef: resolved.messageRef, starred: !!req.body?.starred });
});

app.post('/api/preferences', authMiddleware, (req, res) => {
  const notes = req.body?.notes && typeof req.body.notes === 'object' ? req.body.notes : {};
  const pinned = Array.isArray(req.body?.pinned) ? req.body.pinned : [];
  const muted = Array.isArray(req.body?.muted) ? req.body.muted : [];
  const disappearing = req.body?.disappearing && typeof req.body.disappearing === 'object' ? req.body.disappearing : {};
  const notifyOverrides = req.body?.notifyOverrides && typeof req.body.notifyOverrides === 'object' ? req.body.notifyOverrides : {};
  const now = Date.now();

  db.prepare(`
    INSERT INTO user_state (member_number, notes_json, pinned_json, muted_json, disappearing_json, notify_overrides_json, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(member_number) DO UPDATE SET
      notes_json = excluded.notes_json,
      pinned_json = excluded.pinned_json,
      muted_json = excluded.muted_json,
      disappearing_json = excluded.disappearing_json,
      notify_overrides_json = excluded.notify_overrides_json,
      updated_at = excluded.updated_at
  `).run(
    req.memberNumber,
    JSON.stringify(notes),
    JSON.stringify(pinned.map(n => Number(n)).filter(Boolean)),
    JSON.stringify(muted.map(n => Number(n)).filter(Boolean)),
    JSON.stringify(disappearing),
    JSON.stringify(notifyOverrides),
    now
  );

  const ws = clients.get(req.memberNumber);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: 'preferences_updated',
      preferences: { notes, pinned, muted, disappearing, notifyOverrides, updatedAt: now },
    }));
  }

  res.json({ success: true, updatedAt: now });
});

// ── Group routes ──────────────────────────────────────────────────────────────

// Create a new group
app.post('/api/groups', authMiddleware, (req, res) => {
  const { name, memberNumbers } = req.body || {};
  if (!name || !Array.isArray(memberNumbers)) {
    return res.status(400).json({ error: 'name and memberNumbers array are required' });
  }

  const now = Date.now();
  const avatarColor = `hsl(${Math.floor(Math.random() * 360)}, 70%, 60%)`;

  try {
    const result = db.prepare(
      'INSERT INTO groups (name, created_by, created_at, avatar_color) VALUES (?, ?, ?, ?)'
    ).run(name, req.memberNumber, now, avatarColor);

    const groupId = result.lastInsertRowid;

    db.prepare(
      'INSERT INTO group_members (group_id, member_number, joined_at, role) VALUES (?, ?, ?, ?)'
    ).run(groupId, req.memberNumber, now, 'admin');

    const addMemberStmt = db.prepare(
      'INSERT INTO group_members (group_id, member_number, joined_at, role) VALUES (?, ?, ?, ?)'
    );
    const requestedMemberSet = new Set();
    for (const memberNum of memberNumbers) {
      const num = parseInt(memberNum, 10);
      if (num && num !== req.memberNumber) {
        if (requestedMemberSet.has(num)) continue;
        requestedMemberSet.add(num);
        addMemberStmt.run(groupId, num, now, 'member');
      }
    }

    const fullMembers = db.prepare(
      'SELECT member_number, role FROM group_members WHERE group_id = ? ORDER BY joined_at ASC'
    ).all(groupId);

    const allMembers = [req.memberNumber, ...requestedMemberSet];
    for (const memberNum of allMembers) {
      const memberWs = clients.get(memberNum);
      if (memberWs && memberWs.readyState === WebSocket.OPEN) {
        memberWs.send(JSON.stringify({
          type: 'group_created', groupId, name,
          createdBy: req.memberNumber, createdAt: now, avatarColor,
          members: fullMembers,
        }));
      }
    }

    res.json({ success: true, groupId });
  } catch (err) {
    console.error('Error creating group:', err);
    res.status(500).json({ error: 'Failed to create group' });
  }
});

// Get all groups for authenticated user
app.get('/api/groups', authMiddleware, (req, res) => {
  try {
    const groups = db.prepare(`
      SELECT g.id, g.name, g.created_by, g.created_at, g.avatar_color
      FROM groups g
      INNER JOIN group_members gm ON g.id = gm.group_id
      WHERE gm.member_number = ?
      ORDER BY g.created_at DESC
    `).all(req.memberNumber);

    const result = groups.map(g => {
      const members = db.prepare(
        'SELECT member_number, role FROM group_members WHERE group_id = ?'
      ).all(g.id);
      return { ...g, members };
    });

    res.json({ groups: result });
  } catch (err) {
    console.error('Error fetching groups:', err);
    res.status(500).json({ error: 'Failed to fetch groups' });
  }
});

// Get a specific group
app.get('/api/groups/:groupId', authMiddleware, (req, res) => {
  const groupId = parseInt(req.params.groupId, 10);
  try {
    const membership = db.prepare(
      'SELECT role FROM group_members WHERE group_id = ? AND member_number = ?'
    ).get(groupId, req.memberNumber);
    if (!membership) return res.status(403).json({ error: 'Not a member of this group' });

    const group = db.prepare('SELECT * FROM groups WHERE id = ?').get(groupId);
    if (!group) return res.status(404).json({ error: 'Group not found' });

    const members = db.prepare(
      'SELECT member_number, role, joined_at FROM group_members WHERE group_id = ?'
    ).all(groupId);

    res.json({ ...group, members });
  } catch (err) {
    console.error('Error fetching group:', err);
    res.status(500).json({ error: 'Failed to fetch group' });
  }
});

// Rename a group (admin-only)
app.post('/api/groups/:groupId/rename', authMiddleware, (req, res) => {
  const groupId = parseInt(req.params.groupId, 10);
  const name = String(req.body?.name ?? '').trim().slice(0, 100);
  if (!name) return res.status(400).json({ error: 'name is required' });

  try {
    const selfMembership = db.prepare(
      'SELECT role FROM group_members WHERE group_id = ? AND member_number = ?'
    ).get(groupId, req.memberNumber);
    if (!selfMembership) return res.status(403).json({ error: 'Not a member' });
    if (selfMembership.role !== 'admin') return res.status(403).json({ error: 'Only admins can rename groups' });

    const update = db.prepare('UPDATE groups SET name = ? WHERE id = ?').run(name, groupId);
    if (!update.changes) return res.status(404).json({ error: 'Group not found' });

    const members = db.prepare('SELECT member_number FROM group_members WHERE group_id = ?').all(groupId);
    for (const m of members) {
      const wsClient = clients.get(m.member_number);
      if (wsClient && wsClient.readyState === WebSocket.OPEN) {
        wsClient.send(JSON.stringify({ type: 'group_renamed', groupId, name, renamedBy: req.memberNumber }));
      }
    }
    res.json({ success: true, groupId, name });
  } catch (err) {
    console.error('Error renaming group:', err);
    res.status(500).json({ error: 'Failed to rename group' });
  }
});

// Add members to a group
app.post('/api/groups/:groupId/members', authMiddleware, (req, res) => {
  const groupId = parseInt(req.params.groupId, 10);
  const { memberNumbers } = req.body || {};
  if (!Array.isArray(memberNumbers) || memberNumbers.length === 0) {
    return res.status(400).json({ error: 'memberNumbers array is required' });
  }
  try {
    const membership = db.prepare(
      'SELECT role FROM group_members WHERE group_id = ? AND member_number = ?'
    ).get(groupId, req.memberNumber);
    if (!membership) return res.status(403).json({ error: 'Not a member' });
    if (membership.role !== 'admin') return res.status(403).json({ error: 'Only admins can add members' });

    const group = db.prepare('SELECT name, avatar_color FROM groups WHERE id = ?').get(groupId);
    if (!group) return res.status(404).json({ error: 'Group not found' });

    const now = Date.now();
    const addMemberStmt = db.prepare(
      'INSERT OR IGNORE INTO group_members (group_id, member_number, joined_at, role) VALUES (?, ?, ?, ?)'
    );
    const added = [];
    const skipped = [];
    const seen = new Set();
    for (const memberNum of memberNumbers) {
      const num = parseInt(memberNum, 10);
      if (!num) { skipped.push({ memberNumber: memberNum, reason: 'Invalid' }); continue; }
      if (seen.has(num)) continue;
      seen.add(num);
      if (num === req.memberNumber) { skipped.push({ memberNumber: num, reason: 'Already in group' }); continue; }
      const targetUser = db.prepare('SELECT 1 FROM users WHERE member_number = ?').get(num);
      if (!targetUser) { skipped.push({ memberNumber: num, reason: 'Not registered' }); continue; }
      if (isBlocked(req.memberNumber, num) || isBlocked(num, req.memberNumber)) {
        skipped.push({ memberNumber: num, reason: 'Cannot add blocked member' }); continue;
      }
      const existing = db.prepare('SELECT 1 FROM group_members WHERE group_id = ? AND member_number = ?').get(groupId, num);
      if (existing) { skipped.push({ memberNumber: num, reason: 'Already in group' }); continue; }
      const result = addMemberStmt.run(groupId, num, now, 'member');
      if (result.changes > 0) {
        added.push(num);
        const memberWs = clients.get(num);
        if (memberWs && memberWs.readyState === WebSocket.OPEN) {
          memberWs.send(JSON.stringify({ type: 'group_member_added', groupId, groupName: group.name, avatarColor: group.avatar_color, addedBy: req.memberNumber }));
        }
      }
    }
    if (added.length) {
      const fullMembers = db.prepare('SELECT member_number, role FROM group_members WHERE group_id = ? ORDER BY joined_at ASC').all(groupId);
      const allMembers = db.prepare('SELECT member_number FROM group_members WHERE group_id = ?').all(groupId);
      for (const member of allMembers) {
        const wsClient = clients.get(member.member_number);
        if (wsClient && wsClient.readyState === WebSocket.OPEN) {
          wsClient.send(JSON.stringify({ type: 'group_members_updated', groupId, members: fullMembers }));
        }
      }
    }
    if (!added.length && skipped.length) return res.status(400).json({ error: skipped[0].reason, skipped });
    res.json({ success: true, added, skipped });
  } catch (err) {
    console.error('Error adding members:', err);
    res.status(500).json({ error: 'Failed to add members' });
  }
});

// Remove a member from a group
app.delete('/api/groups/:groupId/members/:memberNumber', authMiddleware, (req, res) => {
  const groupId = parseInt(req.params.groupId, 10);
  const targetMember = parseInt(req.params.memberNumber, 10);
  try {
    const membership = db.prepare('SELECT role FROM group_members WHERE group_id = ? AND member_number = ?').get(groupId, req.memberNumber);
    const targetMembership = db.prepare('SELECT role FROM group_members WHERE group_id = ? AND member_number = ?').get(groupId, targetMember);
    if (!membership) return res.status(403).json({ error: 'Not a member' });
    if (!targetMembership) return res.status(404).json({ error: 'Target not in group' });
    if (targetMember !== req.memberNumber && membership.role !== 'admin') return res.status(403).json({ error: 'Only admins can remove others' });

    const totalMembers = db.prepare('SELECT COUNT(*) AS c FROM group_members WHERE group_id = ?').get(groupId)?.c ?? 0;

    // Last remaining member: allow leave and delete the entire group
    if (totalMembers === 1) {
      const ownedGroupIds = [groupId];
      db.prepare('DELETE FROM message_reactions WHERE message_ref IN (SELECT DISTINCT \'gref:\' || group_message_ref FROM messages WHERE group_id = ? AND group_message_ref IS NOT NULL)').run(groupId);
      db.prepare('DELETE FROM message_revisions WHERE message_id IN (SELECT id FROM messages WHERE group_id = ?)').run(groupId);
      db.prepare('DELETE FROM message_collections WHERE message_ref IN (SELECT DISTINCT \'gref:\' || group_message_ref FROM messages WHERE group_id = ? AND group_message_ref IS NOT NULL)').run(groupId);
      db.prepare('DELETE FROM messages WHERE group_id = ?').run(groupId);
      db.prepare('DELETE FROM group_members WHERE group_id = ?').run(groupId);
      db.prepare('DELETE FROM groups WHERE id = ?').run(groupId);

      const memberWs = clients.get(targetMember);
      if (memberWs && memberWs.readyState === WebSocket.OPEN) {
        memberWs.send(JSON.stringify({ type: 'group_member_removed', groupId, removedBy: req.memberNumber }));
      }
      return res.json({ success: true, groupDeleted: true });
    }

    // There are other members but this is the last admin
    if (targetMembership.role === 'admin') {
      const adminCount = db.prepare('SELECT COUNT(*) AS c FROM group_members WHERE group_id = ? AND role = ?').get(groupId, 'admin')?.c ?? 0;
      if (adminCount <= 1) return res.status(400).json({ error: 'You are the only admin. Promote another member to admin before leaving.' });
    }

    db.prepare('DELETE FROM group_members WHERE group_id = ? AND member_number = ?').run(groupId, targetMember);
    const fullMembers = db.prepare('SELECT member_number, role FROM group_members WHERE group_id = ? ORDER BY joined_at ASC').all(groupId);
    const remaining = db.prepare('SELECT member_number FROM group_members WHERE group_id = ?').all(groupId);
    for (const member of remaining) {
      const wsClient = clients.get(member.member_number);
      if (wsClient && wsClient.readyState === WebSocket.OPEN) {
        wsClient.send(JSON.stringify({ type: 'group_members_updated', groupId, members: fullMembers }));
      }
    }
    const memberWs = clients.get(targetMember);
    if (memberWs && memberWs.readyState === WebSocket.OPEN) {
      memberWs.send(JSON.stringify({ type: 'group_member_removed', groupId, removedBy: req.memberNumber }));
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Error removing member:', err);
    res.status(500).json({ error: 'Failed to remove member' });
  }
});

// Promote/demote a member (admin-only)
app.post('/api/groups/:groupId/members/:memberNumber/role', authMiddleware, (req, res) => {
  const groupId = parseInt(req.params.groupId, 10);
  const targetMember = parseInt(req.params.memberNumber, 10);
  const role = String(req.body?.role ?? '').trim();
  if (!['admin', 'member'].includes(role)) return res.status(400).json({ error: 'role must be admin or member' });
  try {
    const selfMembership = db.prepare('SELECT role FROM group_members WHERE group_id = ? AND member_number = ?').get(groupId, req.memberNumber);
    if (!selfMembership) return res.status(403).json({ error: 'Not a member' });
    if (selfMembership.role !== 'admin') return res.status(403).json({ error: 'Only admins can update roles' });
    const targetMembership = db.prepare('SELECT role FROM group_members WHERE group_id = ? AND member_number = ?').get(groupId, targetMember);
    if (!targetMembership) return res.status(404).json({ error: 'Target not in group' });
    if (targetMembership.role === 'admin' && role === 'member') {
      const adminCount = db.prepare('SELECT COUNT(*) AS c FROM group_members WHERE group_id = ? AND role = ?').get(groupId, 'admin')?.c ?? 0;
      if (adminCount <= 1) return res.status(400).json({ error: 'Group must have at least one admin' });
    }
    db.prepare('UPDATE group_members SET role = ? WHERE group_id = ? AND member_number = ?').run(role, groupId, targetMember);
    const fullMembers = db.prepare('SELECT member_number, role FROM group_members WHERE group_id = ? ORDER BY joined_at ASC').all(groupId);
    const members = db.prepare('SELECT member_number FROM group_members WHERE group_id = ?').all(groupId);
    for (const m of members) {
      const wsClient = clients.get(m.member_number);
      if (wsClient && wsClient.readyState === WebSocket.OPEN) {
        wsClient.send(JSON.stringify({ type: 'group_members_updated', groupId, members: fullMembers }));
      }
    }
    res.json({ success: true, groupId, memberNumber: targetMember, role });
  } catch (err) {
    console.error('Error updating role:', err);
    res.status(500).json({ error: 'Failed to update role' });
  }
});

// Send a group message
app.post('/api/groups/:groupId/messages', authMiddleware, (req, res) => {
  const groupId = parseInt(req.params.groupId, 10);
  const { content, mentionTargets } = req.body || {};
  if (!content) return res.status(400).json({ error: 'content is required' });

  const mentions = Array.isArray(mentionTargets)
    ? mentionTargets.map(n => parseInt(n, 10)).filter(n => Number.isFinite(n) && n > 0)
    : [];

  try {
    const membership = db.prepare('SELECT 1 FROM group_members WHERE group_id = ? AND member_number = ?').get(groupId, req.memberNumber);
    if (!membership) return res.status(403).json({ error: 'Not a member' });

    const members = db.prepare('SELECT member_number FROM group_members WHERE group_id = ?').all(groupId);
    const memberSet = new Set(members.map(m => m.member_number));
    const validMentions = mentions.filter(n => memberSet.has(n));
    const mentionJson = validMentions.length ? JSON.stringify(validMentions) : null;

    const now = Date.now();
    const groupMessageRef = `g:${groupId}:${req.memberNumber}:${now}:${Math.random().toString(36).slice(2, 10)}`;
    const insertStmt = db.prepare(
      'INSERT INTO messages (sender_number, sender_name, recipient_number, content, sent_at, group_id, message_type, delivered, read_at, mention_targets, group_message_ref, parent_message_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    );

    const messageIds = [];
    let senderMessageId = null;

    for (const member of members) {
      const isSender = member.member_number === req.memberNumber;
      const delivered = isSender ? 1 : (clients.has(member.member_number) ? 1 : 0);
      const readAt = isSender ? now : 0;
      const result = insertStmt.run(
        req.memberNumber, req.user.member_name, member.member_number,
        String(content), now, groupId, 'group', delivered, readAt,
        mentionJson, groupMessageRef, req.body?.parentMessageRef || null
      );
      if (isSender) senderMessageId = result.lastInsertRowid;
      else messageIds.push({ recipientNumber: member.member_number, messageId: result.lastInsertRowid });

      const memberWs = clients.get(member.member_number);
      if (!isSender && memberWs && memberWs.readyState === WebSocket.OPEN) {
        const isMentioned = validMentions.includes(member.member_number);
        memberWs.send(JSON.stringify({
          type: 'group_message', id: result.lastInsertRowid, groupId, groupMessageRef,
          senderNumber: req.memberNumber, senderName: req.user.member_name,
          content, sentAt: now, mentionTargets: validMentions, mentioned: isMentioned,
          parentMessageRef: req.body?.parentMessageRef || null,
        }));
      }
    }

    const receipt = computeGroupReceiptSummary(groupMessageRef, req.memberNumber);
    res.json({ success: true, messageIds, senderMessageId, groupMessageRef, receipt });
  } catch (err) {
    console.error('Error sending group message:', err);
    res.status(500).json({ error: 'Failed to send group message' });
  }
});

// Get group message history
app.get('/api/groups/:groupId/messages', authMiddleware, (req, res) => {
  const groupId = parseInt(req.params.groupId, 10);
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  const offset = parseInt(req.query.offset, 10) || 0;

  try {
    const membership = db.prepare('SELECT 1 FROM group_members WHERE group_id = ? AND member_number = ?').get(groupId, req.memberNumber);
    if (!membership) return res.status(403).json({ error: 'Not a member' });

    const messages = db.prepare(`
      SELECT
        m.id, m.sender_number, m.sender_name, m.content, m.sent_at, m.delivered, m.read_at, m.deleted, m.group_message_ref,
        CASE WHEN m.group_message_ref IS NULL THEN NULL
          ELSE (SELECT COUNT(*) FROM messages mx WHERE mx.group_message_ref = m.group_message_ref AND mx.sender_number = m.sender_number AND mx.recipient_number != mx.sender_number)
        END AS total_recipients,
        CASE WHEN m.group_message_ref IS NULL THEN NULL
          ELSE (SELECT SUM(CASE WHEN mx.delivered = 1 THEN 1 ELSE 0 END) FROM messages mx WHERE mx.group_message_ref = m.group_message_ref AND mx.sender_number = m.sender_number AND mx.recipient_number != mx.sender_number)
        END AS delivered_count,
        CASE WHEN m.group_message_ref IS NULL THEN NULL
          ELSE (SELECT SUM(CASE WHEN mx.read_at > 0 THEN 1 ELSE 0 END) FROM messages mx WHERE mx.group_message_ref = m.group_message_ref AND mx.sender_number = m.sender_number AND mx.recipient_number != mx.sender_number)
        END AS read_count
      FROM messages m
      WHERE m.group_id = ? AND m.recipient_number = ?
      ORDER BY m.sent_at DESC LIMIT ? OFFSET ?
    `).all(groupId, req.memberNumber, limit, offset);

    res.json({ messages: messages.reverse() });
  } catch (err) {
    console.error('Error fetching group messages:', err);
    res.status(500).json({ error: 'Failed to fetch group messages' });
  }
});

// Per-member receipt detail for a group message (sender only)
app.get('/api/groups/messages/:groupMessageRef/receipts', authMiddleware, (req, res) => {
  const ref = req.params.groupMessageRef;
  const senderNumber = req.memberNumber;
  const rows = db.prepare(`
    SELECT recipient_number, delivered, read_at
    FROM   messages
    WHERE  group_message_ref = ?
      AND  sender_number     = ?
      AND  recipient_number != ?
  `).all(ref, senderNumber, senderNumber);
  res.json({ receipts: rows });
});

// ── Edit history routes ───────────────────────────────────────────────────────

app.get('/api/messages/:messageId/revisions', authMiddleware, (req, res) => {
  const messageId = parseInt(req.params.messageId, 10);
  if (!messageId) return res.status(400).json({ error: 'Invalid message ID' });

  const msg = db.prepare('SELECT id, sender_number, recipient_number, group_id FROM messages WHERE id = ?').get(messageId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });

  const isAllowed = msg.sender_number === req.memberNumber ||
    msg.recipient_number === req.memberNumber ||
    (msg.group_id && !!db.prepare('SELECT 1 FROM group_members WHERE group_id = ? AND member_number = ?').get(msg.group_id, req.memberNumber));

  if (!isAllowed) return res.status(403).json({ error: 'Forbidden' });

  const revisions = db.prepare(
    'SELECT id, content, revised_at, revised_by FROM message_revisions WHERE message_id = ? ORDER BY revised_at ASC'
  ).all(messageId);

  res.json({ revisions });
});

// Get reply thread for a message
app.get('/api/messages/:messageId/thread', authMiddleware, (req, res) => {
  const messageId = parseInt(req.params.messageId, 10);
  if (!messageId) return res.status(400).json({ error: 'Invalid message ID' });

  const msg = db.prepare('SELECT id, group_id, group_message_ref, sender_number, recipient_number FROM messages WHERE id = ?').get(messageId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });

  // Build the messageRef for this message
  let messageRef;
  if (msg.group_id && msg.group_message_ref) {
    messageRef = `gref:${msg.group_message_ref}`;
  } else {
    messageRef = `sid:${msg.id}`;
  }

  // Find all replies (messages that have this messageRef as parent)
  const replies = db.prepare(`
    SELECT id, sender_number, sender_name, content, sent_at, edited, deleted
    FROM messages
    WHERE parent_message_ref = ?
    ORDER BY sent_at ASC
  `).all(messageRef);

  res.json({ messageRef, replies });
});

// ── Block / unblock routes ────────────────────────────────────────────────────

app.get('/api/blocks', authMiddleware, (req, res) => {
  const rows = db.prepare(
    'SELECT blocked_number, blocked_at FROM blocks WHERE blocker_number = ? ORDER BY blocked_at DESC'
  ).all(req.memberNumber);
  res.json({ blocks: rows });
});

app.post('/api/blocks', authMiddleware, (req, res) => {
  const target = parseInt(req.body?.memberNumber, 10);
  if (!target || target === req.memberNumber) return res.status(400).json({ error: 'Invalid memberNumber' });
  db.prepare('INSERT OR IGNORE INTO blocks (blocker_number, blocked_number, blocked_at) VALUES (?, ?, ?)')
    .run(req.memberNumber, target, Date.now());
  db.prepare('DELETE FROM messages WHERE group_id IS NULL AND delivered = 0 AND sender_number = ? AND recipient_number = ?')
    .run(target, req.memberNumber);
  res.json({ success: true });
});

app.delete('/api/blocks/:memberNumber', authMiddleware, (req, res) => {
  const target = parseInt(req.params.memberNumber, 10);
  if (!target) return res.status(400).json({ error: 'Invalid memberNumber' });
  db.prepare('DELETE FROM blocks WHERE blocker_number = ? AND blocked_number = ?').run(req.memberNumber, target);
  res.json({ success: true });
});

// ── Report routes ─────────────────────────────────────────────────────────────

app.get('/api/reports', authMiddleware, (req, res) => {
  const limit = Math.max(1, Math.min(100, parseInt(req.query?.limit, 10) || 30));
  const rows = db.prepare(
    'SELECT id, target_number, message_id, reason, reported_at, status FROM reports WHERE reporter_number = ? ORDER BY reported_at DESC LIMIT ?'
  ).all(req.memberNumber, limit);
  res.json({ reports: rows });
});

app.post('/api/reports', authMiddleware, (req, res) => {
  const target = parseInt(req.body?.targetNumber, 10);
  const messageId = parseInt(req.body?.messageId, 10) || null;
  const reason = String(req.body?.reason ?? '').trim().slice(0, MAX_REPORT_REASON_LENGTH);
  if (!target || target === req.memberNumber) return res.status(400).json({ error: 'Invalid targetNumber' });
  if (messageId) {
    const msg = db.prepare('SELECT sender_number, recipient_number, group_id FROM messages WHERE id = ?').get(messageId);
    if (!msg) return res.status(403).json({ error: 'Cannot report a message you are not party to' });
    let allowed = msg.sender_number === req.memberNumber || msg.recipient_number === req.memberNumber;
    if (!allowed && msg.group_id) {
      allowed = !!db.prepare('SELECT 1 FROM group_members WHERE group_id = ? AND member_number = ?').get(msg.group_id, req.memberNumber);
    }
    if (!allowed) return res.status(403).json({ error: 'Cannot report a message you are not party to' });
  }
  const result = db.prepare(
    'INSERT INTO reports (reporter_number, target_number, message_id, reason, reported_at) VALUES (?, ?, ?, ?, ?)'
  ).run(req.memberNumber, target, messageId, reason, Date.now());
  res.json({ success: true, reportId: result.lastInsertRowid });
});

// ── Account delete ────────────────────────────────────────────────────────────

app.delete('/api/account/data', authMiddleware, (req, res) => {
  const member = req.memberNumber;

  // Ensure foreign keys are off to prevent unexpected cascading
  db.exec('PRAGMA foreign_keys = OFF');

  const safeRun = (label, stmt, ...params) => {
    try { db.prepare(stmt).run(...params); }
    catch (e) { console.error(`[BCM] Account wipe — ${label}:`, e.message); }
  };

  // 1. Delete owned groups and all their data
  try {
    const ownedGroups = db.prepare('SELECT id FROM groups WHERE created_by = ?').all(member);
    const ownedGroupIds = (ownedGroups || []).map(g => Number(g.id)).filter(Boolean);
    for (const gid of ownedGroupIds) {
      safeRun('poll_votes (owned group)', 'DELETE FROM poll_votes WHERE message_ref IN (SELECT DISTINCT \'gref:\' || group_message_ref FROM messages WHERE group_id = ? AND group_message_ref IS NOT NULL)', gid);
      safeRun('message_polls (owned group)', 'DELETE FROM message_polls WHERE message_ref IN (SELECT DISTINCT \'gref:\' || group_message_ref FROM messages WHERE group_id = ? AND group_message_ref IS NOT NULL)', gid);
      safeRun('message_collections (owned group)', 'DELETE FROM message_collections WHERE message_ref IN (SELECT DISTINCT \'gref:\' || group_message_ref FROM messages WHERE group_id = ? AND group_message_ref IS NOT NULL)', gid);
      safeRun('message_reactions (owned group)', 'DELETE FROM message_reactions WHERE message_ref IN (SELECT DISTINCT \'gref:\' || group_message_ref FROM messages WHERE group_id = ? AND group_message_ref IS NOT NULL)', gid);
      safeRun('message_revisions (owned group)', 'DELETE FROM message_revisions WHERE message_id IN (SELECT id FROM messages WHERE group_id = ?)', gid);
      safeRun('messages (owned group)', 'DELETE FROM messages WHERE group_id = ?', gid);
      safeRun('group_members (owned group)', 'DELETE FROM group_members WHERE group_id = ?', gid);
      safeRun('groups', 'DELETE FROM groups WHERE id = ?', gid);
    }
  } catch (e) { console.error('[BCM] Account wipe — owned groups:', e.message); }

  // 2. Delete user's poll votes
  safeRun('poll_votes', 'DELETE FROM poll_votes WHERE member_number = ?', member);

  // 3. Delete polls the user created (DM and group)
  safeRun('message_polls (DM)', 'DELETE FROM message_polls WHERE message_ref IN (SELECT DISTINCT \'sid:\' || id FROM messages WHERE sender_number = ? OR recipient_number = ?)', member, member);
  safeRun('message_polls (group)', 'DELETE FROM message_polls WHERE message_ref IN (SELECT DISTINCT \'gref:\' || group_message_ref FROM messages WHERE group_message_ref IS NOT NULL AND (sender_number = ? OR recipient_number = ?))', member, member);

  // 4. Delete user's group memberships
  safeRun('group_members', 'DELETE FROM group_members WHERE member_number = ?', member);

  // 5. Delete reactions (DM and group)
  safeRun('message_reactions (DM)', 'DELETE FROM message_reactions WHERE message_ref IN (SELECT \'sid:\' || id FROM messages WHERE sender_number = ? OR recipient_number = ?)', member, member);
  safeRun('message_reactions (group)', 'DELETE FROM message_reactions WHERE message_ref IN (SELECT DISTINCT \'gref:\' || group_message_ref FROM messages WHERE group_message_ref IS NOT NULL AND (sender_number = ? OR recipient_number = ?))', member, member);

  // 6. Delete revisions
  safeRun('message_revisions', 'DELETE FROM message_revisions WHERE message_id IN (SELECT id FROM messages WHERE sender_number = ? OR recipient_number = ?)', member, member);

  // 7. Delete messages
  safeRun('messages', 'DELETE FROM messages WHERE sender_number = ? OR recipient_number = ?', member, member);

  // 8. Delete remaining user-scoped data
  safeRun('starred_messages', 'DELETE FROM starred_messages WHERE member_number = ?', member);
  safeRun('user_state', 'DELETE FROM user_state WHERE member_number = ?', member);
  safeRun('blocks', 'DELETE FROM blocks WHERE blocker_number = ? OR blocked_number = ?', member, member);
  safeRun('reports', 'DELETE FROM reports WHERE reporter_number = ? OR target_number = ?', member, member);
  safeRun('sync_cursors', 'DELETE FROM sync_cursors WHERE member_number = ?', member);
  safeRun('user_profile', 'DELETE FROM user_profile WHERE member_number = ?', member);
  safeRun('trusted_contacts', 'DELETE FROM trusted_contacts WHERE user_number = ? OR trusted_number = ?', member, member);
  safeRun('conversation_folders', 'DELETE FROM conversation_folders WHERE member_number = ? OR target_number = ?', member, member);
  safeRun('message_requests', 'DELETE FROM message_requests WHERE sender_number = ? OR recipient_number = ?', member, member);
  safeRun('message_collections', 'DELETE FROM message_collections WHERE member_number = ?', member);

  // 9. Delete user last so foreign keys cascade naturally if enabled
  safeRun('users', 'DELETE FROM users WHERE member_number = ?', member);

  // Notify and disconnect
  const ws = clients.get(member);
  if (ws && ws.readyState === WebSocket.OPEN) {
    try { ws.send(JSON.stringify({ type: 'account_deleted' })); } catch {}
    try { ws.close(); } catch {}
  }
  clients.delete(member);

  res.json({ success: true });
});

// ── Sync checkpoint routes ────────────────────────────────────────────────────

const syncCursorUpsert = db.prepare(
  'INSERT INTO sync_cursors (member_number, cursor_at) VALUES (?, ?) ON CONFLICT(member_number) DO UPDATE SET cursor_at = excluded.cursor_at WHERE excluded.cursor_at > cursor_at'
);

function isValidCursor(value) {
  return Number.isFinite(value) && value >= 0;
}

function advanceSyncCursor(memberNum, cursorAt) {
  if (Number.isFinite(cursorAt) && cursorAt > 0) syncCursorUpsert.run(memberNum, cursorAt);
}

app.get('/api/sync/checkpoint', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT cursor_at FROM sync_cursors WHERE member_number = ?').get(req.memberNumber);
  res.json({ cursorAt: row?.cursor_at ?? 0 });
});

app.post('/api/sync/checkpoint', authMiddleware, (req, res) => {
  const cursorAt = parseInt(req.body?.cursorAt, 10);
  if (!isValidCursor(cursorAt)) return res.status(400).json({ error: 'cursorAt must be a non-negative integer' });
  advanceSyncCursor(req.memberNumber, cursorAt);
  res.json({ success: true });
});

// Update availability state
app.put('/api/availability', authMiddleware, (req, res) => {
  const availability = ['online', 'away', 'dnd', 'invisible'].includes(req.body?.availability)
    ? req.body.availability : 'online';
  const dndStart = String(req.body?.dndStart ?? '').trim() || null;
  const dndEnd = String(req.body?.dndEnd ?? '').trim() || null;

  db.prepare('UPDATE users SET availability = ?, dnd_start = ?, dnd_end = ? WHERE member_number = ?')
    .run(availability, dndStart, dndEnd, req.memberNumber);

  res.json({ success: true, availability, dndStart, dndEnd });
});

// ── Profile routes ─────────────────────────────────────────────────────────────

function getProfileRow(memberNumber) {
  return db.prepare('SELECT * FROM user_profile WHERE member_number = ?').get(memberNumber);
}

function resolveProfileVisibility(profileRow, viewerNumber, field, profileOwnerNum) {
  const privacy = String((profileRow && profileRow[`privacy_${field}`]) || 'public');
  if (privacy === 'public') return true;
  if (privacy === 'hidden') return false;
  if (privacy === 'contacts') {
    if (viewerNumber === profileOwnerNum) return true;
    const isContact = !!db.prepare(
      'SELECT 1 FROM messages WHERE group_id IS NULL AND ((sender_number = ? AND recipient_number = ?) OR (sender_number = ? AND recipient_number = ?)) LIMIT 1'
    ).get(profileOwnerNum, viewerNumber, viewerNumber, profileOwnerNum);
    return !!isContact;
  }
  return privacy === 'public';
}

// Get a user's public profile (privacy-filtered)
app.get('/api/profile/:memberNumber', (req, res) => {
  const targetNum = parseInt(req.params.memberNumber, 10);
  if (!targetNum) return res.status(400).json({ error: 'Invalid member number' });

  const user = db.prepare('SELECT member_name, last_seen, status, hide_last_seen FROM users WHERE member_number = ?').get(targetNum);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const profile = getProfileRow(targetNum) || {};
  const viewerNum = req.memberNumber || 0;

  const hideLastSeen = Number(user.hide_last_seen || 0) === 1;
  const isOwn = viewerNum === targetNum;

  const result = {
    memberNumber: targetNum,
    memberName: user.member_name,
    isOnline: clients.has(targetNum),
    lastSeen: hideLastSeen ? null : (user.last_seen ?? null),
    status: user.status ?? '',
    avatarUrl: profile.avatar_url && resolveProfileVisibility(profile, viewerNum, 'bio', targetNum) ? profile.avatar_url : '',
    bio: resolveProfileVisibility(profile, viewerNum, 'bio', targetNum) ? (profile.bio ?? '') : '',
    pronouns: resolveProfileVisibility(profile, viewerNum, 'pronouns', targetNum) ? (profile.pronouns ?? '') : '',
    timezone: resolveProfileVisibility(profile, viewerNum, 'timezone', targetNum) ? (profile.timezone ?? '') : '',
    badges: resolveProfileVisibility(profile, viewerNum, 'badges', targetNum) ? parseJsonOr(profile.badges_json, []) : [],
  };

  if (isOwn) {
    result.privacy = {
      bio: profile.privacy_bio || 'public',
      pronouns: profile.privacy_pronouns || 'public',
      timezone: profile.privacy_timezone || 'contacts',
      badges: profile.privacy_badges || 'public',
    };
  }

  res.json(result);
});

// Get shared contact card for a user (more data than public profile, less than own)
app.get('/api/profile/:memberNumber/contact-card', authMiddleware, (req, res) => {
  const targetNum = parseInt(req.params.memberNumber, 10);
  if (!targetNum) return res.status(400).json({ error: 'Invalid member number' });
  if (targetNum === req.memberNumber) {
    // For own profile, just redirect to the full profile
    res.redirect(307, `/api/profile/${targetNum}`);
    return;
  }

  const user = db.prepare('SELECT member_name, last_seen, status, hide_last_seen FROM users WHERE member_number = ?').get(targetNum);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const profile = getProfileRow(targetNum) || {};
  const hideLastSeen = Number(user.hide_last_seen || 0) === 1;
  const hasConversation = !!db.prepare(
    'SELECT 1 FROM messages WHERE group_id IS NULL AND ((sender_number = ? AND recipient_number = ?) OR (sender_number = ? AND recipient_number = ?)) LIMIT 1'
  ).get(req.memberNumber, targetNum, targetNum, req.memberNumber);
  const isTrusted = !!db.prepare(
    'SELECT 1 FROM trusted_contacts WHERE user_number = ? AND trusted_number = ?'
  ).get(req.memberNumber, targetNum);

  res.json({
    memberNumber: targetNum,
    memberName: user.member_name,
    isOnline: clients.has(targetNum),
    lastSeen: hideLastSeen ? null : (user.last_seen ?? null),
    status: user.status ?? '',
    avatarUrl: profile.avatar_url ?? '',
    bio: profile.bio ?? '',
    pronouns: profile.pronouns ?? '',
    timezone: hasConversation ? (profile.timezone ?? '') : '',
    badges: parseJsonOr(profile.badges_json, []),
    hasConversation,
    isTrusted,
  });
});

// Update own profile (bio, pronouns, timezone, avatar, badges, privacy)
app.put('/api/profile', authMiddleware, (req, res) => {
  const body = req.body || {};
  const now = Date.now();

  const bio = String(body.bio ?? '').trim().slice(0, MAX_BIO_LENGTH);
  const pronouns = String(body.pronouns ?? '').trim().slice(0, MAX_PRONOUNS_LENGTH);
  const timezone = String(body.timezone ?? '').trim().slice(0, MAX_TIMEZONE_LENGTH);
  const avatarUrl = String(body.avatarUrl ?? '').trim().slice(0, MAX_DISCORD_WEBHOOK_LENGTH);

  let badges = [];
  if (Array.isArray(body.badges)) {
    badges = body.badges.slice(0, MAX_BADGE_COUNT).map(b => String(b ?? '').trim()).filter(Boolean);
  }

  const privacyBio = VALID_PRIVACY_LEVELS.includes(body.privacyBio) ? body.privacyBio : 'public';
  const privacyPronouns = VALID_PRIVACY_LEVELS.includes(body.privacyPronouns) ? body.privacyPronouns : 'public';
  const privacyTimezone = VALID_PRIVACY_LEVELS.includes(body.privacyTimezone) ? body.privacyTimezone : 'contacts';
  const privacyBadges = VALID_PRIVACY_LEVELS.includes(body.privacyBadges) ? body.privacyBadges : 'public';

  db.prepare(`
    INSERT INTO user_profile (member_number, bio, pronouns, timezone, avatar_url, badges_json, privacy_bio, privacy_pronouns, privacy_timezone, privacy_badges, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(member_number) DO UPDATE SET
      bio = excluded.bio,
      pronouns = excluded.pronouns,
      timezone = excluded.timezone,
      avatar_url = excluded.avatar_url,
      badges_json = excluded.badges_json,
      privacy_bio = excluded.privacy_bio,
      privacy_pronouns = excluded.privacy_pronouns,
      privacy_timezone = excluded.privacy_timezone,
      privacy_badges = excluded.privacy_badges,
      updated_at = excluded.updated_at
  `).run(req.memberNumber, bio, pronouns, timezone, avatarUrl, JSON.stringify(badges),
    privacyBio, privacyPronouns, privacyTimezone, privacyBadges, now);

  res.json({ success: true, updatedAt: now });
});

// ── E2E public key routes ──────────────────────────────────────────────────────

// Upload own public key
app.put('/api/pubkey', authMiddleware, (req, res) => {
  const key = String(req.body?.publicKey ?? '').trim();
  if (!key || key.length > 200) return res.status(400).json({ error: 'invalid_public_key' });
  db.prepare('UPDATE users SET public_key = ? WHERE member_number = ?').run(key, req.memberNumber);
  res.json({ ok: true });
});

// Fetch another user's public key (auth required — not publicly enumerable)
app.get('/api/pubkey/:memberNumber', authMiddleware, (req, res) => {
  const num = parseInt(req.params.memberNumber, 10);
  if (!Number.isFinite(num)) return res.status(400).json({ error: 'invalid' });
  const row = db.prepare('SELECT public_key FROM users WHERE member_number = ?').get(num);
  if (!row) return res.status(404).json({ error: 'not_found' });
  res.json({ publicKey: row.public_key ?? null });
});

// ── Trusted contacts routes ────────────────────────────────────────────────────

// List trusted contacts
app.get('/api/trusted', authMiddleware, (req, res) => {
  const rows = db.prepare(
    'SELECT trusted_number, added_at FROM trusted_contacts WHERE user_number = ? ORDER BY added_at DESC'
  ).all(req.memberNumber);
  res.json({ trusted: rows.map(r => ({ memberNumber: r.trusted_number, addedAt: r.added_at })) });
});

// Add a trusted contact
app.post('/api/trusted', authMiddleware, (req, res) => {
  const targetNum = parseInt(req.body?.memberNumber, 10);
  if (!targetNum || targetNum === req.memberNumber) {
    return res.status(400).json({ error: 'Invalid memberNumber' });
  }

  db.prepare(
    'INSERT OR IGNORE INTO trusted_contacts (user_number, trusted_number, added_at) VALUES (?, ?, ?)'
  ).run(req.memberNumber, targetNum, Date.now());

  res.json({ success: true });
});

// Remove a trusted contact
app.delete('/api/trusted/:memberNumber', authMiddleware, (req, res) => {
  const targetNum = parseInt(req.params.memberNumber, 10);
  if (!targetNum) return res.status(400).json({ error: 'Invalid memberNumber' });

  db.prepare(
    'DELETE FROM trusted_contacts WHERE user_number = ? AND trusted_number = ?'
  ).run(req.memberNumber, targetNum);

  res.json({ success: true });
});

// ── Conversation folders / labels routes ───────────────────────────────────────

// List all folder assignments for the user
app.get('/api/conversations/folders', authMiddleware, (req, res) => {
  const rows = db.prepare(
    'SELECT target_number, folder, label, snoozed_until FROM conversation_folders WHERE member_number = ?'
  ).all(req.memberNumber);
  res.json({
    folders: rows.map(r => ({
      targetNumber: r.target_number,
      folder: r.folder,
      label: r.label || '',
      snoozedUntil: r.snoozed_until || null,
    })),
  });
});

// Set folder/label for a conversation
app.post('/api/conversations/:targetNumber/folder', authMiddleware, (req, res) => {
  const targetNum = parseInt(req.params.targetNumber, 10);
  if (!targetNum || targetNum === req.memberNumber) {
    return res.status(400).json({ error: 'Invalid targetNumber' });
  }

  const folder = String(req.body?.folder ?? 'inbox').trim();
  const label = String(req.body?.label ?? '').trim().slice(0, MAX_LABEL_LENGTH);

  if (!['inbox', 'archive'].includes(folder)) {
    return res.status(400).json({ error: 'folder must be inbox or archive' });
  }

  db.prepare(`
    INSERT INTO conversation_folders (member_number, target_number, folder, label)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(member_number, target_number) DO UPDATE SET
      folder = excluded.folder,
      label = excluded.label
  `).run(req.memberNumber, targetNum, folder, label);

  res.json({ success: true, targetNumber: targetNum, folder, label });
});

// Snooze a conversation
app.post('/api/conversations/:targetNumber/snooze', authMiddleware, (req, res) => {
  const targetNum = parseInt(req.params.targetNumber, 10);
  if (!targetNum || targetNum === req.memberNumber) {
    return res.status(400).json({ error: 'Invalid targetNumber' });
  }

  const durationMs = Math.max(0, parseInt(req.body?.durationMs, 10) || 0);
  const snoozedUntil = durationMs > 0 ? Date.now() + durationMs : null;

  db.prepare(`
    INSERT INTO conversation_folders (member_number, target_number, folder, snoozed_until)
    VALUES (?, ?, 'inbox', ?)
    ON CONFLICT(member_number, target_number) DO UPDATE SET
      snoozed_until = excluded.snoozed_until
  `).run(req.memberNumber, targetNum, snoozedUntil);

  res.json({ success: true, targetNumber: targetNum, snoozedUntil });
});

// ── Message request routes ─────────────────────────────────────────────────────

// Get pending message requests
app.get('/api/message-requests', authMiddleware, (req, res) => {
  const rows = db.prepare(
    'SELECT id, sender_number, content, sent_at, status FROM message_requests WHERE recipient_number = ? AND status = ? ORDER BY sent_at DESC'
  ).all(req.memberNumber, 'pending');
  res.json({ requests: rows });
});

// Accept a message request (moves to DMs)
app.post('/api/message-requests/:id/accept', authMiddleware, (req, res) => {
  const requestId = parseInt(req.params.id, 10);
  if (!requestId) return res.status(400).json({ error: 'Invalid request ID' });

  const mr = db.prepare(
    'SELECT * FROM message_requests WHERE id = ? AND recipient_number = ? AND status = ?'
  ).get(requestId, req.memberNumber, 'pending');
  if (!mr) return res.status(404).json({ error: 'Message request not found' });

  const now = Date.now();
  db.prepare('UPDATE message_requests SET status = ?, reviewed_at = ? WHERE id = ?').run('accepted', now, requestId);

  // Create the actual DM message
  const result = db.prepare(
    'INSERT INTO messages (sender_number, sender_name, recipient_number, content, sent_at, delivered) VALUES (?, ?, ?, ?, ?, 0)'
  ).run(mr.sender_number, `Member #${mr.sender_number}`, mr.recipient_number, mr.content, mr.sent_at);

  res.json({ success: true, messageId: result.lastInsertRowid });
});

// Decline a message request
app.post('/api/message-requests/:id/decline', authMiddleware, (req, res) => {
  const requestId = parseInt(req.params.id, 10);
  if (!requestId) return res.status(400).json({ error: 'Invalid request ID' });

  const mr = db.prepare(
    'SELECT * FROM message_requests WHERE id = ? AND recipient_number = ? AND status = ?'
  ).get(requestId, req.memberNumber, 'pending');
  if (!mr) return res.status(404).json({ error: 'Message request not found' });

  const now = Date.now();
  db.prepare('UPDATE message_requests SET status = ?, reviewed_at = ? WHERE id = ?').run('declined', now, requestId);

  res.json({ success: true });
});

// ── Message collections routes ──────────────────────────────────────────────────

// List user's collections (with counts)
app.get('/api/collections', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT collection_name, COUNT(*) AS count, MIN(added_at) AS created_at
    FROM message_collections
    WHERE member_number = ?
    GROUP BY collection_name
    ORDER BY created_at DESC
  `).all(req.memberNumber);
  res.json({ collections: rows.map(r => ({ name: r.collection_name, count: r.count })) });
});

// Get messages in a collection
app.get('/api/collections/:name', authMiddleware, (req, res) => {
  const name = String(req.params.name).trim();
  if (!name) return res.status(400).json({ error: 'Collection name required' });

  const rows = db.prepare(`
    SELECT message_ref, added_at
    FROM message_collections
    WHERE member_number = ? AND collection_name = ?
    ORDER BY added_at DESC
  `).all(req.memberNumber, name);
  res.json({ messages: rows.map(r => ({ messageRef: r.message_ref, addedAt: r.added_at })) });
});

// Add message to a collection
app.post('/api/collections', authMiddleware, (req, res) => {
  const resolved = resolveMessageReference(req.body?.messageRef, req.memberNumber);
  if (!resolved?.messageRef) {
    return res.status(400).json({ error: 'Invalid or inaccessible messageRef' });
  }

  const collectionName = String(req.body?.collectionName ?? 'default').trim();
  if (!collectionName) return res.status(400).json({ error: 'Collection name required' });

  db.prepare(`
    INSERT OR IGNORE INTO message_collections (member_number, message_ref, collection_name, added_at)
    VALUES (?, ?, ?, ?)
  `).run(req.memberNumber, resolved.messageRef, collectionName, Date.now());

  res.json({ success: true, messageRef: resolved.messageRef, collectionName });
});

// Remove message from a collection
app.delete('/api/collections/:name/messages/:encodedMessageRef', authMiddleware, (req, res) => {
  const collectionName = String(req.params.name).trim();
  const messageRef = decodeURIComponent(req.params.encodedMessageRef);

  if (!collectionName || !messageRef) {
    return res.status(400).json({ error: 'Collection name and messageRef required' });
  }

  db.prepare(`
    DELETE FROM message_collections
    WHERE member_number = ? AND collection_name = ? AND message_ref = ?
  `).run(req.memberNumber, collectionName, messageRef);

  res.json({ success: true });
});

// ── Poll routes ────────────────────────────────────────────────────────────────

// Create a poll attached to a message
app.post('/api/polls', authMiddleware, (req, res) => {
  const resolved = resolveMessageReference(req.body?.messageRef, req.memberNumber);
  if (!resolved?.messageRef) return res.status(400).json({ error: 'Invalid or inaccessible messageRef' });

  const question = String(req.body?.question ?? '').trim();
  const options = Array.isArray(req.body?.options) ? req.body.options.map(o => String(o ?? '').trim()).filter(Boolean) : [];
  if (!question || options.length < 2 || options.length > 10) {
    return res.status(400).json({ error: 'Question and 2-10 options required' });
  }

  const now = Date.now();
  const durationMinutes = Math.max(0, Math.min(10080, parseInt(req.body?.durationMinutes, 10) || 0)); // max 7 days
  const closesAt = durationMinutes > 0 ? now + durationMinutes * 60 * 1000 : null;

  db.prepare(`
    INSERT OR REPLACE INTO message_polls (message_ref, question, options_json, created_by, created_at, closes_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(resolved.messageRef, question, JSON.stringify(options), req.memberNumber, now, closesAt);

  // Push poll info to all participants
  const payload = {
    type: 'poll_created',
    messageRef: resolved.messageRef,
    question,
    options,
    createdBy: req.memberNumber,
    closesAt,
  };
  for (const participant of new Set(resolved.participants || [])) {
    const ws = clients.get(participant);
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload));
  }

  res.json({ success: true, messageRef: resolved.messageRef, question, options });
});

// Vote on a poll option
app.post('/api/polls/:encodedMessageRef/vote', authMiddleware, (req, res) => {
  const messageRef = decodeURIComponent(req.params.encodedMessageRef);
  const optionIndex = parseInt(req.body?.optionIndex, 10);

  const poll = db.prepare('SELECT * FROM message_polls WHERE message_ref = ?').get(messageRef);
  if (!poll) return res.status(404).json({ error: 'Poll not found' });

  if (poll.closes_at && poll.closes_at < Date.now()) {
    return res.status(400).json({ error: 'Poll has closed' });
  }

  const options = parseJsonOr(poll.options_json, []);
  if (!Number.isFinite(optionIndex) || optionIndex < 0 || optionIndex >= options.length) {
    return res.status(400).json({ error: 'Invalid option index' });
  }

  // Verify voter is a participant
  const resolved = resolveMessageReference(messageRef, req.memberNumber);
  if (!resolved) return res.status(403).json({ error: 'Not a participant' });

  const now = Date.now();
  db.prepare(`
    INSERT OR REPLACE INTO poll_votes (message_ref, member_number, option_index, voted_at)
    VALUES (?, ?, ?, ?)
  `).run(messageRef, req.memberNumber, optionIndex, now);

  // Compute updated results
  const votes = db.prepare(
    'SELECT option_index, COUNT(*) AS c FROM poll_votes WHERE message_ref = ? GROUP BY option_index'
  ).all(messageRef);
  const results = options.map((opt, i) => {
    const row = votes.find(v => v.option_index === i);
    return { option: opt, count: row ? row.c : 0 };
  });

  const payload = {
    type: 'poll_vote_updated',
    messageRef,
    results,
  };
  for (const participant of new Set(resolved.participants || [])) {
    const ws = clients.get(participant);
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload));
  }

  res.json({ success: true, messageRef, results });
});

// Get poll data
app.get('/api/polls/:encodedMessageRef', authMiddleware, (req, res) => {
  const messageRef = decodeURIComponent(req.params.encodedMessageRef);

  const poll = db.prepare('SELECT * FROM message_polls WHERE message_ref = ?').get(messageRef);
  if (!poll) return res.status(404).json({ error: 'Poll not found' });

  const options = parseJsonOr(poll.options_json, []);
  const votes = db.prepare(
    'SELECT option_index, COUNT(*) AS c FROM poll_votes WHERE message_ref = ? GROUP BY option_index'
  ).all(messageRef);
  const results = options.map((opt, i) => {
    const row = votes.find(v => v.option_index === i);
    return { option: opt, count: row ? row.c : 0 };
  });

  const myVote = db.prepare(
    'SELECT option_index FROM poll_votes WHERE message_ref = ? AND member_number = ?'
  ).get(messageRef, req.memberNumber);

  res.json({
    question: poll.question,
    options,
    results,
    myVote: myVote ? myVote.option_index : null,
    createdBy: poll.created_by,
    totalVotes: results.reduce((s, r) => s + r.count, 0),
    closesAt: poll.closes_at || null,
  });
});

// ── WebSocket ─────────────────────────────────────────────────────────────────

wss.on('connection', (ws) => {
  let memberNumber = null;

  ws.on('message', (raw) => {
    try {
    let msg;
    try { msg = JSON.parse(raw); } catch {
      try { ws.send(JSON.stringify({ type: 'error', message: 'Invalid JSON' })); } catch {}
      return;
    }

    if (msg.type === 'auth') {
      const { memberNumber: mn, clientSecret } = msg;
      const num  = parseInt(mn, 10);
      const user = db.prepare('SELECT * FROM users WHERE member_number = ?').get(num);

      if (!user || user.auth_token !== hashSecret(clientSecret)) {
        ws.send(JSON.stringify({ type: 'auth_error', message: 'Invalid credentials' }));
        return ws.close();
      }

      memberNumber = num;
      clients.set(memberNumber, ws);

      db.prepare('UPDATE users SET last_seen = ? WHERE member_number = ?').run(Date.now(), memberNumber);

      ws.send(JSON.stringify({ type: 'auth_ok', memberNumber }));

      // Deliver any pending DM and group messages
      const pending = db.prepare(`
        SELECT *
        FROM messages
        WHERE recipient_number = ?
          AND delivered = 0
          AND (
            group_id IS NOT NULL
            OR NOT EXISTS (
              SELECT 1
              FROM blocks
              WHERE blocker_number = ?
                AND blocked_number = messages.sender_number
            )
          )
        ORDER BY sent_at ASC
      `).all(memberNumber, memberNumber);

      if (pending.length > 0) {
        // Separate DMs from group messages
        const dmMessages = pending.filter(m => !m.group_id);
        const groupMessages = pending.filter(m => m.group_id);

        if (dmMessages.length > 0) {
          ws.send(JSON.stringify({ type: 'pending', messages: dmMessages }));
        }

        if (groupMessages.length > 0) {
          ws.send(JSON.stringify({ type: 'pending_group', messages: groupMessages }));
        }

        const ids = pending.map(m => m.id);
        const placeholders = ids.map(() => '?').join(',');
        db.prepare(`UPDATE messages SET delivered = 1 WHERE id IN (${placeholders})`).run(...ids);

        // Notify each sender (if online) that their message was delivered
        for (const m of pending) {
          const senderWs = clients.get(m.sender_number);
          if (senderWs && senderWs.readyState === WebSocket.OPEN) {
            if (m.group_id && m.group_message_ref) {
              pushGroupReceiptUpdateToSender(m.sender_number, m.group_message_ref);
            } else {
              senderWs.send(JSON.stringify({ type: 'message_delivered', id: m.id }));
            }
          }
        }
      }

      // Send user's group list
      const groups = db.prepare(`
        SELECT g.id, g.name, g.created_by, g.created_at, g.avatar_color
        FROM groups g
        INNER JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.member_number = ?
      `).all(memberNumber);

      if (groups.length > 0) {
        const groupsWithMembers = groups.map(g => {
          const members = db.prepare(
            'SELECT member_number, role FROM group_members WHERE group_id = ?'
          ).all(g.id);
          return { ...g, members };
        });
        ws.send(JSON.stringify({ type: 'groups_list', groups: groupsWithMembers }));
      }
    }

    // Recipient marks messages as read; notify original senders
    if (msg.type === 'read' && memberNumber) {
      const ids = (msg.messageIds ?? []).filter(n => Number.isInteger(n));
      if (!ids.length) return;
      const now = Date.now();
      const getRow  = db.prepare('SELECT sender_number, group_id, group_message_ref FROM messages WHERE id = ? AND recipient_number = ?');
      const markRead = db.prepare('UPDATE messages SET read_at = ? WHERE id = ? AND recipient_number = ? AND read_at = 0');
      for (const id of ids) {
        const row = getRow.get(id, memberNumber);
        if (!row) continue;
        const result = markRead.run(now, id, memberNumber);
        if (!result?.changes) continue;
        if (row.group_id && row.group_message_ref) {
          pushGroupReceiptUpdateToSender(row.sender_number, row.group_message_ref);
        } else {
          const senderWs = clients.get(row.sender_number);
          if (senderWs && senderWs.readyState === WebSocket.OPEN) {
            senderWs.send(JSON.stringify({ type: 'message_read', id, readAt: now }));
          }
        }
      }
    }

    if (msg.type === 'edit' && memberNumber) {
      const id = parseInt(msg.id, 10);
      const newContent = String(msg.newContent ?? '').trim();
      if (!id || !newContent || newContent.length > MAX_MESSAGE_LENGTH) return;
      const row = db.prepare('SELECT id, sender_number, recipient_number, content FROM messages WHERE id = ?').get(id);
      if (!row || row.sender_number !== memberNumber) return;

      // Save revision before overwriting (rotate: prune oldest when cap is reached)
      const revCount = db.prepare('SELECT COUNT(*) AS c FROM message_revisions WHERE message_id = ?').get(id)?.c ?? 0;
      if (revCount >= MAX_REVISIONS_PER_MESSAGE) {
        const oldest = db.prepare(
          'SELECT id FROM message_revisions WHERE message_id = ? ORDER BY revised_at ASC LIMIT 1'
        ).get(id);
        if (oldest) db.prepare('DELETE FROM message_revisions WHERE id = ?').run(oldest.id);
      }
      db.prepare(
        'INSERT INTO message_revisions (message_id, content, revised_at, revised_by) VALUES (?, ?, ?, ?)'
      ).run(id, row.content, Date.now(), memberNumber);

      db.prepare('UPDATE messages SET content = ?, edited = 1 WHERE id = ?').run(newContent, id);
      const recipientWs = clients.get(row.recipient_number);
      if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
        recipientWs.send(JSON.stringify({ type: 'message_edited', id, content: newContent }));
      }
      ws.send(JSON.stringify({ type: 'message_edited', id, content: newContent }));
    }

    if (msg.type === 'delete' && memberNumber) {
      const id = parseInt(msg.id, 10);
      if (!id) return;
      const row = db.prepare('SELECT id, sender_number, recipient_number FROM messages WHERE id = ?').get(id);
      if (!row || row.sender_number !== memberNumber) return;
      db.prepare('UPDATE messages SET content = ?, deleted = 1, deleted_at = ? WHERE id = ?').run('', Date.now(), id);
      const recipientWs = clients.get(row.recipient_number);
      if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
        recipientWs.send(JSON.stringify({ type: 'message_deleted', id }));
      }
      ws.send(JSON.stringify({ type: 'message_deleted', id }));
    }

    // Client acknowledges its sync cursor after reconnect
    if (msg.type === 'sync_ack' && memberNumber) {
      const cursorAt = parseInt(msg.cursorAt, 10);
      if (Number.isFinite(cursorAt) && cursorAt > 0) {
        advanceSyncCursor(memberNumber, cursorAt);
      }
    }

    if (msg.type === 'typing' && memberNumber) {
      const groupId = parseInt(msg.groupId, 10);
      if (!groupId) return;
      const membership = db.prepare(
        'SELECT 1 FROM group_members WHERE group_id = ? AND member_number = ?'
      ).get(groupId, memberNumber);
      if (!membership) return;

      const now = Date.now();
      const throttleKey = `${memberNumber}:${groupId}`;
      const prevSentAt = groupTypingSentAt.get(throttleKey) || 0;
      if (now - prevSentAt < GROUP_TYPING_THROTTLE_MS) return;
      groupTypingSentAt.set(throttleKey, now);

      const senderName = db.prepare('SELECT member_name FROM users WHERE member_number = ?').get(memberNumber)?.member_name || `Member #${memberNumber}`;
      const members = db.prepare('SELECT member_number FROM group_members WHERE group_id = ?').all(groupId);
      for (const m of members) {
        if (m.member_number === memberNumber) continue;
        const recipientWs = clients.get(m.member_number);
        if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
          recipientWs.send(JSON.stringify({
            type: 'group_typing',
            groupId,
            senderNumber: memberNumber,
            senderName,
          }));
        }
      }
    }
    } catch (err) {
      console.error('[BCM] Unhandled error in WS message handler:', err);
    }
  });

  ws.on('close', () => {
    if (memberNumber !== null) {
      clients.delete(memberNumber);
      db.prepare('UPDATE users SET last_seen = ? WHERE member_number = ?').run(Date.now(), memberNumber);
    }
  });
});

// ── Link Preview ──────────────────────────────────────────────────────────────

app.get('/api/link-preview', authMiddleware, async (req, res) => {
  const { url } = req.query;
  if (!url || !/^https?:\/\//i.test(url)) return res.status(400).json({ error: 'Invalid URL' });
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; BCMBot/1.0)', 'Accept': 'text/html,*/*' },
      redirect: 'follow',
    });
    clearTimeout(tid);
    if (!resp.ok) return res.json({ url, title: '', description: '', image: '', domain: new URL(url).hostname });
    const ct = resp.headers.get('content-type') || '';
    if (!ct.includes('text/html')) return res.json({ url, title: '', description: '', image: '', domain: new URL(url).hostname });
    const html = await resp.text();
    const getOG = prop => {
      const m = html.match(new RegExp(`<meta[^>]+(?:property|name)=["']og:${prop}["'][^>]+content=["']([^"']+)["']`, 'i'))
              || html.match(new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["']og:${prop}["']`, 'i'));
      return m ? m[1].replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&#39;/g,"'").trim() : '';
    };
    const titleM = html.match(/<title[^>]*>([^<]*)<\/title>/i);
    const title = getOG('title') || (titleM ? titleM[1].trim() : '') || new URL(url).hostname;
    const description = getOG('description')
      || (html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i) || [])[1]
      || '';
    const image = getOG('image') || '';
    const domain = new URL(url).hostname.replace(/^www\./, '');
    res.json({ url, title: title.slice(0,120), description: description.slice(0,280), image: image.slice(0,500), domain });
  } catch {
    try { res.json({ url, title: '', description: '', image: '', domain: new URL(url).hostname }); }
    catch { res.json({ url, title: '', description: '', image: '', domain: '' }); }
  }
});

// ── Global error guards (prevent server crash on unhandled throws) ────────────

process.on('uncaughtException', (err) => {
  console.error('[BCM] Uncaught exception (server kept alive):', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[BCM] Unhandled promise rejection (server kept alive):', reason);
});

// Express catch-all error handler (must be registered after all routes)
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[BCM] Unhandled route error:', err);
  if (!res.headersSent) res.status(500).json({ error: 'Internal server error' });
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────

function shutdown() {
  db.prepare('UPDATE users SET last_seen = ?').run(Date.now());
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// ── Start ─────────────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`BC Offline Messenger server listening on port ${PORT}`);
});
