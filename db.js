const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'messages.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    member_number INTEGER PRIMARY KEY,
    member_name   TEXT    NOT NULL,
    auth_token    TEXT    NOT NULL,
    last_seen     INTEGER NOT NULL DEFAULT 0,
    status        TEXT    NOT NULL DEFAULT '',
    discord_webhook TEXT  NOT NULL DEFAULT '',
    hide_last_seen INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS messages (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_number    INTEGER NOT NULL,
    sender_name      TEXT    NOT NULL,
    recipient_number INTEGER,
    content          TEXT    NOT NULL,
    sent_at          INTEGER NOT NULL,
    delivered        INTEGER NOT NULL DEFAULT 0,
    deleted          INTEGER NOT NULL DEFAULT 0
  );

  CREATE INDEX IF NOT EXISTS idx_messages_pending
    ON messages(recipient_number, delivered);

  CREATE TABLE IF NOT EXISTS groups (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    created_by   INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    avatar_color TEXT
  );

  CREATE TABLE IF NOT EXISTS group_members (
    group_id      INTEGER NOT NULL,
    member_number INTEGER NOT NULL,
    joined_at     INTEGER NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'member',
    PRIMARY KEY (group_id, member_number),
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_group_members_member
    ON group_members(member_number);
`);

// Safe migrations for existing databases
try { db.exec('ALTER TABLE messages ADD COLUMN read_at INTEGER NOT NULL DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE messages ADD COLUMN group_id INTEGER'); } catch {}
try { db.exec('ALTER TABLE messages ADD COLUMN message_type TEXT NOT NULL DEFAULT "dm"'); } catch {}
try { db.exec('ALTER TABLE messages ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT ""'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN discord_webhook TEXT NOT NULL DEFAULT ""'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN hide_last_seen INTEGER NOT NULL DEFAULT 0'); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_messages_group ON messages(group_id)'); } catch {}

// ── vNext schema additions ────────────────────────────────────────────────────

// Edit history: one row per revision, bounded per message
db.exec(`
  CREATE TABLE IF NOT EXISTS message_revisions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id  INTEGER NOT NULL,
    content     TEXT    NOT NULL,
    revised_at  INTEGER NOT NULL,
    revised_by  INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_revisions_msg ON message_revisions(message_id);
`);

// Block list: blocker cannot receive messages/DMs from blocked member
db.exec(`
  CREATE TABLE IF NOT EXISTS blocks (
    blocker_number INTEGER NOT NULL,
    blocked_number INTEGER NOT NULL,
    blocked_at     INTEGER NOT NULL,
    PRIMARY KEY (blocker_number, blocked_number)
  );
  CREATE INDEX IF NOT EXISTS idx_blocks_blocker ON blocks(blocker_number);
  CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks(blocked_number);
`);

// Abuse reports
db.exec(`
  CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_number INTEGER NOT NULL,
    target_number   INTEGER NOT NULL,
    message_id      INTEGER,
    reason          TEXT    NOT NULL DEFAULT '',
    reported_at     INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_reports_reporter ON reports(reporter_number);
  CREATE INDEX IF NOT EXISTS idx_reports_target   ON reports(target_number);
`);

// Per-member sync cursor: tracks the last message sent_at successfully delivered
// so clients can resume without duplication after reconnect
db.exec(`
  CREATE TABLE IF NOT EXISTS sync_cursors (
    member_number INTEGER PRIMARY KEY,
    cursor_at     INTEGER NOT NULL DEFAULT 0
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS message_reactions (
    message_ref TEXT PRIMARY KEY,
    emoji       TEXT    NOT NULL,
    set_by      INTEGER NOT NULL,
    reacted_at  INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS starred_messages (
    member_number INTEGER NOT NULL,
    message_ref   TEXT    NOT NULL,
    starred_at    INTEGER NOT NULL,
    PRIMARY KEY (member_number, message_ref)
  );
  CREATE INDEX IF NOT EXISTS idx_starred_messages_member
    ON starred_messages(member_number, starred_at DESC);
  CREATE TABLE IF NOT EXISTS user_state (
    member_number      INTEGER PRIMARY KEY,
    notes_json         TEXT    NOT NULL DEFAULT '{}',
    pinned_json        TEXT    NOT NULL DEFAULT '[]',
    muted_json         TEXT    NOT NULL DEFAULT '[]',
    disappearing_json  TEXT    NOT NULL DEFAULT '{}',
    updated_at         INTEGER NOT NULL DEFAULT 0
  );
`);

// Soft-delete metadata: store deleted_at timestamp
try { db.exec('ALTER TABLE messages ADD COLUMN deleted_at INTEGER'); } catch {}
// Mention targets: JSON array of member numbers mentioned in this message
try { db.exec('ALTER TABLE messages ADD COLUMN mention_targets TEXT'); } catch {}
// edited flag so clients can display "(edited)"
try { db.exec('ALTER TABLE messages ADD COLUMN edited INTEGER NOT NULL DEFAULT 0'); } catch {}
// Group-message logical key: shared across per-recipient fanout rows for receipt/read aggregation
try { db.exec('ALTER TABLE messages ADD COLUMN group_message_ref TEXT'); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_messages_group_ref ON messages(group_message_ref)'); } catch {}

// ── Rich user profiles ────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS user_profile (
    member_number       INTEGER PRIMARY KEY,
    bio                 TEXT    NOT NULL DEFAULT '',
    pronouns            TEXT    NOT NULL DEFAULT '',
    timezone            TEXT    NOT NULL DEFAULT '',
    avatar_url          TEXT    NOT NULL DEFAULT '',
    badge                 TEXT    NOT NULL DEFAULT '',
    badges_json         TEXT    NOT NULL DEFAULT '[]',
    privacy_bio         TEXT    NOT NULL DEFAULT 'public',
    privacy_pronouns    TEXT    NOT NULL DEFAULT 'public',
    privacy_timezone    TEXT    NOT NULL DEFAULT 'contacts',
    privacy_badges      TEXT    NOT NULL DEFAULT 'public',
    updated_at          INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (member_number) REFERENCES users(member_number) ON DELETE CASCADE
  );
`);

// Migrations for existing databases
try { db.exec('ALTER TABLE user_profile ADD COLUMN bio TEXT NOT NULL DEFAULT \'\''); } catch {}
try { db.exec('ALTER TABLE user_profile ADD COLUMN pronouns TEXT NOT NULL DEFAULT \'\''); } catch {}
try { db.exec('ALTER TABLE user_profile ADD COLUMN timezone TEXT NOT NULL DEFAULT \'\''); } catch {}
try { db.exec('ALTER TABLE user_profile ADD COLUMN avatar_url TEXT NOT NULL DEFAULT \'\''); } catch {}
try { db.exec('ALTER TABLE user_profile ADD COLUMN badges_json TEXT NOT NULL DEFAULT \'[]\''); } catch {}
try { db.exec('ALTER TABLE user_profile ADD COLUMN privacy_bio TEXT NOT NULL DEFAULT \'public\''); } catch {}
try { db.exec('ALTER TABLE user_profile ADD COLUMN privacy_pronouns TEXT NOT NULL DEFAULT \'public\''); } catch {}
try { db.exec('ALTER TABLE user_profile ADD COLUMN privacy_timezone TEXT NOT NULL DEFAULT \'contacts\''); } catch {}
try { db.exec('ALTER TABLE user_profile ADD COLUMN privacy_badges TEXT NOT NULL DEFAULT \'public\''); } catch {}
try { db.exec('ALTER TABLE user_profile ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0'); } catch {}

// notify_overrides_json for per-contact notification rules
try { db.exec('ALTER TABLE user_state ADD COLUMN notify_overrides_json TEXT NOT NULL DEFAULT \'{}\''); } catch {}

// trusted_contacts: per-user list of trusted members
db.exec(`
  CREATE TABLE IF NOT EXISTS trusted_contacts (
    user_number   INTEGER NOT NULL,
    trusted_number INTEGER NOT NULL,
    added_at      INTEGER NOT NULL,
    PRIMARY KEY (user_number, trusted_number),
    FOREIGN KEY (user_number) REFERENCES users(member_number) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_trusted_user ON trusted_contacts(user_number);
`);

// inbox folders / labels for conversation organization
db.exec(`
  CREATE TABLE IF NOT EXISTS conversation_folders (
    member_number  INTEGER NOT NULL,
    target_number  INTEGER NOT NULL,
    folder         TEXT    NOT NULL DEFAULT 'inbox',
    snoozed_until  INTEGER,
    label          TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (member_number, target_number),
    FOREIGN KEY (member_number) REFERENCES users(member_number) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_conv_folders_member ON conversation_folders(member_number);
`);

// Group invite permissions: per-group controls for who can invite / mention first
try { db.exec('ALTER TABLE groups ADD COLUMN invite_policy TEXT DEFAULT \'admin\''); } catch {}

// Message request table for unknown users DMing
db.exec(`
  CREATE TABLE IF NOT EXISTS message_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_number   INTEGER NOT NULL,
    recipient_number INTEGER NOT NULL,
    content         TEXT    NOT NULL,
    sent_at         INTEGER NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'pending',
    reviewed_at     INTEGER,
    FOREIGN KEY (recipient_number) REFERENCES users(member_number) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_msg_requests_recipient ON message_requests(recipient_number, status);
`);

// moderation_reports status tracking
try { db.exec('ALTER TABLE reports ADD COLUMN status TEXT NOT NULL DEFAULT \'submitted\''); } catch {}
try { db.exec('ALTER TABLE reports ADD COLUMN reviewed_at INTEGER'); } catch {}
try { db.exec('ALTER TABLE reports ADD COLUMN resolution TEXT'); } catch {}

// message collections (categorized bookmarks)
db.exec(`
  CREATE TABLE IF NOT EXISTS message_collections (
    member_number   INTEGER NOT NULL,
    message_ref     TEXT    NOT NULL,
    collection_name TEXT    NOT NULL DEFAULT 'default',
    added_at        INTEGER NOT NULL,
    PRIMARY KEY (member_number, message_ref, collection_name),
    FOREIGN KEY (member_number) REFERENCES users(member_number) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_coll_member ON message_collections(member_number, collection_name);
`);

// Availability and DND columns
try { db.exec('ALTER TABLE users ADD COLUMN availability TEXT NOT NULL DEFAULT \'online\''); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN dnd_start TEXT'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN dnd_end TEXT'); } catch {}

// parent_message_ref for reply threading
try { db.exec('ALTER TABLE messages ADD COLUMN parent_message_ref TEXT'); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_msg_parent_ref ON messages(parent_message_ref)'); } catch {}

// Polls: per-message poll definition and per-member votes
db.exec(`
  CREATE TABLE IF NOT EXISTS message_polls (
    message_ref  TEXT PRIMARY KEY,
    question     TEXT    NOT NULL DEFAULT '',
    options_json TEXT    NOT NULL DEFAULT '[]',
    created_by   INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    closes_at    INTEGER
  );
  CREATE TABLE IF NOT EXISTS poll_votes (
    message_ref   TEXT    NOT NULL,
    member_number INTEGER NOT NULL,
    option_index  INTEGER NOT NULL,
    voted_at      INTEGER NOT NULL,
    PRIMARY KEY (message_ref, member_number)
  );
  CREATE INDEX IF NOT EXISTS idx_poll_votes_ref ON poll_votes(message_ref);
`);

// poll closes_at migration
try { db.exec('ALTER TABLE message_polls ADD COLUMN closes_at INTEGER'); } catch {}

module.exports = db;
