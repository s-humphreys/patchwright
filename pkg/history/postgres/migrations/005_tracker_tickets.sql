-- Tickets as the tracker dates them, closed ones included, so cycle time can be
-- measured and ticketed work reported for periods before the record began. Keyed by
-- issue key and rewritten on every sync; the tracker is the source of truth for
-- every column but the item match, which is patchwright's best effort by image.
CREATE TABLE IF NOT EXISTS tickets (
    key             TEXT PRIMARY KEY,
    project         TEXT NOT NULL,
    item_key        TEXT,
    -- When the matched item's span opened, held here so the interval from finding
    -- to ticket survives the item row being pruned.
    item_opened_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL,
    -- First move into an in-progress status, and how that was found.
    started_at      TIMESTAMPTZ,
    started_from    TEXT NOT NULL DEFAULT '',
    resolved_at     TIMESTAMPTZ,
    due_at          TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT '',
    status_category TEXT NOT NULL DEFAULT '',
    last_seen_at    TIMESTAMPTZ NOT NULL,
    raw             JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS tickets_created_at ON tickets (created_at);
CREATE INDEX IF NOT EXISTS tickets_resolved_at ON tickets (resolved_at);
CREATE INDEX IF NOT EXISTS tickets_item_key ON tickets (item_key) WHERE item_key IS NOT NULL;
