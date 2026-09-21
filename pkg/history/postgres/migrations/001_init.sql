-- The record of movement. Small on purpose: an assessment row per run, an item row
-- per open-to-close span of a work item, and an append-only event per transition.
-- Everything a report needs is a query over events by time.

CREATE TABLE IF NOT EXISTS assessments (
    id          BIGSERIAL PRIMARY KEY,
    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    findings    INTEGER NOT NULL,
    actionable  INTEGER NOT NULL,
    items       INTEGER NOT NULL,
    -- RiskStats for the estate, and the same per class and per team.
    risk        JSONB NOT NULL,
    by_class    JSONB NOT NULL DEFAULT '{}'::jsonb,
    by_team     JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS assessments_finished_at ON assessments (finished_at);

CREATE TABLE IF NOT EXISTS items (
    id          BIGSERIAL PRIMARY KEY,
    key         TEXT NOT NULL,
    repository  TEXT NOT NULL,
    class       TEXT NOT NULL,
    team        TEXT NOT NULL,
    target      TEXT NOT NULL DEFAULT '',
    opened_at   TIMESTAMPTZ NOT NULL,
    closed_at   TIMESTAMPTZ,
    closed_kind TEXT,
    -- How the item looked when it opened, which is what a resolution is classified
    -- by, and its latest snapshot.
    opened      JSONB NOT NULL,
    current     JSONB NOT NULL
);
-- One open span per key at a time. A key that closes and recurs is a new row.
CREATE UNIQUE INDEX IF NOT EXISTS items_open_key ON items (key) WHERE closed_at IS NULL;
CREATE INDEX IF NOT EXISTS items_key ON items (key);
CREATE INDEX IF NOT EXISTS items_closed_at ON items (closed_at);

CREATE TABLE IF NOT EXISTS events (
    id            BIGSERIAL PRIMARY KEY,
    item_id       BIGINT NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    assessment_id BIGINT REFERENCES assessments (id) ON DELETE SET NULL,
    kind          TEXT NOT NULL,
    at            TIMESTAMPTZ NOT NULL,
    payload       JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_at ON events (at);
CREATE INDEX IF NOT EXISTS events_item_id ON events (item_id);
-- A replayed run inserts nothing twice: the same item, kind and assessment (and
-- ticket, for ticket events) is one event.
CREATE UNIQUE INDEX IF NOT EXISTS events_once
    ON events (item_id, kind, assessment_id, (COALESCE(payload->>'ticket', '')))
    WHERE assessment_id IS NOT NULL;
