-- The grace period: an open item absent from an assessment is counted, not lapsed,
-- until it has been missing for the configured number of consecutive runs.
ALTER TABLE items
    ADD COLUMN IF NOT EXISTS missing_runs  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS missing_since TIMESTAMPTZ;
