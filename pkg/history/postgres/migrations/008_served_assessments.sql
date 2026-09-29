-- The assessment the server last served, so a restarted process can serve it at
-- once instead of answering 503 until a fresh run completes. The payload is opaque
-- to the database: gzipped JSON the server writes and reads, labelled with the
-- build and the payload schema that wrote it. Only the newest few rows are kept.
CREATE TABLE IF NOT EXISTS served_assessments (
    id             BIGSERIAL PRIMARY KEY,
    generated_at   TIMESTAMPTZ NOT NULL,
    version        TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    payload        BYTEA NOT NULL,
    stored_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS served_assessments_generated_at ON served_assessments (generated_at DESC, id DESC);
