-- What the assessment worker is doing, for a deployment that splits the worker from
-- the replicas serving the page. One row: the worker writes its heartbeat, whether it
-- is running and how its last run ended; the web replicas write only the time an
-- assessment was last asked for, which the worker picks up.
CREATE TABLE IF NOT EXISTS worker_state (
    id                   SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    heartbeat_at         TIMESTAMPTZ,
    version              TEXT NOT NULL DEFAULT '',
    running              BOOLEAN NOT NULL DEFAULT false,
    started_at           TIMESTAMPTZ,
    last_error           TEXT NOT NULL DEFAULT '',
    refresh_requested_at TIMESTAMPTZ,
    refresh_handled_at   TIMESTAMPTZ,
    history_recorded_at  TIMESTAMPTZ,
    history_error        TEXT NOT NULL DEFAULT ''
);
