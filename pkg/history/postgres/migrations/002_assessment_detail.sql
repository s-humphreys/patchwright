-- More on the assessment row, so aggregate questions nobody has asked yet can be
-- answered from the day the record began rather than from the day they were asked.
--   counts, actionable_counts: severity totals over the estate
--   summary: the server's headline summary for the run, as given
--   snapshot: the full work-item list for the run, read one run at a time
ALTER TABLE assessments
    ADD COLUMN IF NOT EXISTS counts             JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS actionable_counts  JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS distinct_cves      INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS distinct_kev       INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS distinct_epss_high INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS summary            JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS snapshot           JSONB;
