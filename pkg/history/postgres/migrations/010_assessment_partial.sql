-- Whether an assessment read every source. A decommission is credited only when
-- every run in its window did, since a cluster nobody read looks exactly like a
-- cluster where nothing runs. Runs recorded before this column are read from the
-- source failures their stored summary already lists.
ALTER TABLE assessments
    ADD COLUMN IF NOT EXISTS partial BOOLEAN NOT NULL DEFAULT false;
UPDATE assessments SET partial = true
    WHERE jsonb_typeof(summary->'source_failures') = 'array'
      AND jsonb_array_length(summary->'source_failures') > 0;
