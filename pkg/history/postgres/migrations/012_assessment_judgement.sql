-- What a decommission must see unchanged and complete across its window: the live
-- source's configured clusters, and whether the run could judge decommissions at all.
-- Runs recorded before have an empty scope, which matches no run after, so a lapse
-- whose window straddles the upgrade is not credited.
ALTER TABLE assessments
    ADD COLUMN IF NOT EXISTS live_scope TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS unjudged BOOLEAN NOT NULL DEFAULT false;
