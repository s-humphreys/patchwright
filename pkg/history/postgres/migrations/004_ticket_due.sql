-- The due date each ticket covering an item was raised with, by issue key, so a
-- ticket closing can be measured against its deadline without asking the tracker.
ALTER TABLE items
    ADD COLUMN IF NOT EXISTS ticket_due JSONB NOT NULL DEFAULT '{}'::jsonb;
