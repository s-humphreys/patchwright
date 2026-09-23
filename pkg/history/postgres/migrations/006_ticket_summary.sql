-- The ticket's title, so a list of tickets can say what each one is about without a
-- round trip to the tracker. Nullable: rows read before titles were stay empty until
-- the tracker is read in full again.
ALTER TABLE tickets
    ADD COLUMN IF NOT EXISTS summary TEXT;
