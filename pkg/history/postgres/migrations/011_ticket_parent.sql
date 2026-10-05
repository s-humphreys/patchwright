-- The epic each ticket is filed under, so a route excluded from the ticket counts can
-- be told apart by project and epic. Null on rows read before it was; the sync reads
-- the tracker in full once while any ticket the last read touched is null, and writes
-- an empty string for a ticket at the project root.
ALTER TABLE tickets
    ADD COLUMN IF NOT EXISTS parent TEXT;
