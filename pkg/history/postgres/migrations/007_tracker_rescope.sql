-- The tracker search gained its epic scope after the first production read, which
-- had indexed every Task the projects ever raised. Everything here is re-derivable
-- from the tracker, so the table is emptied and the next run reads it in full,
-- scoped, rather than leaving out-of-scope rows that an incremental sync would
-- never revisit.
DELETE FROM tickets;
