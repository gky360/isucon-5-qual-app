CREATE TABLE fp LIKE footprints;
ALTER TABLE fp ADD COLUMN date date NOT NULL, ADD UNIQUE INDEX unique_per_day (user_id,owner_id,date), ADD INDEX user_id (user_id);
REPLACE INTO fp SELECT id, user_id, owner_id, created_at, DATE(created_at) FROM footprints WHERE id <= 500000;
RENAME TABLE footprints TO footprints_old, fp TO footprints;
