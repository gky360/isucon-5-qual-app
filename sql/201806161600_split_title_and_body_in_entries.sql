CREATE TABLE ents LIKE entries;
ALTER TABLE ents ADD title VARCHAR(191);
INSERT INTO ents SELECT id, user_id, private, SUBSTRING(body, CHAR_LENGTH(SUBSTRING_INDEX(body, '\n', 1)) + 2), created_at, SUBSTRING_INDEX(body, '\n', 1) FROM entries
WHERE id <= 500000;
RENAME TABLE entries to entries_old, ents TO entries;
