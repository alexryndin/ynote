BEGIN;

CREATE TABLE IF NOT EXISTS tags (
  id INTEGER NOT NULL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS snippet_types (
  id INTEGER NOT NULL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS snippets (
  id INTEGER NOT NULL PRIMARY KEY,
  title TEXT UNIQUE NOT NULL,
  content TEXT,
  type INTEGER NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted BOOL DEFAULT FALSE NOT NULL,
  FOREIGN KEY(type) REFERENCES snippet_types(id)
);

CREATE TABLE IF NOT EXISTS snippet_to_tags (
  id INTEGER NOT NULL PRIMARY KEY,
  snippet_id NOT NULL,
  tag_id NOT NULL,
  FOREIGN KEY(snippet_id) REFERENCES snippets(id),
  FOREIGN KEY(tag_id) REFERENCES tags(id)
  UNIQUE(snippet_id, tag_id)
);

INSERT INTO snippet_types (name) VALUES ("bash");
INSERT INTO snippet_types (name) VALUES ("plain");
INSERT INTO snippets (title, content, type) VALUES ("Hello", "world", 1);
INSERT INTO snippets (title, content, type) VALUES ("Привет", "Мир", 1);
INSERT INTO snippets (title, content, type) VALUES ("Halo!", "test very long string that contains very much of a characters, including русские", 2);
INSERT INTO tags (name) VALUES ("kafka");
INSERT INTO tags (name) VALUES ("c");
INSERT INTO snippet_to_tags (snippet_id, tag_id) VALUES (1,1);
INSERT INTO snippet_to_tags (snippet_id, tag_id) VALUES (1,2);
INSERT INTO snippet_to_tags (snippet_id, tag_id) VALUES (2,2);

COMMIT;
