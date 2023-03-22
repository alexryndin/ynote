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
  dir NOT NULL DEFAULT 1,
  created DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
  updated DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
  deleted BOOL DEFAULT FALSE NOT NULL,
  unsorted BOOL DEFAULT FALSE NOT NULL,
  FOREIGN KEY(type) REFERENCES snippet_types(id),
  FOREIGN KEY(dir) REFERENCES dirs(id)
);

CREATE TABLE IF NOT EXISTS snippet_to_tags (
  id INTEGER NOT NULL PRIMARY KEY,
  snippet_id NOT NULL,
  tag_id NOT NULL,
  FOREIGN KEY(snippet_id) REFERENCES snippets(id),
  FOREIGN KEY(tag_id) REFERENCES tags(id)
  UNIQUE(snippet_id, tag_id)
);

CREATE TABLE IF NOT EXISTS dirs (
  id INTEGER NOT NULL PRIMARY KEY,
  parent_id NOT NULL,
  name TEXT NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(parent_id) REFERENCES dirs(id)
  UNIQUE(id, parent_id)
  UNIQUE(parent_id, name)
);

CREATE TABLE IF NOT EXISTS file_types (
  id INTEGER NOT NULL PRIMARY KEY,
  name TEXT NOT NULL,
  mime TEXT NOT NULL UNIQUE,
  UNIQUE(name, mime)
);

CREATE TABLE IF NOT EXISTS files (
  id INTEGER NOT NULL PRIMARY KEY,
  name TEXT NOT NULL,
  location TEXT UNIQUE NOT NULL,
  type INTEGER NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(type) REFERENCES file_types(id)
);

CREATE TABLE IF NOT EXISTS files_to_tags (
  id INTEGER NOT NULL PRIMARY KEY,
  file_id NOT NULL,
  tag_id NOT NULL,
  FOREIGN KEY(file_id) REFERENCES files(id),
  FOREIGN KEY(tag_id) REFERENCES tags(id)
  UNIQUE(file_id, tag_id)
);

CREATE VIEW snippets_view AS
SELECT snippets.id as id, title, content, name as type, dir, created, updated, deleted
FROM snippets JOIN snippet_types
ON snippets.type = snippet_types.id;

CREATE TRIGGER insert_snippet_view
  INSTEAD OF INSERT ON snippets_view
BEGIN
  INSERT OR IGNORE INTO snippet_types (name)
  VALUES (new.type);

  INSERT INTO snippets (
    id,
    title,
    content,
    type,
    dir,
    created,
    updated,
    deleted
  ) VALUES (
  new.id,
  new.title,
  new.content,
  (select snippet_types.id from snippet_types where name = new.type),
  new.dir,
  ifnull(new.created, datetime()),
  ifnull(new.updated, datetime()),
  ifnull(new.deleted, false)
  );
END;

CREATE TRIGGER update_snippet_view
  INSTEAD OF UPDATE ON snippets_view
BEGIN
  INSERT OR IGNORE INTO snippet_types (name)
  VALUES (new.type);

  UPDATE snippets
  SET
  id = new.id,
  title = new.title,
  content = new.content,
  type = (select snippet_types.id from snippet_types where name = new.type),
  dir = new.dir,
  created = new.created,
  updated = iif(old.updated = new.updated, datetime(), new.updated),
  deleted = new.deleted
  where id = new.id;
END;


INSERT INTO snippet_types (name) VALUES ("bash");
INSERT INTO snippet_types (name) VALUES ("code");
INSERT INTO snippet_types (name) VALUES ("plain");
INSERT INTO snippet_types (name) VALUES ("markdown");
INSERT INTO snippets (title, content, type) VALUES ("Hello", "world", 1);
INSERT INTO snippets (title, content, type) VALUES ("Привет", "Мир", 1);
INSERT INTO snippets (title, content, type) VALUES ("Halo!", "test very long string that contains very much of a characters, including русские", 3);
INSERT INTO snippets (title, content, type) VALUES ("Маркdown!", '# Title 1
## Сабтайтл 2
Некоторый текст
```
int main(void){
    printf("hello world");
    return 0;
}
```
## Subtitle 2
Некоторый text.
', 4);
INSERT INTO tags (name) VALUES ("kafka");
INSERT INTO tags (name) VALUES ("c");
INSERT INTO tags (name) VALUES ("test");
INSERT INTO snippet_to_tags (snippet_id, tag_id) VALUES (1,1);
INSERT INTO snippet_to_tags (snippet_id, tag_id) VALUES (1,2);
INSERT INTO snippet_to_tags (snippet_id, tag_id) VALUES (2,2);
INSERT INTO snippet_to_tags (snippet_id, tag_id) VALUES (4,3);
INSERT INTO file_types (name, mime) VALUES ("png", "image/png");
INSERT INTO file_types (name, mime) VALUES ("text", "application/octet-stream");

INSERT INTO dirs(id, name, parent_id) VALUES (1, "root", 1), (2, "codes", 1);

COMMIT;

