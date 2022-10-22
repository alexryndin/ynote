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
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted BOOL DEFAULT FALSE NOT NULL,
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
  name TEXT NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dir_to_dirs (
  id INTEGER NOT NULL PRIMARY KEY,
  dir_id NOT NULL,
  child_id NOT NULL,
  FOREIGN KEY(dir_id) REFERENCES dirs(id),
  FOREIGN KEY(child_id) REFERENCES dirs(id)
  UNIQUE(dir_id, child_id)
);

CREATE TABLE IF NOT EXISTS files (
  id INTEGER NOT NULL PRIMARY KEY,
  name TEXT NOT NULL,
  location TEXT UNIQUE NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS files_to_tags (
  id INTEGER NOT NULL PRIMARY KEY,
  file_id NOT NULL,
  tag_id NOT NULL,
  FOREIGN KEY(file_id) REFERENCES files(id),
  FOREIGN KEY(tag_id) REFERENCES tags(id)
  UNIQUE(file_id, tag_id)
);

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

INSERT INTO dirs(name) VALUES ("root"), ("codes");
INSERT INTO dir_to_dirs (dir_id, child_id) VALUES (1,2);

COMMIT;

