package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
)

// Snippet represents a note in the database
type Index struct {
	ID      int
	Title   string
	Type    string
	Content string
	Created time.Time
	Updated time.Time
	Tags    string
}
type Snippet struct {
	ID      int
	Title   string
	Type    string
	Path    string
	Content template.HTML
	Created time.Time
	Updated time.Time
	Tags    string
}

type Tag struct {
	ID   int
	Name string
}

func pathAscent(db *sql.DB, id int) (string, error) {
	q :=
		`WITH RECURSIVE
      ascend(x, id, name, parent_id) AS (
      select 1, id, name, parent_id from dirs where id = (select dir from
      snippets where id = ?)
      UNION
      SELECT x+1, dirs.id, dirs.name, dirs.parent_id from dirs, ascend
      where ascend.parent_id = dirs.id and ascend.id != ascend.parent_id
      limit 255
      )
      select IIF(count(*) > 1, substr(group_concat(name, '/'),5), '/') from
      (select name from ascend
      order by x desc);`
	var ret string
	err := db.QueryRow(q, id).Scan(&ret)
	if err != nil {
		logger.Debug(fmt.Sprintf("err %+v", err))
		return "", err
	}
	return ret, nil
}

func getIndex(db *sql.DB, path string, unsorted bool) ([]Index, error) {
	id := 1
	var err error
	if !unsorted {
		id, err = pathDescent(db, path)
		if err != nil {
			return nil, err
		}
	}
	q := `
SELECT
  a.id AS id,
  a.name AS title,
  '' AS content,
  '' AS tags,
  'd' AS type
FROM dirs AS a
JOIN dirs AS b
  ON b.id = a.parent_id
WHERE b.id = ? and a.id != 1
UNION ALL
SELECT
  snippets.id AS id,
  snippets.title AS title,
  substr(snippets.content, 1, 50) AS content,
  IFNULL(group_concat(tags.name, ', '), '') AS tags,
  's' AS type
FROM snippets
LEFT JOIN snippet_to_tags
  ON snippets.id = snippet_to_tags.snippet_id
LEFT JOIN tags
  ON snippet_to_tags.tag_id = tags.id
WHERE snippets.dir = ?2
AND snippets.unsorted = ?3
AND snippets.deleted = 0
GROUP BY snippets.id;
`
	stmt, err := db.Prepare(q)
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query(id, id, unsorted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var notes []Index
	for rows.Next() {
		var note Index
		if err := rows.Scan(&note.ID, &note.Title, &note.Content, &note.Tags, &note.Type); err != nil {
			return nil, err
		}
		notes = append(notes, note)
	}

	return notes, nil
}

func pathDescent(db *sql.DB, path string) (int, error) {
	ret := 1
	q := `
select a.id from dirs as a
join dirs as b on a.parent_id == b.id
where b.id = ? and a.name = ?;`
	if len(path) < 1 || path[0] != '/' {
		return 1, errors.New("wrong path")
	}
	if len(path) == 1 {
		return 1, nil

	}
	spath := strings.Split(path, "/")
	for _, v := range spath {
		if v == "" {
			continue
		}

		stmt, err := db.Prepare(q)
		if err != nil {
			return 1, err
		}
		rows, err := stmt.Query(ret, v)
		if err != nil {
			return 1, err
		}
		defer rows.Close()

		// Iterate over the results and print them
		if !rows.Next() {
			return 1, errors.New("Path not found")

		}
		if err := rows.Scan(&ret); err != nil {
			return 1, errors.New("database error")
		}
		if err := rows.Err(); err != nil {
			return 1, err
		}
	}
	return ret, nil
}

func mkdir(db *sql.DB, name string, parentID int) (string, error) {
	q := `INSERT INTO dirs (name, parent_id)
VALUES (?, ?)
RETURNING id`
	var ret int
	err := db.QueryRow(q, name, parentID).Scan(&ret)
	if err != nil {
		if driverErr, ok := err.(sqlite3.Error); ok {
			if driverErr.Code == sqlite3.ErrConstraint {
				return "already exists", nil
			}
		}
		logger.Debug(fmt.Sprintf("err %+v", err))
		return "", err
	}
	return fmt.Sprintf("dir id:%d created", ret), nil
}

func getAllSnippets(db *sql.DB) ([]Snippet, error) {
	// Prepare the SELECT statement
	stmt, err := db.Prepare("SELECT id, title, content FROM snippets where deleted = 0")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	// Execute the SELECT statement
	rows, err := stmt.Query()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Iterate over the rows, scanning the values into the note struct
	var notes []Snippet
	for rows.Next() {
		var note Snippet
		if err := rows.Scan(&note.ID, &note.Title, &note.Content); err != nil {
			return nil, err
		}
		notes = append(notes, note)
	}

	return notes, nil
}

func ensureTags(db *sql.DB, tags []string) error {
	if len(tags) == 0 {
		return nil
	}
	q := fmt.Sprintf("INSERT OR IGNORE INTO tags (name) VALUES (%s)", strings.Repeat("(?),", len(tags))[0:])
	stmt, err := db.Prepare(q)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(tags)
	if err != nil {
		return err
	}
	return nil

}

func getOrInsertSnippetType(db *sql.DB, name string) (int, error) {
	q := `INSERT OR IGNORE INTO snippet_types (name) VALUES (?);`
	stmt, err := db.Prepare(q)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	// Execute the INSERT statement
	_, err = stmt.Exec(name)
	if err != nil {
		return 0, err
	}
	q = `SELECT id from snippet_types where name = ?;`
	stmt.Close()
	var ret int
	err = db.QueryRow(q, name).Scan(&ret)
	if err != nil {
		return 0, err
	}
	return ret, nil
}
func deleteSnippet(db *sql.DB, id int) error {
	q := `UPDATE snippets SET deleted = 1 WHERE id = ?`
	_, err := db.Exec(q, id)
	return err
}

func getSnippet(db *sql.DB, id int, raw bool) (*Snippet, error) {
	var s Snippet
	var q string
	if raw {
		q = `SELECT s.id, s.title, s.content, s.created, s.updated, t.name as type, IFNULL(group_concat(tg.name, ', '), '') as tags
FROM snippets s
INNER JOIN snippet_types t ON s.type = t.id
LEFT JOIN snippet_to_tags stt ON s.id = stt.snippet_id
LEFT JOIN tags tg ON stt.tag_id = tg.id where s.id = ? and deleted = 0
GROUP BY s.id`

	} else {
		q = `SELECT s.id, s.title, md2html(s.content), s.created, s.updated, t.name as type, IFNULL(group_concat(tg.name, ', '), '') as tags
FROM snippets s
INNER JOIN snippet_types t ON s.type = t.id
LEFT JOIN snippet_to_tags stt ON s.id = stt.snippet_id
LEFT JOIN tags tg ON stt.tag_id = tg.id where s.id = ? and deleted = 0
GROUP BY s.id`
	}
	err := db.QueryRow(q, id).Scan(&s.ID, &s.Title, &s.Content, &s.Created, &s.Updated, &s.Type, &s.Tags)
	if err != nil {
		return nil, err
	}
	path, err := pathAscent(db, s.ID)
	if err != nil {
		return nil, err
	}
	s.Path = path
	return &s, nil
}

func editSnippet(db *sql.DB, s *Snippet) (int, error) {
	// Prepare the INSERT statement
	ensureTagsAsString(db, s.Tags)
	snippet_type, err := getOrInsertSnippetType(db, s.Type)
	if err != nil {
		return 0, err
	}
	q := `UPDATE snippets SET title = ?, content = ?, type = ? where id = ?`

	logger.Debug(fmt.Sprintf("q is %s", q))
	logger.Debug(fmt.Sprintf("q is %+v", s))
	_, err = db.Exec(q, s.Title, s.Content, snippet_type, s.ID)
	if err != nil {
		return 0, err
	}

	// Get the ID of the new row
	q = `DELETE snippet_to_tags where snippet_id = ?`
	logger.Debug(fmt.Sprintf("q is %s", q))
	db.Exec(q, s.ID)
	if err != nil {
		return 0, err
	}

	q = `INSERT OR IGNORE INTO snippet_to_tags
     (snippet_id, tag_id) SELECT ?, id FROM tags WHERE name IN (%s)`
	q = fmt.Sprintf(q, strings.TrimSuffix(strings.Repeat("?,", len(s.Tags)), ","))
	logger.Debug(fmt.Sprintf("q is %s", q))
	stmt, err := db.Prepare(q)
	if err != nil {
		return 0, err
	}

	defer stmt.Close()

	var args []interface{}
	args = append(args, s.ID)
	for _, v := range s.Tags {
		args = append(args, v)

	}

	_, err = stmt.Exec(args...)
	if err != nil {
		return 0, err
	}

	return s.ID, nil
}

type File struct {
	name     string
	location string
	_type    string
	mime     string
	tags     string
}

func ensureTagsAsString(db *sql.DB, tags string) error {
	tags_split := strings.Split(tags, ",")
	var tags_new []string
	for _, v := range tags_split {
		v := strings.Trim(v, " ")
		if v == "" {
			continue
		}
		tags_new = append(tags_new, v)
	}
	return ensureTags(db, tags_new)
}

func regiesterFile(db *sql.DB, f *File) (int, error) {
	var mime int
	q := `SELECT id from file_types where mime = ?;`
	err := db.QueryRow(q, f.mime).Scan(&mime)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, errors.New("unknown mime")

		}
		return 0, err
	}
	if err = ensureTagsAsString(db, f.tags); err != nil {
		return 0, err
	}
	q = `INSERT INTO files (name, location, type) VALUES (?, ?, ?) RETURNING id`
	var ret int
	err = db.QueryRow(q, f.name, f.location, mime).Scan(&ret)
	if err != nil {
		return 0, err
	}
	return ret, nil

}

func createSnippet(db *sql.DB, s *Snippet) (int, error) {
	// Prepare the INSERT statement
	ensureTagsAsString(db, s.Tags)
	snippet_type, err := getOrInsertSnippetType(db, s.Type)
	if err != nil {
		return 0, err
	}

	pathid, _ := pathDescent(db, s.Path)

	q := `INSERT INTO snippets (title, content, type, dir) VALUES (?, ?, ?, ?) RETURNING ID`

	// Execute the INSERT statement
	var id int
	err = db.QueryRow(q, s.Title, s.Content, snippet_type, pathid).Scan(&id)
	if err != nil {
		if driverErr, ok := err.(sqlite3.Error); ok {
			if driverErr.Code == sqlite3.ErrConstraint {
				return 0, errors.New("already exists")
			}
		}
		return 0, err
	}

	// Get the ID of the new row

	q = `INSERT OR IGNORE INTO snippet_to_tags
     (snippet_id, tag_id) SELECT ?, id FROM tags WHERE name IN (%s)`
	q = fmt.Sprintf(q, strings.Repeat("?,", len(s.Tags)))
	stmt, err := db.Prepare(q)
	if err != nil {
		return 0, err
	}

	defer stmt.Close()

	var args []interface{}
	args = append(args, id)
	for _, v := range s.Tags {
		args = append(args, v)

	}

	_, err = stmt.Exec(args...)
	if err != nil {
		return 0, err
	}

	return id, nil
}
