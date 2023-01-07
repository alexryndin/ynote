package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/pflag"
)

var db *sql.DB

func getSnippet(db *sql.DB, id int) (Snippet, error) {
	// Prepare the SELECT statement
	stmt, err := db.Prepare("SELECT id, title, content FROM snippets WHERE id = ?")
	if err != nil {
		return Snippet{}, err
	}
	defer stmt.Close()

	// Execute the SELECT statement
	var snippet Snippet
	err = stmt.QueryRow(id).Scan(&snippet.ID, &snippet.Title, &snippet.Content)
	if err != nil {
		if err == sql.ErrNoRows {
			return Snippet{}, fmt.Errorf("snippet with ID %d not found", id)
		}
		return Snippet{}, err
	}

	return snippet, nil
}

func getAllSnippets(db *sql.DB) ([]Snippet, error) {
	// Prepare the SELECT statement
	stmt, err := db.Prepare("SELECT id, title, content FROM snippets")
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

func indexHandler(c *gin.Context) {
	// Get all the snippets from the database
	log.Println("db is %p", db)
	snippets, err := getAllSnippets(db)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html.tmpl", gin.H{
			"error": err.Error(),
		})
		return
	}

	// Render the list of snippets
	c.HTML(http.StatusOK, "index.html.tmpl", gin.H{
		"snippets": snippets,
	})
}

func createHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "create.html", nil)
}

func viewHandler(c *gin.Context) {
	// Get the ID parameter from the URL
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html.tmpl", gin.H{
			"error": "invalid snippet ID",
		})
		return
	}

	// Get the snippet from the database
	snippet, err := getSnippet(db, id)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html.tmpl", gin.H{
			"error": err.Error(),
		})
		return
	}

	// Render the snippet
	c.HTML(http.StatusOK, "view.html", gin.H{
		"snippet": snippet,
	})
}

func createSnippet(db *sql.DB, s Snippet) (int, error) {
	// Prepare the INSERT statement
	stmt, err := db.Prepare("INSERT INTO snippets (title, content) VALUES (?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	// Execute the INSERT statement
	result, err := stmt.Exec(s.Title, s.Content)
	if err != nil {
		return 0, err
	}

	// Get the ID of the new row
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	return int(id), nil
}

func notesHandler(c *gin.Context) {
	// Bind the form data to a Snippet struct
	var s Snippet
	if err := c.Bind(&s); err != nil {
		c.HTML(http.StatusBadRequest, "error.html.tmpl", gin.H{
			"error": "invalid form data",
		})
		return
	}

	// Validate the form data
	if s.Title == "" || s.Content == "" {
		c.HTML(http.StatusBadRequest, "error.html.tmpl", gin.H{
			"error": "title and content are required",
		})
		return
	}

	// Create the snippet in the database
	id, err := createSnippet(db, s)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html.tmpl", gin.H{
			"error": err.Error(),
		})
		return
	}

	// Redirect to the view page
	c.Redirect(http.StatusSeeOther, fmt.Sprintf("/view/%d", id))
}

// Snippet represents a note in the database
type Snippet struct {
	ID      int
	Title   string
	Content string
}

type Config struct {
	Server struct {
		Port int
	}
	Database struct {
		Path string
	}
}

func readConfig(filename string) (*Config, error) {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read the file into a byte slice
	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// Unmarshal the TOML data into a Config struct
	var config Config
	if _, err := toml.Decode(string(bytes), &config); err != nil {
		return nil, err
	}

	return &config, nil
}

var configFile string

func init() {
	pflag.StringVarP(&configFile, "config", "c", "config.toml", "path to config file")
}

func main() {
	pflag.Parse()
	var err error
	// Read the config from a file
	config, err := readConfig(configFile)
	if err != nil {
		panic(err)
	}

	db, err = sql.Open("sqlite3", "file:"+config.Database.Path+"?mode=rw")
	if err != nil || db == nil {
		panic(err)
	}
	defer db.Close()
	err = db.Ping()
	if err != nil || db == nil {
		panic(err)
	}

	r := gin.Default()

	// Set up the HTML rendering middleware
	r.LoadHTMLGlob("templates/*.html.tmpl")

	// Set up the routes
	r.GET("/", indexHandler)
	r.GET("/create", createHandler)
	r.GET("/view/:id", viewHandler)
	r.POST("/notes", notesHandler)
	r.Static("/static", "static/www/")

	// Start the server
	r.Run()
}
