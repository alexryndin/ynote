package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sqlite "github.com/mattn/go-sqlite3"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
)

var db *sql.DB
var logger *zap.Logger
var port = 8080

type RenderInfo struct {
	Port int
}

func indexMsgHandler(c *gin.Context, status int, msg string) {
	// Get all the snippets from the database
	//logger := c.MustGet("logger").(*zap.Logger)
	pathStr := c.Param("path")
	if pathStr == "" {
		pathStr = "/"
	}
	logger.Debug(fmt.Sprintf("path is %s", pathStr))

	snippets, err := getIndex(db, pathStr, false)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error", gin.H{
			"error": err.Error(),
		})
		return
	}
	// Render the list of snippets
	c.HTML(status, "index", gin.H{
		"snippets": snippets,
		"port":     port,
		"msg":      msg,
		"menu": Menu{
			Path: pathStr,
		},
	})
}

func indexHandler(c *gin.Context) {
	indexMsgHandler(c, 200, "")
	return
}

func createFormHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "create.html.tmpl", nil)
}

var frontMatterRegex = regexp.MustCompile(`(?s)(?m)^\+\+\+$(.+?)^\+\+\+$`)

// ExtractFrontMatter extracts the front matter block from the given content string
// and returns it as a map.
func splitPairs(content string) map[string]string {
	frontMatterMap := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		frontMatterMap[key] = value
	}

	return frontMatterMap

}
func ExtractFrontMatter(content string) (map[string]string, error) {
	frontMatter := frontMatterRegex.FindStringSubmatch(content)
	if frontMatter == nil {
		return nil, errors.New("FrontMatter block not found")
	}
	frontMatterBlock := frontMatter[1]
	return splitPairs(frontMatterBlock), nil

	// Parse the front matter block into a map
}

type RawSnippet struct {
	Content string
	fm      map[string]string
}

func extractValidateRawSnippet(content string) (*RawSnippet, error) {
	var ret RawSnippet
	firstIndex := strings.Index(content, "+++")
	secondIndex := strings.Index(content[firstIndex+3:], "+++")
	if secondIndex == -1 {
		return nil, errors.New("invalid frontmatter -- missing `+++` separated block")
	}
	secondIndex = secondIndex + firstIndex + 3
	frontmatter := content[firstIndex : secondIndex+3]
	content = content[secondIndex+4:]
	content = content[:len(content)-1]
	fm, err := ExtractFrontMatter(frontmatter)
	if err != nil {
		return nil, err
	}
	// Create the snippet in the database
	for _, v := range []string{"title", "tags", "type"} {
		_, ok := fm[v]
		if !ok {
			return nil, errors.New(fmt.Sprintf("%s required", v))
		}

	}
	for _, v := range []string{"title", "type"} {
		val := fm[v]
		if val == "" {
			return nil, errors.New(fmt.Sprintf("%s required", v))
		}

	}
	ret.fm = fm
	ret.Content = content
	return &ret, nil

}

func newSnippetHandler(c *gin.Context) {
	// Bind the form data to a Snippet struct
	var s Snippet
	path := c.Query("path")
	if path == "" {
		path = "/"
	}
	logger.Debug(fmt.Sprintf("path is %s", path))
	if c.Request.Method == "GET" {
		s.Title = "New snippet"
		c.HTML(http.StatusOK, "snippet_edit", gin.H{
			"snippet": s,
			"menu": Menu{
				Path: path,
			},
			"port": port,
		})
		return

	}
	contentb, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error", gin.H{
			"error": "Server Error",
		})
		return
	}
	content := strings.ReplaceAll(string(contentb), "\r\n", "\n")
	// Validate the form data
	if content == "" {
		c.HTML(http.StatusBadRequest, "error", gin.H{
			"error": " content is required",
		})
		return
	}
	rs, err := extractValidateRawSnippet(content)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error", gin.H{
			"error": err,
		})
		return
	}

	s.Title = rs.fm["title"]
	s.Tags = rs.fm["tags"]
	s.Type = rs.fm["type"]
	s.Path = path
	id, err := createSnippet(db, &s)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error", gin.H{
			"error": err,
		})
		return
	}

	// Redirect to the view page
	c.Redirect(http.StatusSeeOther, fmt.Sprintf("/snippet/%d", id))
	return
}

func commandHandler(c *gin.Context) {
	logger := c.MustGet("logger").(*zap.Logger)
	contentb, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error", gin.H{
			"error": "Server Error",
		})
		return
	}
	content := strings.ReplaceAll(string(contentb), "\r\n", "\n")
	// Validate the form data
	cmdmap := splitPairs(content)
	command := cmdmap["command"]
	if command == "" {
		c.HTML(http.StatusBadRequest, "error", gin.H{
			"error": " command is required",
		})
		return
	}

	path := cmdmap["path"]
	logger.Debug(fmt.Sprintf("path is %s", path))
	if path == "" {
		path = "/"
	}

	cs := strings.Split(command, " ")
	logger.Debug(fmt.Sprintf("command is %+v", cs))
	if cs[0] == "rm" {
		usage := "Usage: rm d|s id"
		if len(cs) < 3 || cs[1] != "s" {
			indexMsgHandler(c, http.StatusBadRequest, usage)
			return
		}
		id, err := strconv.Atoi(cs[2])
		if err != nil {
			indexMsgHandler(c, http.StatusBadRequest, usage)
			return
		}
		err = deleteSnippet(db, id)
		if err != nil {
			logger.Error(err.Error())
			indexMsgHandler(c, http.StatusInternalServerError, "Internal error")
			return
		}
		indexMsgHandler(c, http.StatusOK, "ok")
		return

	} else if cs[0] == "mkdir" {
		usage := "Usage: mkdir <name>"
		if len(cs) < 2 {
			indexMsgHandler(c, http.StatusBadRequest, usage)
			return
		}
		name := cs[1]
		id, err := pathDescent(db, path)
		if err != nil {
			indexMsgHandler(c, http.StatusBadRequest, err.Error())
			return
		}

		msg, err := mkdir(db, name, id)
		if err != nil {
			logger.Error(err.Error())
			indexMsgHandler(c, http.StatusInternalServerError, "Internal error")
			return
		}
		indexMsgHandler(c, http.StatusOK, msg)
		return

	}
	indexMsgHandler(c, http.StatusBadRequest, " wrong command")
	return
}
func cleanFilename(s string) (string, bool) {
	// Remove any directory information and extra slashes from the string
	base := filepath.Base(filepath.Clean(s))

	// Check that the base string is not empty
	if base == "." || base == ".." || base == "" {
		return "", false
	}

	// Check that the base string doesn't contain any invalid characters
	for _, r := range base {
		if strings.IndexRune(`<>:"/\|?*`, r) >= 0 {
			return "", false
		}
	}

	return base, true
}
func uploadHandler(c *gin.Context) {
	// Get the ID parameter from the URL
	// Create a new UUID for the file name
	file_ok := true
	var register_name string
	var content_type string
	store_name := uuid.New().String()
	store_path := filepath.Join("uploads", "tmp", store_name)

	path := c.Query("path")
	if path == "" {
		path = "/"
	}
	if c.Request.Method == "GET" {
		c.HTML(http.StatusOK, "upload", gin.H{
			"path": path,
		})
		return
	}

	reader, err := c.Request.MultipartReader()
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		if part.FileName() != "" {
			if part.FormName() != "file" {
				continue
			}
			content_type = part.Header.Get("Content-Type")
			register_name = part.FileName()
			logger.Debug(fmt.Sprintf("register_name is %s", part.FileName()))

			out, err := os.Create(store_path)
			if err != nil {
				c.AbortWithError(http.StatusInternalServerError, err)
				return
			}
			defer out.Close()

			// Copy the contents of the source file to the destination file
			_, err = io.Copy(out, part)
			if err != nil {
				c.AbortWithError(http.StatusInternalServerError, err)
				return
			}
			file_ok = true
		} else {
			if part.FormName() == "filename" {
				lr := io.LimitReader(part, int64(256))

				// Read the contents of the Limited Reader
				contents, err := ioutil.ReadAll(lr)
				if err != nil {
					c.String(http.StatusInternalServerError, "internal error")
					return
				}

				// Check if the number of bytes read is less than or equal to the maximum
				if len(contents) > 255 {
					c.String(http.StatusBadRequest, "too long filename")
					return
				}
				var ok bool
				register_name, ok = cleanFilename((string)(contents))
				if !ok {
					c.String(http.StatusBadRequest, "bad filename")
					return

				}

			}
			continue

		}
	}

	if !file_ok {
		c.String(http.StatusBadRequest, "Expecting file in a 'file' field")
	}

	logger.Debug(fmt.Sprintf("store_path is %s", store_path))
	logger.Debug(fmt.Sprintf("register_name is %s", register_name))
	store_dir := filepath.Join("uploads", store_name[:2])
	_, err = os.Stat(store_dir)
	if os.IsNotExist(err) {
		err := os.Mkdir(store_dir, 0755)
		if err != nil {
			// Handle error
			c.HTML(http.StatusInternalServerError, "error", gin.H{
				"error": err,
			})
			return
		}
	} else {
		c.HTML(http.StatusInternalServerError, "error", gin.H{
			"error": err,
		})
		return

	}

	id, err := regiesterFile(db, &File{
		mime:     content_type,
		location: filepath.Join(store_dir),
		name:     register_name,
	})
	destination_path := filepath.Join(store_dir, fmt.Sprintf("%s_%d", store_name, id))
	os.Rename(store_path, destination_path)
	c.HTML(http.StatusOK, "upload", gin.H{
		"path": path,
		"msg":  fmt.Sprintf("file uploaded, name: %s", register_name),
	})
	return
}
func uploadsHandler(c *gin.Context) {
	// Get the ID parameter from the URL
	c.String(http.StatusNotImplemented, "not implemented")
	return
}

func editSnippetHandler(c *gin.Context) {
	// Get the ID parameter from the URL
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html.tmpl", gin.H{
			"error": "invalid snippet ID",
		})
		return
	}
	snippet, err := getSnippet(db, id, true)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			c.String(http.StatusNotFound, "not found")
			return
		default:
			c.HTML(http.StatusInternalServerError, "error", gin.H{
				"error": err,
			})
			return
		}

	}
	if c.Request.Method == "POST" {
		contentb, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error", gin.H{
				"error": "Server Error",
			})
			return
		}
		content := strings.ReplaceAll(string(contentb), "\r\n", "\n")
		// Validate the form data
		if content == "" {
			c.HTML(http.StatusBadRequest, "error", gin.H{
				"error": " content is required",
			})
			return
		}
		rs, err := extractValidateRawSnippet(content)
		snippet.Title = rs.fm["title"]
		snippet.Tags = rs.fm["tags"]
		snippet.Type = rs.fm["type"]
		snippet.Content = (template.HTML)(rs.Content)
		logger.Debug(fmt.Sprintf("q is %+v", snippet))
		if err != nil {
			c.HTML(http.StatusBadRequest, "error", gin.H{
				"error": err,
			})
			return
		}
		id, err = editSnippet(db, snippet)
		if err != nil {
			c.HTML(http.StatusBadRequest, "error", gin.H{
				"error": err,
			})
			return
		}
		c.Redirect(http.StatusFound, fmt.Sprintf("/snippet/%d", snippet.ID))
		return
	}
	// Render the snippet
	c.HTML(http.StatusOK, "snippet_edit", gin.H{
		"snippet": snippet,
		"port":    port,
		"path":    snippet.Path,
		"edit":    true,
		"menu": Menu{
			Path: snippet.Path,
		},
	})
	return
}

func getSnippetHandler(c *gin.Context) {
	// Get the ID parameter from the URL
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html.tmpl", gin.H{
			"error": "invalid snippet ID",
		})
		return
	}
	snippet, err := getSnippet(db, id, false)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			c.String(http.StatusNotFound, "not found")
			return
		default:
			c.HTML(http.StatusInternalServerError, "error", gin.H{
				"error": err,
			})
			return
		}

	}
	// Render the snippet
	c.HTML(http.StatusOK, "snippet", gin.H{
		"snippet": snippet,
		"port":    port,
		"path":    snippet.Path,
		"menu": Menu{
			Edit: true,
			Path: snippet.Path,
		},
	})
}

type Menu struct {
	Edit bool
	Path string
}

// Bind the form data to a Snippet struct

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
	logger, _ = zap.NewDevelopment()
	defer logger.Sync()
	pflag.Parse()
	var err error
	// Read the config from a file
	config, err := readConfig(configFile)
	if err != nil {
		panic(err)
	}

	sql.Register("sqlite3_ext",
		&sqlite.SQLiteDriver{
			Extensions: []string{
				"./dbw_extension",
			},
		},
	)

	db, err = sql.Open("sqlite3_ext", "file:"+config.Database.Path+"?mode=rw")
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
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/root")
	})
	r.GET("/root", indexHandler)
	r.GET("/root/*path", indexHandler)
	r.GET("/snippet/new", newSnippetHandler)
	r.POST("/snippet/new", newSnippetHandler)
	r.POST("/snippet/:id/edit", editSnippetHandler)
	r.GET("/snippet/:id/edit", editSnippetHandler)
	r.GET("/snippet/:id", getSnippetHandler)
	r.POST("/command", commandHandler)
	r.POST("/upload", uploadHandler)
	r.GET("/upload", uploadHandler)
	r.GET("/uploads", uploadsHandler)
	r.Static("/static", "static/www/")

	// Start the server
	r.Run()
}
