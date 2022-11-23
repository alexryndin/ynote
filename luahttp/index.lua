local tags = require "luahttp/tags"
local string = require "string"
local pages = require "pages"

function string.startswith(String,Start)
   return string.sub(String,1,string.len(Start))==Start
end

--function snippets()
--  local snippets = snippets
--  tr()
--  tr()
--  return table(tr)
--end
--<a rel="noopener noreferrer" href="//localhost:8080/root//codes" class="list-item"> 📁:2 <span class="muted">[</span><span class="identifier">codes</span><span class="muted">]</span></a>
dir_sym = "📁"
local snippets = tags(function(ud, dir)
  local p = p{ class = "list-item" }
  port = httpaux.get_port(ud)
  while ldbw.step(ud) == sqlite3.SQLITE_ROW do
    ctype = ldbw.column_int64(ud, 4)
    sep = (ctype == 1.) and dir_sym..": " or "ID: "
    href = ctype == 1 and ldbw.column_text(ud, 1)
                       or "/lua/get_snippet/"..ldbw.column_int64(ud, 0)
    p (
      a { rel="noopener noreferrer",
          class="list-item",
          href = href } (
        sep..ldbw.column_int64(ud, 0).." ",
        span {class = "muted"} ("["),
        span {class = "identifier"} (ldbw.column_text(ud, 1)),
        span {class = "muted"} ("] "),
        ldbw.column_text(ud, 2)
      )
    )
    p (br)
  end
  return p
end)

function get_snippet(ud, path)
  t = httpaux.get_query(ud)

end

return function (ud)
  path = httpaux.get_path(ud)
  if path == "/lua/get_snippet" then
    return get_snippet(ud, path)
  end
  if string.startswith(path, '/root/') then
    path = path:sub(string.len('/root/'))
  end
  dir = ldbw.path_descend(ud, path)
  q = [[select c.id as id, c.name as title, '' as content, '' as tags, 1 as type from dirs as a
       join dir_to_dirs
       as b on a.id = b.dir_id join dirs as c on b.child_id = c.id
       where a.id = ?
       UNION ALL
       select snippets.id as id, snippets.title as title, substr(snippets.content, 1, 50) as content, group_concat(tags.name, ', ') as tags, 2 as type from snippets left join snippet_to_tags on snippets.id = snippet_to_tags.snippet_id left join tags on snippet_to_tags.tag_id = tags.id where snippets.dir = ? group by snippets.id;]]
  ldbw.prepare(ud, q)
  err = ldbw.bind_int64(ud, 1, dir)
  if err then
    print(err)
    return "server error", 500
  end
  err = ldbw.bind_int64(ud, 2, dir)
  if err then
    print(err)
    return "server error", 500
  end
  local html = tags(function()
      return html (
          head (
              meta { charset = "utf-8" },
              title "ynote",
              link {rel = "stylesheet", href = "/static/css/nb.css"}
          ),
          body (
            unsafe(pages.menu_bar {["new"] = true, ["path"] = path}),
            div {class = "main"} (
              form {
                id = "search",
                ["accept-charset"] = "UTF-8",
                action = "/command",
                method = "post"
              } (
                input {
                  id = "search-input",
                  placeholder = "command"
                },
                input {
                  ["type"] = "hidden",
                  name = "path",
                  value = path
                }
              ),


              snippets(ud)
            )
          )
      )
  end)
  return tostring(html())
end
