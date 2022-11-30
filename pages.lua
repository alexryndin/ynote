local tags = require "luahttp/tags"
local string = require "string"
local template = require "resty.template.safe"

pages = {}

local snippet = tags(function(p)
  local _edit = p["edit"]
  local edit_mode = p["edit_mode"]
  local _content = p["content"]
  local _type = p["_type"]
  local _tags = p["tags"]
  local _title = p["title"]
  local _id = p["id"]
  local _path = p["path"]
  local _new = p["new"]

  print("edit_mode is ", edit_mode)

  if edit_mode then
    local content = [[+++
title = %s
type =  %s
tags = %s
+++
%s]]


    content = string.format(content, _title, _type, _tags, _content)

    local action=nil

    if _new then
      action = "/api/create_snippet?path=" .. _path
    else
      action = "/api/create_snippet?id=" .. _id .. "&edit=true"
    end

    local form = form {
      enctype="text/plain",
      ["accept-charset"]="UTF-8",
      method="post",
      action=unsafe(action)
    } (
      textarea {
        class="content",
        cols=70,
        id="content",
        name="content",
        rows=30
      } (content),
      br, br,
      input {type = "submit", value = "save"}
    )
    content = nil
    return form
  else return unsafe(_content)
  end


end)

function pages.menu_bar(p)
  local edit = p["edit"]
  local new = p["new"]
  local path = p["path"]
  local id = p["id"]
  print("create is ", create)
  ret = {}
  table.insert(ret, [[
<nav class="header-crumbs">
  <strong>
  <a href="/root"><span class="muted">❯</span> Y </a><span class="muted">·</span>
]])
  if id ~= nil then
    table.insert(ret, string.format([[
<a rel="noopener noreferrer" href="/lua/get_snippet/%d">#%d</a> <span class="muted">·</span> ]], id, id))
  end
  if edit then
    table.insert(ret, string.format([[
<a rel="noopener noreferrer" href="/lua/get_snippet/%d?edit=true&edit_mode=true">edit</a> <span class="muted">·</span> ]], id))
  end
  if new then
    table.insert(ret, string.format([[<a rel="noopener noreferrer" href="/api/create_snippet?path=%s">new</a> <span class="muted">·</span> ]], path))
  end
  table.insert(ret, string.format([[<a rel="noopener noreferrer" href="/root%s">%s</a> <span class="muted">·</span> ]], path, path))

  table.insert(ret, [[</strong></nav>]])
  return table.concat(ret, "")
end

local snippet_view = tags(function(p)
  print("nav is ", p["id"])
  return html (
    head (
        meta { charset = "utf-8" },
        title "ynote",
        link {rel = "stylesheet", href = "/static/css/nb.css"}
    ),
    body (
      unsafe(pages.menu_bar {
        ["edit"] = not p["edit_mode"] and not p["new"],
        ["id"] = p["id"],
        ["path"] = p["path"],
      }),
      div {class = "main"} (
        h1 (p["title"]),
        snippet(p)
      )
    )
  )
end)

function pages.new_snippet(ud, message, path)
  params = {
    id = nil,
    content = [[]],
    title = "New snippet",
    ["_type"] = "plain",
    tags = "",
    ["path"] = path,
    ["edit_mode"] = true,
    new = true,
  }
  return tostring(snippet_view(params))
end

dir_sym = "📁"

local snippets = function(s, port, cwd)
  ret = {}
  table.insert(ret, [[<p class="list-item">]])
  for _, v in ipairs(s) do
    sep = (v["type"] == "d") and dir_sym..": " or "ID: "
    href = v["type"] == "d" and string.format("/root%s%s", cwd == "/" and "/" or cwd .. "/", v["title"])
                       or "/lua/get_snippet/"..v["id"]

    table.insert(ret, string.format([[<a rel="noopener noreferrer" class="list-item" href="%s">%s%d ]], href, sep, v["id"]))
    table.insert(ret, [[<span class="muted">[</span>]])
    table.insert(ret, string.format([[<span class="identifier">%s</span>]], v["title"]))
    table.insert(ret, [[<span class="muted">]</span> ]])
    table.insert(ret, v["content"])
    table.insert(ret, [[</a><br>]])
  end
  table.insert(ret, [[</p>]])
  return table.concat(ret, "")
end

local snippets_to_table = function(ud)
  ret = {}
  while ldbw.step(ud) == sqlite3.SQLITE_ROW do
    table.insert(ret, {
      id = ldbw.column_int64(ud, 0),
      title = ldbw.column_text(ud, 1),
      content = ldbw.column_text(ud, 2),
      tags = ldbw.column_text(ud, 3),
      ["type"] = ldbw.column_text(ud, 4),
    })
  end
  return ret
end

local startswith  = function(String,Start)
   return string.sub(String,1,string.len(Start))==Start
end

function pages.index_snippets(s, path, message)
  return template.process([[
<!DOCTYPE html>
  <head>
    <meta charset="utf-8">
    <title>ynote</title>
    <link rel="stylesheet" href="/static/css/nb.css">
  </head>
  <body>
  {*menu*}
    <div class="main">
      <form id="search" accept-charset="UTF-8" action="/command" enctype="text/plain" method="post">
        {% if message ~= "" then %}
          <div>
            {{message}}
          </div>
        {% end %}
        <input name="command" id="search-input" placeholder="command">
        <input type="hidden" name="path" value="{*path*}">
      </form>
      {*snippets*}
    </div>
  </body>
</html>
]], {
  menu = pages.menu_bar {["new"] = true, ["path"] = path},
  path = path,
  snippets = snippets(s, port, path),
  message = message
})
end

function pages.index(ud, path, message)
  print("the message is ", message)
  local path = path ~= "" and path or httpaux.get_path(ud)
  if startswith(path, '/root/') then
    path = path:sub(string.len('/root/'))
  end
  if path == "/root" then path = "/" end
  dir = ldbw.path_descend(ud, path)
  q = [[
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
  group_concat(tags.name, ', ') AS tags,
  's' AS type
FROM snippets
LEFT JOIN snippet_to_tags
  ON snippets.id = snippet_to_tags.snippet_id
LEFT JOIN tags
  ON snippet_to_tags.tag_id = tags.id
WHERE snippets.dir = ?
GROUP BY snippets.id;]]
  ldbw.prepare(ud, q)
  local err = ldbw.bind_int64(ud, 1, dir)
  if err then
    print(err)
    return "server error", 500
  end
  err = ldbw.bind_int64(ud, 2, dir)
  if err then
    print(err)
    return "server error", 500
  end
  local port = httpaux.get_port(ud)
  local s = snippets_to_table(ud)
  return pages.index_snippets(s, path, message)
end

function pages.get_snippet(ud, id, edit_mode, snippet_dir, message)
  print("andd here edit is ", edit_mode)
  q = [[SELECT snippets.id as id,
                 title,]]
                 .. (edit_mode and " content," or "md2html(content),\n") ..
                 [[snippet_types.name AS type,
                 datetime(created, 'localtime') AS created,
                 datetime(updated, 'localtime') AS updated,
                 IFNULL(group_concat(tags.name, ', '), '')
     FROM snippets LEFT JOIN snippet_types
     ON snippets.type = snippet_types.id
                   LEFT JOIN snippet_to_tags ON snippets.id = snippet_to_tags.snippet_id
                   LEFT JOIN tags ON snippet_to_tags.tag_id = tags.id
          WHERE snippets.id=?]]
  print(ud)
  ldbw.prepare(ud, q)
  err = ldbw.bind_int64(ud, 1, id)
  if err then
    print(err)
    return "server error"
  end

  err = ldbw.step(ud)
  if err ~= sqlite3.SQLITE_ROW then
    return "not found"
  end

  local snippet_id = ldbw.column_int64(ud, 0)

  local params = {
    new = false,
    ["edit_mode"] = edit_mode,
    id = snippet_id,
    content = ldbw.column_text(ud, 2),
    title = ldbw.column_text(ud, 1),
    ["_type"] = ldbw.column_text(ud, 3),
    tags = ldbw.column_text(ud, 6),
    path = snippet_dir,
  }

  return tostring(snippet_view(params))
end

return pages
