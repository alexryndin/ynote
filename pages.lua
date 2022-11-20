local tags = require "luahttp/tags"
local string = require "string"

pages = {}

local snippet = tags(function(p)
  _edit = p["edit"]
  _content = p["content"]
  _type = p["_type"]
  _tags = p["tags"]
  _title = p["title"]
  _id = p["id"]
  _path = p["path"]
  _new = p["new"]

  print("id is ", _id)

  if _edit then
    content = [[+++
title = %s
type =  %s
tags = %s
+++
%s]]


    content = string.format(content, _title, _type, _tags, _content)

    if _new then
      action = "/api/create_snippet?path=" .. _path
    else
      action = "/api/create_snippet?id=" .. _id .. "&edit=" .. (_edit and "true" or "false")
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


local snippet_view = tags(function(p)
  return html (
    head (
        meta { charset = "utf-8" },
        title "ynote",
        link {rel = "stylesheet", href = "/static/css/nb.css"}
    ),
    body (
      div {class = "main"} (
        h1 (p["title"]),
        snippet(p)
      )
    )
  )
end)

function pages.new_snippet(ud, message, path)
  params = {
    edit = true,
    id = nil,
    content = [[]],
    title = "New snippet",
    ["_type"] = "plain",
    tags = "",
    ["path"] = path,
    new = true,
  }
  return tostring(snippet_view(params))
end

function pages.get_snippet(ud, id, message)
  query = httpaux.get_query(ud)
  is_edit = query["edit"] == "true" and true or false
  print(query["edit"])
  print("andd here edit is ", is_edit)
  q = [[SELECT snippets.id as id,
                 title,]]
                 .. (is_edit and " content," or "md2html(content),\n") ..
                 [[snippet_types.name AS type,
                 datetime(created, 'localtime') AS created,
                 datetime(updated, 'localtime') AS updated,
                 IFNULL(group_concat(tags.name, ', '), '')
     FROM snippets LEFT JOIN snippet_types
     ON snippets.type = snippet_types.id
                   LEFT JOIN snippet_to_tags ON snippets.id = snippet_to_tags.snippet_id
                   LEFT JOIN tags ON snippet_to_tags.tag_id = tags.id
          WHERE snippets.id=?]]
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

  test = "test"

  snippet_id = ldbw.column_int64(ud, 0)

  params = {
    edit = is_edit,
    id = snippet_id,
    content = ldbw.column_text(ud, 2),
    title = ldbw.column_text(ud, 1),
    ["_type"] = ldbw.column_text(ud, 3),
    tags = ldbw.column_text(ud, 6)
  }

  print(params["tags"])
  print(ldbw.column_text(ud, 7))

  return tostring(snippet_view(params))

end

return pages
