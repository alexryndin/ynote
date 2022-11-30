local pages = require "pages"

return function (ud)
  local path = httpaux.get_path(ud)
  local id = path:match(".*/(.*)")
  id = tonumber(id)
  local query = httpaux.get_query(ud)
  local edit_mode = query["edit_mode"] == "true" and true or false
  local snippet_dir = ldbw.path_ascend(ud, id)
  print(snippet_dir)

  print(ldbw.column_text(ud, 7))
  return pages.get_snippet(ud, id, edit_mode, snippet_dir, "")
end
