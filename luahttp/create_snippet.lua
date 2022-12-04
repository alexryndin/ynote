local math = require('math')
local pages = require "pages"

return function (ud)
  t = httpaux.get_query(ud)
  method = httpaux.get_method(ud)
  edit = t["edit"] == "true" and true or false
  id = math.tointeger(t["id"]) or -1
  path = t["path"] or "/"
    print("path would be", path, t["path"])
  if edit == true and id == nil then
    return "id is required", 403
  end
  if method == "POST" then
    print("path would be", path, t["path"])
    id, err, http_code = ldbw.create_from_raw(ud, id, edit, path)
    if err then
      print(err)
      return err, http_code or 500
    end
    snippet_dir = ldbw.path_ascend(ud, id)
    return pages.get_snippet(ud, id, false, snippet_dir, "")
  else
    return pages.new_snippet(ud, "", path)
  end
end
