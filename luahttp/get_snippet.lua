local pages = require "pages"

return function (ud)
  path = httpaux.get_path(ud)
  id = path:match(".*/(.*)")
  id = tonumber(id)
  return pages.get_snippet(ud, id, "")
end
