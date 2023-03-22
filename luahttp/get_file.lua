local pages = require "pages"
return function()
  local path = httpaux.get_path(ud)
  local id = path:match(".*/(.*)")
  id = tonumber(id)
  return pages.get_file(ud, id, message)
  return "test"
end
