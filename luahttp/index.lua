local tags = require "luahttp/tags"
local string = require "string"
local pages = require "pages"


--function snippets()
--  local snippets = snippets
--  tr()
--  tr()
--  return table(tr)
--end
--<a rel="noopener noreferrer" href="//localhost:8080/root//codes" class="list-item"> 📁:2 <span class="muted">[</span><span class="identifier">codes</span><span class="muted">]</span></a>

return function (ud)
  print("ud is ", ud)
  return pages.index(ud, "")
end
