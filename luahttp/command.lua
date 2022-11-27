local string = require "string"
local pages = require "pages"

local mkdir = function(ud, argv, cwd)
  if #argv < 2 then
    return "usage: mkdir <dirname>"
  end
  local dir, err = ldbw.path_descend(ud, cwd)
  if err ~= nil then return err end
  local q = [[
INSERT INTO dirs (name, parent_id)
VALUES (?, ?)
RETURNING id
]]
  local err = ldbw.prepare(ud, q)
  if err then print(err); return "server error" end

  local err = ldbw.bind_text(ud, 1, argv[2])
  if err then print(err); return "server error" end

  local err = ldbw.bind_int64(ud, 2, dir)
  if err then print(err); return "server error" end

  local code, err = ldbw.step(ud)
  if code ~= sqlite3.SQLITE_ROW then print(err); return "server error" end

  return "dir created"
end

local mv = function(ud, argv, cwd)
  local usage = "usage: mv <d|s> <id> <dir>"
  if #argv < 4 then
    return usage
  end

  local from, err = ldbw.path_descend(ud, cwd)
  if err ~= nil then return err end

  local to, err = ldbw.path_descend(ud, argv[4])
  if err ~= nil then return err end

  local q = nil

  if argv[2] == 'd' then
  q = [[
UPDATE dirs
SET parent_id = ?
WHERE id = ?
]]
  elseif argv[2] == 's' then
  q = [[
UPDATE snippets
SET dir = ?
WHERE id = ?
]]
  else
    return usage
  end

  local err = ldbw.prepare(ud, q)
  if err then print(err); return "server error" end

  local err = ldbw.bind_int64(ud, 1, to)
  if err then print(err); return "server error" end

  local err = ldbw.bind_int64(ud, 2, tonumber(argv[3]))
  if err then print(err); return "server error" end

  local code, err = ldbw.step(ud)
  if codes ~= sqlite3.SQLITE_DONE then print(err); return "server error" end

  return "ok"
end

return function (ud)
  local form = {}
  local body = httpaux.get_body(ud)
  for line in body:gmatch("[^\n]+") do
    key, value = line:match("(%S-)%=(.+)")
    print(key, value)
    form[key] = value
    -- table.insert(tb, i) -- in case you want to store each separate element in a table
  end
  local path = form["path"] ~= nil and form["path"] or "/"
  if form['command'] ~= nil then
    local command_s = {}
    for split in form['command']:gmatch("%S+") do
      print(split)
      table.insert(command_s, split)
    end
    if command_s[1] == "mkdir" then
      local ret = mkdir(ud, command_s, path)
      return pages.index(ud, path, ret)
    elseif command_s[1] == "mv" then
      local ret = mv(ud, command_s, path)
      return pages.index(ud, path, ret)
    end

  end
  return pages.index(ud, path, "ok")
 end
