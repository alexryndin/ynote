local string = require "string"
local pages = require "pages"

local find = function(ud, cmd, cwd)
  local usage = "find <search string>"
  local cmd = string.gsub(cmd, "find%s+", "", 1)
  local parsed = {}

  for word, sub in string.gmatch(cmd, "(%w+)%s*=%s*\"(.-)\"") do
    if word == "tags" then
      local args = {}
      for sub in string.gmatch(sub, "([^,]+),?") do
        table.insert(args, sub)
      end
      parsed[word] = args
    else
      parsed[word] = sub
    end
  end

  q = {[[SELECT
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
WHERE 1 = 1
]]}

  local keys = {"title", "content"}
  for _, v in ipairs(keys) do
    if parsed[v] ~= nil then
      table.insert(q, "AND " .. v .. " like ? ")
    end
  end

  if parsed["tags"] ~= nil then
    table.insert(
      q,
      string.format(
        "AND tags.name in (%s) ",
        string.sub(
          string.rep(
            "?,",
            #parsed["tags"]
          ),
          1,
          2 * #parsed["tags"] - 1
        )
      )
    )
  end

  table.insert(q, "GROUP BY snippets.id ")

  q = table.concat(q, " ")

  local err = ldbw.prepare(ud, q)
  if err then print(err); return "server error" end


  local to_bind = 1

  for i, t in ipairs(keys) do
    if parsed[t] ~= nil then
      local err = ldbw.bind_text(ud, to_bind, parsed[t])
      to_bind = to_bind + 1
      if err then print(err); return "server error" end
    end
  end

  if parsed["tags"] ~= nil then
    for i = 1, #parsed["tags"] do
      local err = ldbw.bind_text(ud, to_bind, parsed["tags"][i])
  print(q)
      to_bind = to_bind + 1
      if err then print(err); return "server error" end
    end
  end

  local snippets = {}

  while ldbw.step(ud) == sqlite3.SQLITE_ROW do
    table.insert(snippets, {
      id = ldbw.column_int64(ud, 0),
      title = ldbw.column_text(ud, 1),
      content = ldbw.column_text(ud, 2),
      tags = ldbw.column_text(ud, 3),
      ["type"] = 's',
    })
  end

  return pages.index_snippets(snippets, path, message)
end

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
    print(line)
    key, value = line:match("(%S-)=(.*)")
    form[key] = value
    -- table.insert(tb, i) -- in case you want to store each separate element in a table
  end
  local path = form["path"] ~= nil and form["path"] or "/"
  if form['command'] ~= nil then
    local command_s = {}
    for split in form['command']:gmatch("%S+") do
      table.insert(command_s, split)
    end
    if command_s[1] == "mkdir" then
      local ret = mkdir(ud, command_s, path)
      return pages.index(ud, path, ret)
    elseif command_s[1] == "mv" then
      local ret = mv(ud, command_s, path)
      return pages.index(ud, path, ret)
    elseif command_s[1] == "find" then
      return find(ud, form['command'], path)
    end
  end
  return pages.index(ud, path, "ok")
 end
