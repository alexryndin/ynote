#include <dbg.h>
#include <lauxlib.h>
#include <ldbw.h>
#include <sqlite3.h>
#include <ynote.h>
#include <bbstrlib.h>

struct LDBWCtx *LDBWCtx_create() {
  struct LDBWCtx *ret = calloc(1, sizeof(struct LDBWCtx));
  CHECK_MEM(ret);
  return ret;
error:
  return NULL;
}
void LDBWCtx_destroy(struct LDBWCtx *ldbwctx) {
  if (ldbwctx != NULL) {
    if (ldbwctx->stmt != NULL) {
      sqlite3_finalize(ldbwctx->stmt);
      ldbwctx->stmt = NULL;
    }
    free(ldbwctx);
  }
}

static int l_sqlite3_prepare(lua_State *lua) {
  int ret = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  luaL_checktype(lua, 2, LUA_TSTRING);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  sqlite3 *db = ynote_get_db_handle(luactx)->conn;
  struct LDBWCtx *ldbwctx = ynote_get_ldbwctx(luactx);
  const char *q = lua_tostring(lua, 2);
  if (ldbwctx->stmt != NULL) {
    sqlite3_finalize((sqlite3_stmt *)ldbwctx->stmt);
    ldbwctx->stmt = NULL;
  }
  if (sqlite3_prepare_v2(db, q, -1, &ldbwctx->stmt, NULL) != SQLITE_OK) {
    lua_pushfstring(lua, "db error: %s", sqlite3_errmsg(db));
    ret = 1;
    goto error;
  }

  lua_pushnil(lua);
  LOG_DEBUG("I GOT HERE!");
  return 1;
exit:
  return ret;
error:
  if (ldbwctx->stmt != NULL) {
    sqlite3_finalize((sqlite3_stmt *)ldbwctx->stmt);
    ldbwctx->stmt = NULL;
  }
  goto exit;
}

static int l_sqlite3_finalize(lua_State *lua) {
  int ret = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  sqlite3 *db = ynote_get_db_handle(luactx)->conn;
  struct LDBWCtx *ldbwctx = ynote_get_ldbwctx(luactx);
  if (ldbwctx->stmt != NULL) {
    sqlite3_finalize((sqlite3_stmt *)ldbwctx->stmt);
    ret = 0;
    goto exit;
  }
exit:
  return ret;
error:
  goto exit;
}

static int l_sqlite3_bind_int64(lua_State *lua) {
  int ret = 0;
  int err = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  luaL_checktype(lua, 2, LUA_TNUMBER);
  luaL_checktype(lua, 3, LUA_TNUMBER);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  sqlite3 *db = ynote_get_db_handle(luactx)->conn;
  struct LDBWCtx *ldbwctx = ynote_get_ldbwctx(luactx);
  sqlite3_stmt *stmt = ldbwctx->stmt;
  const sqlite_int64 i = lua_tointeger(lua, 2);
  const sqlite_int64 n = lua_tointeger(lua, 3);
  if ((err = sqlite3_bind_int64(stmt, i, n), err != SQLITE_OK)) {
    lua_pushfstring(lua, "db error: %s", sqlite3_errmsg(db));
    ret = 1;
    goto error;
  }
  // fallthrough
exit:
  return ret;
error:
  if (ldbwctx->stmt != NULL) {
    sqlite3_finalize((sqlite3_stmt *)ldbwctx->stmt);
    ldbwctx->stmt = NULL;
  }
  goto exit;
}
static int l_sqlite3_bind_text(lua_State *lua) {
  int ret = 0;
  int err = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  luaL_checktype(lua, 2, LUA_TNUMBER);
  luaL_checktype(lua, 3, LUA_TSTRING);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  sqlite3 *db = ynote_get_db_handle(luactx)->conn;
  struct LDBWCtx *ldbwctx = ynote_get_ldbwctx(luactx);
  sqlite3_stmt *stmt = ldbwctx->stmt;
  const sqlite_int64 i = lua_tointeger(lua, 2);
  const char *s = lua_tostring(lua, 3);
  if ((err = sqlite3_bind_text(stmt, i, s, -1, NULL), err != SQLITE_OK)) {
    lua_pushfstring(lua, "db error: %s", sqlite3_errmsg(db));
    ret = 1;
    goto error;
  }
  // fallthrough
exit:
  return ret;
error:
  if (ldbwctx->stmt != NULL) {
    sqlite3_finalize((sqlite3_stmt *)ldbwctx->stmt);
    ldbwctx->stmt = NULL;
  }
  goto exit;
}
static int l_path_descend(lua_State *lua) {
  int ret = 0;
  int err = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  luaL_checktype(lua, 2, LUA_TSTRING);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  DBWHandler *db = ynote_get_db_handle(luactx);
  struct LDBWCtx *ldbwctx = ynote_get_ldbwctx(luactx);
  sqlite3_stmt *stmt = ldbwctx->stmt;
  const char *path = lua_tostring(lua, 2);
  struct tagbstring tbpath = {0};
  btfromcstr(tbpath, path);
  int dir = dbw_path_descend(db, &tbpath, &err);
  if (err != DBW_OK) {
    lua_pushnil(lua);
    lua_pushstring(lua, "Couldn't get dir by path");
    ret = 2;
    goto exit;
  }
  lua_pushinteger(lua, dir);
  ret = 1;
  // fallthrough
exit:
  return ret;
}

static int l_path_ascend(lua_State *lua) {
  int ret = 0;
  int err = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  luaL_checktype(lua, 2, LUA_TNUMBER);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  DBWHandler *db = ynote_get_db_handle(luactx);
  struct LDBWCtx *ldbwctx = ynote_get_ldbwctx(luactx);
  sqlite3_stmt *stmt = ldbwctx->stmt;
  sqlite_int64 id = lua_tointeger(lua, 2);
  bstring s = dbw_snippet_path_ascend(db, id, &err);
  if (err != DBW_OK) {
    lua_pushnil(lua);
    lua_pushstring(lua, "Couldn't get dir by path");
    ret = 2;
    if (s != NULL) {
      bdestroy(s);
    }
    goto exit;
  }
  if (bdata(s) == NULL) {
    lua_pushnil(lua);
    lua_pushstring(lua, "DB error");
    ret = 2;
    goto exit;
  }
  lua_pushstring(lua, bdata(s));
  lua_pushnil(lua);
  ret = 2;
  if (s != NULL) {
    bdestroy(s);
  }
exit:
  return ret;
}

static int l_sqlite3_step(lua_State *lua) {
  int ret = 0;
  int err = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  sqlite3 *db = ynote_get_db_handle(luactx)->conn;
  struct LDBWCtx *ldbwctx = ynote_get_ldbwctx(luactx);
  sqlite3_stmt *stmt = ldbwctx->stmt;
  if ((err = sqlite3_step(stmt), err != SQLITE_DONE && err != SQLITE_ROW)) {
    lua_pushnil(lua);
    lua_pushfstring(lua, "db error: %s", sqlite3_errmsg(db));
    ret = 2;
    goto error;
  }
  lua_pushinteger(lua, err);
  lua_pushnil(lua);
  ret = 2;
  // fallthrough
exit:
  return ret;
error:
  if (ldbwctx->stmt != NULL) {
    sqlite3_finalize((sqlite3_stmt *)ldbwctx->stmt);
    ldbwctx->stmt = NULL;
  }
  goto exit;
}

static int l_sqlite3_column_text(lua_State *lua) {
  int ret = 0;
  int err = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  luaL_checktype(lua, 2, LUA_TNUMBER);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  sqlite3 *db = ynote_get_db_handle(luactx)->conn;
  struct LDBWCtx *ldbwctx = ynote_get_ldbwctx(luactx);
  sqlite3_stmt *stmt = ldbwctx->stmt;
  const sqlite_int64 i = lua_tointeger(lua, 2);
  const unsigned char *output = sqlite3_column_text(stmt, i);
  lua_pushfstring(lua, "%s", output);
  ret = 1;
  // fallthrough
exit:
  return ret;
error:
  if (ldbwctx->stmt != NULL) {
    sqlite3_finalize((sqlite3_stmt *)ldbwctx->stmt);
    ldbwctx->stmt = NULL;
  }
  goto exit;
}

static int l_sqlite3_column_int64(lua_State *lua) {
  int ret = 0;
  int err = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  luaL_checktype(lua, 2, LUA_TNUMBER);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  sqlite3 *db = ynote_get_db_handle(luactx)->conn;
  struct LDBWCtx *ldbwctx = ynote_get_ldbwctx(luactx);
  sqlite3_stmt *stmt = ldbwctx->stmt;
  const sqlite_int64 i = lua_tointeger(lua, 2);
  sqlite_int64 output = sqlite3_column_int64(stmt, i);
  lua_pushinteger(lua, output);
  ret = 1;
  // fallthrough
exit:
  return ret;
error:
  if (ldbwctx->stmt != NULL) {
    sqlite3_finalize((sqlite3_stmt *)ldbwctx->stmt);
    ldbwctx->stmt = NULL;
  }
  goto exit;
}


static int l_post_create_snippet_from_raw_response(lua_State *lua) {
  int ret = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  luaL_checktype(lua, 2, LUA_TNUMBER);
  luaL_checktype(lua, 3, LUA_TBOOLEAN);
  luaL_checktype(lua, 4, LUA_TSTRING);

  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  DBWHandler *db = ynote_get_db_handle(luactx);
  struct ConnInfo *ci = ynote_get_conn_info(luactx);
  const int border_len = 4;

  bstring tags = NULL;
  bstring title = NULL;
  bstring type = NULL;

  bstrListEmb *tagslist = NULL;
  bstrListEmb tagslist_noempty = {0};

  TBPairs *bp = NULL;

  struct tagbstring toml = {0};
  int err = 0;

  sqlite_int64 id = lua_tointeger(lua, 2);
  int edit = lua_toboolean(lua, 3);
  const char *path = lua_tostring(lua, 4);
  struct tagbstring tbpath = {0};
  btfromcstr(tbpath, path);

  CHECK(
      bfindreplace(
          ci->userp,
          &(struct tagbstring)bsStatic("\r\n"),
          &(struct tagbstring)bsStatic("\n"),
          0) == BSTR_OK,
      "Couldn't replace string");

  struct tagbstring body = *((bstring)ci->userp);
  LOG_DEBUG("got body %s", bdata(&body));
  CHECK(strstartswith(bdata(&body), "content="), "Wrong form");
  bmid2tbstr(body, &body, strlen("content="), blength(&body));

  if (!strstartswith(bdata(&body), "+++\n")) {
    goto wrong_header;
  }
  int toml_end = border_len;
  toml_end = binstr(&body, border_len, &(struct tagbstring)bsStatic("+++\n"));
  if (toml_end == BSTR_ERR && toml_end <= border_len) {
    goto wrong_header;
  }
  bmid2tbstr(toml, &body, border_len, toml_end - border_len);
  LOG_DEBUG(
      "toml to parse is %s, toml_end %d, border_len %d",
      bdata(&toml),
      toml_end,
      border_len);
  bp = bsplittopairs_noalloc(&toml);
  bmid2tbstr(body, &body, toml_end + border_len, blength(&body));

  title = TBPairs_get(bp, &BSS("title"));
  tags = TBPairs_get(bp, &BSS("tags"));
  type = TBPairs_get(bp, &BSS("type"));

  if (bdata(title) == NULL || bdata(type) == NULL) {
    lua_pushnil(lua);
    lua_pushfstring(lua, "title or type is missing");
    ret = 2;
    goto error;
  }

  if (bdata(tags) != NULL) {
    tagslist = bsplit_noalloc(tags, ',');
    CHECK(tagslist != NULL, "Couldn't split tags");
    for (size_t i = 0; i < tagslist->n; i++) {
      CHECK(tbtrimws(&tagslist->a[i]) == BSTR_OK, "Couldn't trim string");
      if (blength(&tagslist->a[i]) > 0) {
        rv_push(tagslist_noempty, tagslist->a[i], &err);
        CHECK(err == RV_ERR_OK, "Couldn't push to vec");
      }
    }
  }
  sqlite_int64 dir = 1;
  dir = dbw_path_descend(db, &tbpath, &err);
  if (err == DBW_ERR_NOT_FOUND) {
    lua_pushnil(lua);
    lua_pushstring(lua, "path not found");
    lua_pushinteger(lua, 403);
    ret = 3;
    goto error;
  }
  if (err != DBW_OK) {
    lua_pushnil(lua);
    lua_pushstring(lua, "server error");
    ret = 2;
    goto error;
  }

  // remove extra \n
  if (blength(&body) > 0 && bdata(&body)[blength(&body) - 1] == '\n') {
    bdata(&body)[--body.slen] = '\0';
  }

  if (edit) {
    id = dbw_edit_snippet(
        db, id, title, &body, type, &tagslist_noempty, 0, &err);
  } else {
    id = dbw_new_snippet(db, title, &body, type, &tagslist_noempty, dir, &err);
  }

  if (err != DBW_OK) {
    if (err == DBW_ERR_ALREADY_EXISTS) {
      lua_pushnil(lua);
      lua_pushstring(lua, "Snippet already exists");
      lua_pushinteger(lua, 403);
      ret = 3;
      goto error;
    }
    lua_pushnil(lua);
    lua_pushfstring(lua, "server error");
    ret = 2;
    goto error;
  }

  lua_pushinteger(lua, id);
  lua_pushnil(lua);
  ret = 2;
  // fallthrough
exit:
  if (bp != NULL) {
    TBPairs_destroy(bp);
  }
  if (tagslist != NULL) {
    bstrListEmb_destroy(tagslist);
  }
  rv_destroy(tagslist_noempty);
  return ret;
wrong_header:
  // if header is missing
  lua_pushnil(lua);
  lua_pushstring(lua, "header block is missing or malformed");
  lua_pushinteger(lua, 403);
  ret = 3;
  goto exit;
error:
  goto exit;
}

static const struct luaL_Reg ldbw[] = {
    {"prepare", l_sqlite3_prepare},
    {"finalize", l_sqlite3_finalize},
    {"bind_int64", l_sqlite3_bind_int64},
    {"bind_text", l_sqlite3_bind_text},
    {"step", l_sqlite3_step},
    {"column_text", l_sqlite3_column_text},
    {"column_int64", l_sqlite3_column_int64},
    {"path_descend", l_path_descend},
    {"path_ascend", l_path_ascend},
    {"create_from_raw", l_post_create_snippet_from_raw_response},
    {NULL, NULL}};

void register_ldbwlib(lua_State *lua) {
  luaL_newlib(lua, ldbw);
  lua_setglobal(lua, "ldbw");

  lua_newtable(lua);
  lua_pushstring(lua, "SQLITE_OK");
  lua_pushinteger(lua, SQLITE_OK);
  lua_settable(lua, -3);
  lua_pushstring(lua, "SQLITE_DONE");
  lua_pushinteger(lua, SQLITE_DONE);
  lua_settable(lua, -3);
  lua_pushstring(lua, "SQLITE_ROW");
  lua_pushinteger(lua, SQLITE_ROW);
  lua_settable(lua, -3);
  lua_setglobal(lua, "sqlite3");

  lua_newtable(lua);
  lua_pushstring(lua, "DBW_ERR_NOT_FOUND");
  lua_pushinteger(lua, DBW_ERR_NOT_FOUND);
  lua_settable(lua, -3);
  lua_pushstring(lua, "DBW_OK");
  lua_pushinteger(lua, DBW_OK);
  lua_settable(lua, -3);
  lua_pushstring(lua, "DBW_ERR_NOT_FOUND");
  lua_pushinteger(lua, DBW_ERR_NOT_FOUND);
  lua_settable(lua, -3);
  lua_pushstring(lua, "DBW_ERR_ALREADY_EXISTS");
  lua_pushinteger(lua, DBW_ERR_ALREADY_EXISTS);
  lua_settable(lua, -3);
  lua_setglobal(lua, "dbwerr");
}
