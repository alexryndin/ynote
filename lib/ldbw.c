#include <dbg.h>
#include <lauxlib.h>
#include <ldbw.h>
#include <sqlite3.h>
#include <ynote.h>

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
  int dir = dbw_path_descend(db, &tbpath, NULL);
  lua_pushinteger(lua, dir);
  ret = 1;
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

struct BPair {
  struct tagbstring k;
  struct tagbstring v;
};

typedef rvec_t(struct BPair) BPairs;

void BPairs_destroy(BPairs *bp) {
  if (bp != NULL) {
    rv_destroy(*bp);
    free(bp);
  }
}

static BPairs *bsplittopairs_noalloc(bstring s) {
  BPairs *ret = NULL;
  bstrListEmb *strsplit = NULL;
  int err = RV_ERR_OK;

  CHECK(s != NULL, "NULL string");

  ret = calloc(1, sizeof(BPairs));
  CHECK_MEM(ret);

  strsplit = bsplit_noalloc(s, '\n');
  CHECK(strsplit != NULL, "Couldn't split string");
  for (int i = 0; i < strsplit->n; i++) {
    struct BPair pair = {0};
    struct tagbstring k = {0};
    struct tagbstring v = {0};
    int delim_pos = 0;
    if (blength(&strsplit->a[i]) < 1) {
      continue;
    }
    delim_pos = binchr(&strsplit->a[i], 1, &(struct tagbstring)bsStatic("="));
    if (delim_pos != BSTR_ERR) {
      bmid2tbstr(k, &strsplit->a[i], 0, delim_pos);
      bmid2tbstr(v, &strsplit->a[i], delim_pos + 1, blength(&strsplit->a[i]));
      if (blength(&k) > 0) {
        CHECK(tbtrimws(&k) == BSTR_OK, "Couldn't trim string");
      }
      if (blength(&v) > 0) {
        CHECK(tbtrimws(&v) == BSTR_OK, "Couldn't trim string");
      }
      pair.k = k;
      pair.v = v;
      rv_push(*ret, pair, &err);
      CHECK(err == RV_ERR_OK, "Couldn't push value to vec");
    }
  }

exit:
  if (strsplit != NULL) {
    bstrListEmb_destroy(strsplit);
  }
  return ret;
error:
  if (ret != NULL) {
    rv_destroy(*ret);
    free(ret);
  }
  ret = NULL;
  goto exit;
}

static bstring BPairs_get(BPairs *bp, bstring key) {
  CHECK(key != NULL, "Null key");
  CHECK(bp != NULL, "Null bp");

  for (size_t i = 0; i < bp->n; i++) {
    if (!bstrcmp(&bp->a[i].k, key)) {
      return &bp->a[i].v;
    }
  }
error:
  return NULL;
}

static bstring BPairs_get_copy(BPairs *bp, bstring key, int *err) {
  bstring ret = NULL;
  ret = BPairs_get(bp, key);
  if (ret != NULL) {
    ret = bstrcpy(ret);
    CHECK_MEM(ret);
  }
error:
  if (ret != NULL) {
    bdestroy(ret);
  }
  return NULL;
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

  BPairs *bp = NULL;

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

  if (strstartswith(bdata(&body), "+++\n")) {
    int toml_end = border_len;
    toml_end = binstr(&body, border_len, &(struct tagbstring)bsStatic("+++\n"));
    if (toml_end != BSTR_ERR && toml_end > border_len) {
      bmid2tbstr(toml, &body, border_len, toml_end - border_len);
      LOG_DEBUG(
          "toml to parse is %s, toml_end %d, border_len %d",
          bdata(&toml),
          toml_end,
          border_len);
      bp = bsplittopairs_noalloc(&toml);
      bmid2tbstr(body, &body, toml_end + border_len, blength(&body));

#define _BP_GET_ENSURE(k)         \
  (k) = BPairs_get(bp, &BSS(#k)); \
  if ((k) != NULL) {              \
    (k) = bstrcpy(k);             \
    CHECK_MEM(k);                 \
  }

      _BP_GET_ENSURE(title);
      _BP_GET_ENSURE(tags);
      _BP_GET_ENSURE(type);

#undef _BP_GET_ENSURE

      if (title == NULL || type == NULL) {
        lua_pushnil(lua);
        lua_pushfstring(lua, "title or type is missing");
        ret = 2;
        goto error;
      }

      if (tags != NULL) {
        tagslist = bsplit_noalloc(tags, ',');
        CHECK(tagslist != NULL, "Couldn't split tags");
      }
      sqlite_int64 dir = 1;
      dir = dbw_path_descend(db, &tbpath, &err);
      if (err == DBW_ERR_NOT_FOUND) {
        lua_pushnil(lua);
        lua_pushstring(lua, "path not found");
        ret = 2;
        goto error;
      }
      if (err != DBW_OK) {
        lua_pushnil(lua);
        lua_pushstring(lua, "server error");
        ret = 2;
        goto error;
      }

      if (edit) {
        id = dbw_edit_snippet(db, id, title, &body, type, tagslist, 0, &err);
      } else {
        id = dbw_new_snippet(db, title, &body, type, tagslist, dir, &err);
      }
    }
  } else {
    // if header is missing
    lua_pushnil(lua);
    lua_pushstring(lua, "header block is missing");
    ret = 2;
  }
  lua_pushinteger(lua, id);
  lua_pushinteger(lua, err);
  ret = 2;
exit:
  if (bp != NULL) {
    BPairs_destroy(bp);
  }
  if (tagslist != NULL) {
    bstrListEmb_destroy(tagslist);
  }
  return ret;
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
