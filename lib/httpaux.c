#include <bbstrlib.h>
#include <bstrlib.h>
#include <httpaux.h>
#include <lauxlib.h>
#include <microhttpd.h>
#include <ynote.h>

static void UploadFile_destroy(struct UploadFile uf) {
  if (uf.field_name) {
    bdestroy(uf.field_name);
  }
  if (uf.name) {
    bdestroy(uf.name);
  }
  if (uf.path) {
    bdestroy(uf.path);
  }
  if (uf.mime) {
    bdestroy(uf.mime);
  }
  if (uf.fd) {
    close(uf.fd);
  }
  return;
}

void ConnInfo_destroy(struct ConnInfo *ci) {
  if (ci == NULL) {
    return;
  }
  if (ci->userp != NULL) {
    switch (ci->type) {
    case CIT_POST_RAW:
      bdestroy((bstring)(ci->userp));
      break;
    case CIT_POST_UPLOAD_FORM: {
      UploadFilesVec *v = ci->userp;
      for (size_t i = 0; i < v->n; i++) {
        struct UploadFile *uf = NULL;
        uf = rv_get(*v, i, NULL);
        if (uf != NULL) {
          UploadFile_destroy(*uf);
        } else {
          LOG_ERR("UploadFile must not be null here");
        }
      }
      rv_destroy(*(UploadFilesVec *)(ci->userp));
      free(ci->userp);
    } break;
    case CIT_POST_FIELDS: {
      BPairs *v = ci->userp;
      BPairs_destroy(v);
    }; break;
    }
  }
  if (ci->pp != NULL) {
    MHD_destroy_post_processor(ci->pp);
  }
  free(ci);
}

struct ConnInfo *ConnInfo_create(
    enum ConnInfoType cit,
    enum HTTPServerMethodName method_name,
    const char *method_str,
    enum HTTPServerCallName call_name,
    struct MHD_Connection *connection,
    const char *url,
    struct YNoteApp *app) {
  const char *header_str = NULL;
  bstrListEmb *split_header_line = NULL;
  struct ConnInfo *ci = calloc(1, sizeof(struct ConnInfo));
  CHECK_MEM(ci);
  ci->app = app;

  ci->api_call_name = call_name;
  ci->method_name = method_name;
  ci->method_str = method_str;

  ci->url = url;

  header_str =
      MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Accept");
  LOG_DEBUG("header str %s", header_str);
  if (header_str != NULL) {
    CHECK(
        (split_header_line = bcstrsplit_noalloc(header_str, ',')) != NULL,
        "Couldn't split line");
    if (split_header_line->n > 0 && !strncmp(
                                        bdatae(&split_header_line->a[0], ""),
                                        "text/html",
                                        strlen("text/html"))) {
      ci->at = HTTP_ACCEPT_TEXT_HTML;
    }
    bstrListEmb_destroy(split_header_line);
    split_header_line = NULL;
  }
  header_str =
      MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Content-Type");
  if (header_str != NULL) {
    CHECK(
        (split_header_line = bcstrsplit_noalloc(header_str, ';')) != NULL,
        "Couldn't split line");
    if (split_header_line->n > 0) {
      if (strstartswith(
              bdatae(&split_header_line->a[0], ""), "multipart/form-data")) {
        ci->ct = HTTP_CONTENT_MULTIPART_FORM_DATA;
      } else if (strstartswith(
                     bdatae(&split_header_line->a[0], ""),
                     "application/x-www-form-urlencoded")) {
        ci->ct = HTTP_CONTENT_FORM_URLENCODED;
      } else if (strstartswith(
                     bdatae(&split_header_line->a[0], ""),
                     "application/json")) {
        ci->ct = HTTP_CONTENT_APPLICATION_JSON;

      } else if (strstartswith(
                     bdatae(&split_header_line->a[0], ""), "text/plain")) {
        ci->ct = HTTP_CONTENT_TEXT_PLAIN;
      }
    }
    bstrListEmb_destroy(split_header_line);
    split_header_line = NULL;
  }
  if (method_name == HTTP_METHOD_POST) {
    if (call_name == RESTAPI_UPLOAD) {
      cit = CIT_POST_FILE_FORM;
    } else if (call_name == RESTAPI_NGINX_UPLOAD) {
      cit = CIT_POST_UPLOAD_FORM;
    } else if (call_name == RESTAPI_UNSORTED) {
      cit = CIT_POST_FIELDS;
    } else if (
        call_name == RESTAPI_CREATE_SNIPPET &&
        cit == HTTP_CONTENT_MULTIPART_FORM_DATA) {
      cit = CIT_POST_SNIPPET_FORM;
    } else {
      cit = CIT_POST_RAW;
    }
  } else {
    cit = CIT_OTHER;
  }
  switch (cit) {
  case CIT_POST_RAW: {
    CHECK((ci->userp = bfromcstr("")) != NULL, "Couldn't create con_cls");
  }; break;
  case CIT_POST_UPLOAD_FORM: {
    CHECK(
        (ci->userp = calloc(1, sizeof(UploadFilesVec))) != NULL,
        "Couldn't create con_cls");
  }; break;
  case CIT_POST_FILE_FORM: {
    CHECK(
        (ci->userp = calloc(1, sizeof(struct UploadFile))) != NULL,
        "Couldn't create con_cls");
  }; break;
  case CIT_POST_FIELDS: {
    CHECK((ci->userp = BPairs_create()) != NULL, "Couldn't create con_cls");
  }; break;
  default:
    break;
  }

  ci->type = cit;

exit:
  if (split_header_line != NULL) {
    bstrListEmb_destroy(split_header_line);
  }
  return ci;
error:
  if (ci != NULL) {
    ConnInfo_destroy(ci);
    ci = NULL;
  }
  goto exit;
}

static enum MHD_Result push_values_iterator(
    void *cls, enum MHD_ValueKind kind, const char *key, const char *value) {
  lua_State *lua = cls;
  lua_pushstring(lua, key);
  lua_pushstring(lua, value);
  lua_rawset(lua, -3);
  return MHD_YES;
}

static int l_get_path(lua_State *lua) {
  int ret = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  struct ConnInfo *ci =
      ynote_get_conn_info((struct LuaCtx *)lua_touserdata(lua, 1));
  lua_pushstring(lua, ci->url);
  return 1;
exit:
  return ret;
error:
  goto exit;
}

static int l_get_query(lua_State *lua) {
  int ret = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  struct ConnInfo *ci = ynote_get_conn_info(luactx);
  lua_newtable(lua);
  MHD_get_connection_values(
      luactx->conn, MHD_GET_ARGUMENT_KIND, push_values_iterator, lua);
  return 1;
}

static int l_get_method(lua_State *lua) {
  int ret = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  struct ConnInfo *ci = ynote_get_conn_info(luactx);
  lua_pushstring(lua, ci->method_str);
  return 1;
}

static int l_get_port(lua_State *lua) {
  int ret = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  int port = ynote_get_port(luactx);
  lua_pushinteger(lua, port);
  return 1;
}

static int l_get_body(lua_State *lua) {
  int ret = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  struct ConnInfo *ci =
      ynote_get_conn_info((struct LuaCtx *)lua_touserdata(lua, 1));
  if (ci->ct != CIT_POST_RAW || bdata((bstring)ci->userp) == NULL) {
    lua_pushnil(lua);
    ret = 1;
  }
  lua_pushstring(lua, bdata((bstring)ci->userp));
  ret = 1;
exit:
  return ret;
error:
  goto exit;
}
static int l_get_whole_form(lua_State *lua) {
  int ret = 0;
  luaL_checktype(lua, 1, LUA_TLIGHTUSERDATA);
  struct LuaCtx *luactx = (struct LuaCtx *)lua_touserdata(lua, 1);
  struct ConnInfo *ci = ynote_get_conn_info(luactx);
  BPairs *bps = ci->userp;
  lua_newtable(lua);
  for (size_t i = 0; i < bps->n; i++) {
    struct BPair *bp = rv_get(*bps, i, NULL);
    lua_pushstring(lua, bdata(bp->k));
    lua_pushstring(lua, bdata(bp->v));
    lua_rawset(lua, -3);
  }
  return 1;
}

static const struct luaL_Reg httpaux[] = {
    {"get_path", l_get_path},
    {"get_query", l_get_query},
    {"get_method", l_get_method},
    {"get_port", l_get_port},
    {"get_body", l_get_body},
    {"get_whole_form", l_get_whole_form},
    {NULL, NULL}};

void register_httpauxlib(lua_State *lua) {
  luaL_newlib(lua, httpaux);
  lua_setglobal(lua, "httpaux");
}
