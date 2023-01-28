#include <assert.h>
#include <bbstrlib.h>
#include <bstrlib.h>
#include <curl/curl.h>
#include <dbg.h>
#include <dbw.h>
#include <event2/event.h>
#include <fcntl.h>
#include <httpaux.h>
#include <json-builder.h>
#include <json.h>
#include <lauxlib.h>
#include <ldbw.h>
#include <lualib.h>
#include <microhttpd.h>
#include <rvec.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <uuid/uuid.h>
#include <web_static.h>
#include <ynote.h>

#ifndef BUF_LEN
#define BUF_LEN 4096
#endif

#define MAX_UPLOAD_FILES   20
#define MAX_CONTENT_LENGTH 1 * 1024 * 1024 * 1024

#define STR_HELPER(x) #x
#define STR(x)        STR_HELPER(x)

#define USAGE "Usage: %s -c|--conf config path\n"

static const char *const getUpdatesUrl =
    "https://api.telegram.org/bot%s/getUpdates?timeout=%d&offset=%d";

static const char *const sendMessagelUrl =
    "https://api.telegram.org/bot%s/sendMessage?chat_id=%lld&text=%s";

#define HTML_BFORMATA(B, M, ...)                      \
  do {                                                \
    CHECK(                                            \
        bformata((B), (M), ##__VA_ARGS__) == BSTR_OK, \
        "Couldn't concat html part");                 \
  } while (0)

#define HTML_BCATSCTR(B, M)                                            \
  do {                                                                 \
    CHECK(bcatcstr((B), (M)) == BSTR_OK, "Couldn't concat html part"); \
  } while (0)

#define HTML_BCONCAT(B, M)                                            \
  do {                                                                \
    CHECK(bconcat((B), (M)) == BSTR_OK, "Couldn't concat html part"); \
  } while (0)

#define CHECK_ERR(A, M, ...)                                    \
  do {                                                          \
    if (!(A)) {                                                 \
      LOG_ERR(M, ##__VA_ARGS__);                                \
      static_msg = (struct tagbstring)bsStatic("Server Error"); \
      errno = 0;                                                \
      goto error;                                               \
    }                                                           \
  } while (0)

#define JSON_GET_ENSURE(json, json_t, i, t, M)               \
  do {                                                       \
    JSON_GET_ITEM((json), (json_t), (i));                    \
    CHECK_ERR((json_t) != NULL && (json_t)->type == (t), M); \
  } while (0)

#define JSON_GET_ENSURE2(json, json_t, i, t)                      \
  do {                                                            \
    JSON_GET_ITEM((json), (json_t), (i));                         \
    CHECK((json_t) != NULL && (json_t)->type == t, "Wrong json"); \
  } while (0)

#define PARSE_INT(func, num_str, num, rc)        \
  do {                                           \
    errno = 0;                                   \
    char *end;                                   \
    (num) = (func)((num_str), &end, 10);         \
    if ((num_str) == end) {                      \
      (rc) = 1;                                  \
      break;                                     \
    }                                            \
    const char range_error = errno == ERANGE;    \
    if (range_error) {                           \
      LOG_ERR("Range error while parsing int."); \
      rc = 2;                                    \
      errno = 0;                                 \
      break;                                     \
    }                                            \
                                                 \
  } while (0)

#define LUA_CONF_READ_STRING(dst, src)               \
  do {                                               \
    switch (lua_getglobal((app->lua), #src)) {       \
    case LUA_TNIL:                                   \
      LOG_ERR("Failed to read " #src);               \
      goto error;                                    \
    case LUA_TSTRING:                                \
      (dst) = bfromcstr(lua_tostring(app->lua, -1)); \
      CHECK((dst) != NULL, "Failed to read " #src);  \
      CHECK(blength((dst)) > 0, "Empty config");     \
      break;                                         \
    default:                                         \
      LOG_ERR(#src " must be a string");             \
      goto error;                                    \
    }                                                \
  } while (0);

#define LUA_CONF_READ_NUMBER(dst, src, _default) \
  do {                                           \
    switch (lua_getglobal((app->lua), #src)) {   \
    case LUA_TNIL:                               \
      (dst) = (_default);                        \
      break;                                     \
    case LUA_TNUMBER:                            \
      (dst) = lua_tonumber(app->lua, -1);        \
      break;                                     \
    default:                                     \
      LOG_ERR(#src " must be a number");         \
      goto error;                                \
    }                                            \
  } while (0);

#define LUA_CONF_READ_BOOL(dst, src, _default) \
  do {                                         \
    switch (lua_getglobal((app->lua), #src)) { \
    case LUA_TNIL:                             \
      (dst) = (_default);                      \
      break;                                   \
    case LUA_TBOOLEAN:                         \
      (dst) = lua_toboolean(app->lua, -1);     \
      break;                                   \
    default:                                   \
      LOG_ERR(#src " must be a number");       \
      goto error;                              \
    }                                          \
  } while (0);

enum TgState {
  TGS_ROOT,
  TGS_GET_BY_ID,
};

struct User {
  uint id;
  char allowed;
  enum TgState tg_state;
};

typedef rvec_t(struct User) Users;

struct UsersInfo {
  Users users;
};

struct YNoteApp {
  struct event_base *evbase;
  uint client_timeout;
  int port;
  uint updates_offset;
  struct UsersInfo users_info;
  DBWHandler *db_handle;
  CURLM *curl_multi;
  bstring tg_token;
  struct event *http_client_timer_event;
  int http_clients_running;
  bstring dbpath;
  bstring conf_path;
  lua_State *lua;
  int tg_bot_enabled;
};

static int validate_static_path(bstring path);

DBWHandler *ynote_get_db_handle(struct LuaCtx *luactx) {
  if (luactx == NULL) {
    return NULL;
  }
  return luactx->ci->app->db_handle;
}

static int ynote_lua_check_and_execute_file(
    struct MHD_Connection *conn, struct ConnInfo *ci, const char *path);

static int parse_cli_options(struct YNoteApp *app, int argc, char *argv[]) {
  int ret = 0;
  CHECK(app != NULL, "Null app");

  for (int i = 0; i < argc; i++) {
    if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--conf")) {
      i++;
      if (i >= argc) {
        SENTINEL("Wrong usage");
      }
      app->conf_path = bfromcstr(argv[i]);
      CHECK(app->conf_path != NULL, "Couldn't create string");
    }
  }
  if (app->conf_path == NULL) {
    app->conf_path = bfromcstr("./ynote.lua");
    CHECK(app->conf_path != NULL, "Couldn't create string");
  }

exit:
  return ret;
error:
  ret = -1;
  goto exit;
}

static void bdestroy_silent(bstring s) { bdestroy(s); }

static struct User *get_user(struct UsersInfo *ui, unsigned id) {
  CHECK(ui != NULL, "Null UsersInfo");
  for (size_t i = 0; i < ui->users.n; i++) {
    if (id == rv_get(ui->users, i, NULL)->id) {
      return rv_get(ui->users, i, NULL);
    }
  }
error:
  return NULL;
}

static int http_client_add_req(
    struct YNoteApp *app,
    CURL *easy,
    enum HTTPReqType,
    bstring url,
    void *data);

static int http_client_send_msg_req(
    struct YNoteApp *app, long long chat_id, bstring msg, char escape_msg);

static int http_client_get_updates_req(struct YNoteApp *app);

static int
tg_answer_snippet(struct YNoteApp *app, bstring str_id, long long to) {
  int rc = 0;
  int err = 0;
  struct tagbstring static_msg = {0};
  json_value *json = NULL;
  json_value *json_tmp = NULL;
  json_value *json_title = NULL;
  json_value *json_content = NULL;
  json_value *json_type = NULL;
  json_value *json_created = NULL;
  json_value *json_updated = NULL;
  bstring response_msg = NULL;
  bstring json_str = NULL;

  CHECK(app != NULL, "Null app");
  CHECK(bdata(str_id) != NULL, "Null str_id");

  sqlite_int64 id = 0;
  PARSE_INT(strtoll, bdatae(str_id, ""), id, err);
  if (err != 0) {
    static_msg = (struct tagbstring)bsStatic("Couldn't parse int");
    rc = -1;
    goto error;
  } else {
    json_str = dbw_get_snippet(app->db_handle, id, &err);
    switch (err) {
    case DBW_OK:
      break;
    case DBW_ERR_NOT_FOUND:
      static_msg = (struct tagbstring)bsStatic("Not found");
      goto exit;
      break;
    default:
      static_msg = (struct tagbstring)bsStatic("DB Error");
      rc = -1;
      goto error;
      break;
    }
  }
  if (bdata(json_str) == NULL) {
    static_msg = (struct tagbstring)bsStatic("DB Error");
    goto error;
  }
  json = json_parse(bdata(json_str), blength(json_str));
  if (json == NULL) {
    static_msg = (struct tagbstring)bsStatic("Server Error");
    goto error;
  }

  JSON_GET_ITEM(json, json_tmp, "status");
  CHECK_ERR(
      json_tmp != NULL && json_tmp->type == json_string &&
          !strcmp(json_tmp->u.string.ptr, "ok"),
      "Server Error");

  JSON_GET_ENSURE(json, json, "result", json_object, "Server Error");

  JSON_GET_ENSURE(json, json_title, "title", json_string, "Server Error");
  JSON_GET_ENSURE(json, json_content, "content", json_string, "Server Error");
  JSON_GET_ENSURE(json, json_type, "type", json_string, "Server Error");
  JSON_GET_ENSURE(json, json_created, "created", json_string, "Server Error");
  JSON_GET_ENSURE(json, json_updated, "updated", json_string, "Server Error");

  response_msg = bformat(
      "%s\n%s\n\n%s\n\n%s\n%s",
      json_title->u.string.ptr,
      json_type->u.string.ptr,
      json_content->u.string.ptr,
      json_created->u.string.ptr,
      json_updated->u.string.ptr);

  CHECK_ERR(response_msg != NULL, "Server Error");

exit:
  if (http_client_send_msg_req(
          app, to, response_msg ? response_msg : &static_msg, 1) != 0) {
    LOG_ERR("Couldn't respond to user");
  }

  if (response_msg != NULL) {
    bdestroy(response_msg);
  }
  if (json_str != NULL) {
    bdestroy(json_str);
  }
  if (json != NULL) {
    json_value_free(json);
  }
  return rc;
error:
  rc = -1;
  goto exit;
}

static void
http_client_process_res(struct YNoteApp *app, struct HTTPReqInfo *req) {
  json_value *json = NULL;
  json_value *json_tmp = NULL;
  json_value *json_msg = NULL;

  bstring json_str_res = NULL;

  json_value *json_from_db = NULL;

  struct bstrList *vargs = NULL;
  struct tagbstring static_msg = {0};
  bstring response_msg = NULL;

  CHECK(app != NULL, "Null app");

  CHECK(req != NULL, "Null req");
  CHECK(bdata(req->res) != NULL, "Null request data");

  LOG_DEBUG("http_client res: %s", bdata(req->res));

  json = json_parse(bdata(req->res), blength(req->res));
  CHECK(json != NULL, "Couldn't parse telegram response");
  CHECK(json->type == json_object, "Incorrect json");

  JSON_GET_ITEM(json, json_tmp, "ok");
  CHECK(json_tmp != NULL && json_tmp->type == json_boolean, "Bad response");

  // if not ok
  if (!(json_tmp->u.boolean)) {
    int error_code = 0;
    char *desc = "";
    JSON_GET_ITEM(json, json_tmp, "error_code");
    if (json_tmp != NULL && json_tmp->type == json_integer) {
      error_code = json_tmp->u.integer;
    }
    JSON_GET_ITEM(json, json_tmp, "description");
    if (json_tmp != NULL && json_tmp->type == json_string) {
      desc = json_tmp->u.string.ptr;
    }
    LOG_ERR("Bad response from telegram, code %d, error: %s", error_code, desc);
    goto error;
  }

  if (req->req_type == TG_SEND_MSG) {
    goto exit;
  }

  switch (req->req_type) {
  case TG_GET_UPDATES:
    JSON_GET_ITEM(json, json_tmp, "result");
    CHECK(json_tmp != NULL && json_tmp->type == json_array, "Bad response");

    if (json_tmp->u.array.length > 0) {
      int update_id = 0;
      long long from_id = 0;
      struct tagbstring text = {0};
      char *name = NULL;
      char *lastname = NULL;
      json_value *json_from = NULL;
      json_value **messages = json_tmp->u.array.values;

      const int msg_len = json_tmp->u.array.length;

      for (int i = 0; i < msg_len; i++) {
        json_msg = messages[i];
        CHECK(json_msg->type == json_object, "Bad response");
        JSON_GET_ITEM(json_msg, json_tmp, "update_id");
        CHECK(
            json_tmp != NULL && json_tmp->type == json_integer &&
                json_tmp->u.integer > 0,
            "Bad response");
        update_id = json_tmp->u.integer;
        app->updates_offset = update_id;

        JSON_GET_ITEM(json_msg, json_msg, "message");
        // As for now we can only process messages
        if (json_msg == NULL) {
          LOG_DEBUG("Got response without message");
          continue;
        }
        CHECK(json_msg->type == json_object, "Bad response");

        JSON_GET_ITEM(json_msg, json_tmp, "text");
        // Text is required
        if (json_tmp == NULL) {
          continue;
        }
        CHECK(json_tmp->type == json_string, "Bad response");
        btfromcstr(text, json_tmp->u.string.ptr);

        JSON_GET_ITEM(json_msg, json_from, "from");
        if (json_from == NULL) {
          continue;
        }
        CHECK(json_from->type == json_object, "Bad response");

        JSON_GET_ITEM(json_from, json_tmp, "id");
        CHECK(
            json_tmp != NULL && json_tmp->type == json_integer, "Bad response");
        from_id = json_tmp->u.integer;

        JSON_GET_ITEM(json_from, json_tmp, "first_name");
        if (json_tmp != NULL) {
          CHECK(json_tmp->type == json_string, "Bad response");
          name = json_tmp->u.string.ptr;
        };

        JSON_GET_ITEM(json_from, json_tmp, "last_name");
        if (json_tmp != NULL) {
          CHECK(json_tmp->type == json_string, "Bad response");
          lastname = json_tmp->u.string.ptr;
        };

        JSON_GET_ITEM(json_from, json_tmp, "is_bot");
        CHECK(
            json_tmp != NULL && json_tmp->type == json_boolean, "Bad response");
        LOG_DEBUG(
            "%s %s %s (id %lld) wrote %s",
            json_tmp->u.boolean ? "Bot" : "Human",
            name,
            lastname,
            from_id,
            bdata(&text));

        struct User *u;
        u = get_user(&app->users_info, from_id);

        if (u != NULL && u->allowed) {
          switch (u->tg_state) {
          case TGS_ROOT:

            vargs = bsplit(&text, ' ');
            if (vargs == NULL) {
              LOG_ERR("Could't split message");
              continue;
            }
            if (vargs->qty > 0) {
              if (!strcmp(bdatae(vargs->entry[0], ""), "/get_id")) {
                if (vargs->qty < 2) {
                  u->tg_state = TGS_GET_BY_ID;
                  static_msg = (struct tagbstring)bsStatic("Send me id please");
                  CHECK(
                      http_client_send_msg_req(app, from_id, &static_msg, 1) ==
                          0,
                      "Couldn't respond to user");
                } else {
                  u->tg_state = TGS_ROOT;
                  CHECK(
                      tg_answer_snippet(app, vargs->entry[1], from_id) == 0,
                      "Couldn't properly reply to user");
                }
              } else {
                u->tg_state = TGS_ROOT;
                static_msg = (struct tagbstring)bsStatic("Unknown command");
                CHECK(
                    http_client_send_msg_req(app, from_id, &static_msg, 1) == 0,
                    "Couldn't respond to user");
              }
            }
            break; // TGS_ROOT
          case TGS_GET_BY_ID:
            u->tg_state = TGS_ROOT;
            CHECK(
                tg_answer_snippet(app, &text, from_id) == 0,
                "Couldn't properly reply to user");
            break;
          }
        }
        bstrListDestroy(vargs);
        vargs = NULL;
        continue;
      }
    }
    break; // case TG_GET_UPDATES
  case TG_SEND_MSG:
    break;
  default:
    break;
  }

exit:
error:
  if (json != NULL) {
    json_value_free(json);
  }
  if (json_from_db != NULL) {
    json_value_free(json_from_db);
  }
  if (vargs != NULL) {
    bstrListDestroy(vargs);
  }
  if (json_str_res != NULL) {
    bdestroy(json_str_res);
  }
  if (response_msg != NULL) {
    bdestroy(response_msg);
  }
  return;
}

static void http_req_info_destroy(struct HTTPReqInfo *req_info) {
  if (req_info != NULL) {
    if (req_info->res != NULL) {
      bdestroy(req_info->res);
    }
    if (req_info->url != NULL) {
      bdestroy(req_info->url);
    }
    free(req_info);
  }
}

static void http_check_multi(struct YNoteApp *app) {
  CURLMsg *msg = NULL;
  int msgs_left = 0;
  struct HTTPReqInfo *req_info = NULL;
  CURL *easy = NULL;
  CURLcode res_code;
  LOG_DEBUG(
      "check_multi invoked, clients running = %d", app->http_clients_running);

  while ((msg = curl_multi_info_read(app->curl_multi, &msgs_left))) {
    if (msg->msg == CURLMSG_DONE) {
      LOG_DEBUG("Curl is done");
      easy = msg->easy_handle;
      res_code = msg->data.result;
      CHECK(
          curl_easy_getinfo(easy, CURLINFO_PRIVATE, (char **)&req_info) ==
              CURLE_OK,
          "Couldn't getinfo");
      if (res_code == CURLE_OK) {
        http_client_process_res(app, req_info);
      } else {
        LOG_ERR("Curl returned error: %s", curl_easy_strerror(res_code));
      }
      curl_multi_remove_handle(app->curl_multi, easy);
      curl_easy_cleanup(easy);
      if (req_info->req_type == TG_GET_UPDATES) {
        http_client_get_updates_req(app);
      }
      http_req_info_destroy(req_info);
      req_info = NULL;
    }
  }
  return;

error:
  if (app->curl_multi != NULL && easy != NULL) {
    curl_multi_remove_handle(app->curl_multi, easy);
  }
  if (req_info != NULL) {
    http_req_info_destroy(req_info);
  }
  return;
}

static struct HTTPReqInfo *http_req_info_new(void) {
  struct HTTPReqInfo *ret = NULL;
  ret = calloc(1, sizeof(struct HTTPReqInfo));
  CHECK_MEM(ret);
  ret->res = bfromcstr("");
  CHECK_MEM(ret->res);

  return ret;
error:
  if (ret != NULL) {
    if (ret->res != NULL) {
      bdestroy(ret->res);
    }
    free(ret);
  }
  return NULL;
}

static void http_client_sock_ctx_destroy(struct HTTPSockCtx *ctx) {
  if (ctx != NULL) {
    if (ctx->ev != NULL) {
      if (event_initialized(ctx->ev)) {
        event_del(ctx->ev);
      }
      event_free(ctx->ev);
    }
    free(ctx);
  }
  LOG_DEBUG("HTTPSockCtx destroyed");
}

static short action_to_event_type(int action) {
  return ((action & CURL_POLL_IN) ? EV_READ : 0) |
         ((action & CURL_POLL_OUT) ? EV_WRITE : 0) | EV_PERSIST;
}

static void
http_client_event_cb(evutil_socket_t sock, short event_type, void *userp) {
  struct YNoteApp *app = userp;

  CHECK(
      app != NULL && app->http_client_timer_event != NULL &&
          app->curl_multi != NULL,
      "Null app");
  int action = ((event_type & EV_READ) ? CURL_CSELECT_IN : 0) |
               ((event_type & EV_WRITE) ? CURL_CSELECT_OUT : 0);

  LOG_DEBUG("New event on sock %d, action  = %d", sock, action);

  CURLMcode rc = CURLM_OK;

  rc = curl_multi_socket_action(
      app->curl_multi, sock, action, &app->http_clients_running);

  CHECK(
      rc == CURLM_OK,
      "curl_multi_socket_action returned %s",
      curl_multi_strerror(rc));

  http_check_multi(app);
  return;
error:
  LOG_ERR("http_client_event_cb failed");
  return;
}

static void
http_client_timer_cb(evutil_socket_t socket, short events, void *userp) {
  struct YNoteApp *app = userp;
  (void)socket;
  (void)events;

  LOG_DEBUG("New timer");

  CHECK(app != NULL && app->http_client_timer_event != NULL, "Null app");

  CURLMcode rc = CURLM_OK;

  rc = curl_multi_socket_action(
      app->curl_multi, CURL_SOCKET_TIMEOUT, 0, &app->http_clients_running);

  // TODO: reinit mhandle if rc != CURLM_OK
  CHECK(
      rc == CURLM_OK,
      "curl_multi_socket_action returned %s",
      curl_multi_strerror(rc));

  http_check_multi(app);

  return;

error:
  LOG_ERR("http_client_timer_cb failed");
  return;
}

static struct HTTPSockCtx *
http_client_sock_ctx_new(curl_socket_t sock, int action, struct YNoteApp *app) {
  struct HTTPSockCtx *ctx = NULL;

  LOG_DEBUG("New socket %d, action %d", sock, action);

  CHECK(app != NULL && app->evbase != NULL, "Null app");
  CHECK_MEM(ctx = calloc(1, sizeof(struct HTTPSockCtx)));

  ctx->ev = event_new(
      app->evbase,
      sock,
      action_to_event_type(action),
      http_client_event_cb,
      app);
  CHECK(ctx->ev != NULL, "Couldn't create event");
  CHECK(event_add(ctx->ev, NULL) == 0, "Couldn't add event");
  return ctx;

error:
  if (ctx != NULL) {
    http_client_sock_ctx_destroy(ctx);
  }
  return NULL;
}

static size_t http_client_bstr_concat_cb(
    char *ptr, size_t size, size_t nmemb, struct HTTPReqInfo *req_info) {
  CHECK(
      bcatblk(req_info->res, ptr, size * nmemb) == BSTR_OK,
      "Buffer copy failed");
  LOG_DEBUG("Concat, bstr now is %s", bdata(req_info->res));
  return size * nmemb;
error:
  return 0;
}

static int http_client_add_req(
    struct YNoteApp *app,
    CURL *easy,
    enum HTTPReqType req_type,
    bstring url,
    void *data) {
  struct HTTPReqInfo *req_info = NULL;
  int rc = CURLE_OK;

  CHECK(
      app != NULL && app->curl_multi != NULL, "Null app or curl multi handle");

  req_info = http_req_info_new();
  CHECK(req_info != NULL, "Couldn't create HTTPReqInfo");

  req_info->req_type = req_type;

  if (url != NULL) {
    CHECK(bdata(url) != NULL && bdata(url)[blength(url)] == '\0', "Null url");
    req_info->url = url;
  } else {
    if (req_type == TG_GET_UPDATES) {
      req_info->url = bformat(
          getUpdatesUrl,
          bdata(app->tg_token),
          app->client_timeout,
          app->updates_offset + 1);
    } else if (req_type == TG_SEND_MSG) {
      req_info->url = bformat(
          sendMessagelUrl, bdata(app->tg_token), app->client_timeout, data);
    }
    CHECK(req_info->url != NULL, "Couldn't create request url");
  }

  if (easy == NULL) {
    easy = curl_easy_init();
    CHECK(easy != NULL, "Couldn't create curl easy handle");
  }

  CHECK(
      curl_easy_setopt(easy, CURLOPT_URL, bdata(req_info->url)) == CURLE_OK,
      "Couldn't set url");

  CHECK(
      curl_easy_setopt(
          easy, CURLOPT_WRITEFUNCTION, http_client_bstr_concat_cb) == CURLE_OK,
      "Couldn't set writefunction");
  CHECK(
      curl_easy_setopt(easy, CURLOPT_WRITEDATA, req_info) == CURLE_OK,
      "Couldn't set writedata");
  CHECK(
      curl_easy_setopt(easy, CURLOPT_PRIVATE, req_info) == CURLE_OK,
      "Couldn't set curlopt_private");

  rc = curl_multi_add_handle(app->curl_multi, easy);

  CHECK(rc == CURLE_OK, "Couldn't add easy handle");

  LOG_DEBUG("Added url %s", bdata(req_info->url));

  return 0;

error:
  if (url != NULL) {
    bdestroy(url);
  }
  if (req_info != NULL) {
    http_req_info_destroy(req_info);
  }
  if (easy != NULL) {
    curl_easy_cleanup(easy);
  }

  return -1;
}

static int http_client_get_updates_req(struct YNoteApp *app) {
  return http_client_add_req(app, NULL, TG_GET_UPDATES, NULL, NULL);
}

static int http_client_send_msg_req(
    struct YNoteApp *app, long long chat_id, bstring msg, char escape_msg) {
  CURL *easy = NULL;
  char *encoded_msg = NULL;

  easy = curl_easy_init();
  CHECK(easy != NULL, "Couldn't create curl easy handle");

  bstring url = NULL;

  CHECK(bdata(msg) != NULL, "Null msg");

  if (escape_msg) {
    encoded_msg = curl_easy_escape(easy, bdata(msg), blength(msg));
    CHECK(encoded_msg != NULL, "Couldn't escape url");
    url = bformat(sendMessagelUrl, bdata(app->tg_token), chat_id, encoded_msg);
    curl_free(encoded_msg);

  } else {
    url = bformat(sendMessagelUrl, bdata(app->tg_token), chat_id, msg);
  }

  CHECK(url != NULL, "Couldn't create url");
  return http_client_add_req(app, easy, TG_SEND_MSG, url, NULL);

error:
  if (url != NULL) {
    bdestroy(url);
  }
  if (easy != NULL) {
    curl_easy_cleanup(easy);
  }
  if (encoded_msg != NULL) {
    curl_free(encoded_msg);
  }
  return -1;
}

static int http_client_handle_socket(
    CURLM *chandle, curl_socket_t s, int action, void *userp, void *socketp) {

  LOG_DEBUG("New handle sock, action = %d", action);

  struct YNoteApp *app = userp;
  struct HTTPSockCtx *sock_ctx = socketp;

  CHECK(app != NULL, "Null app");

  switch (action) {
  case CURL_POLL_IN:
  case CURL_POLL_OUT:
  case CURL_POLL_INOUT:
    if (sock_ctx == NULL) {
      CHECK(
          (sock_ctx = http_client_sock_ctx_new(s, action, app)) != NULL,
          "Couldn't create sock_ctx");
      curl_multi_assign(app->curl_multi, s, sock_ctx);

    } else {
      CHECK(event_del(sock_ctx->ev) == 0, "Couldn't dev event");
      CHECK(
          event_assign(
              sock_ctx->ev,
              app->evbase,
              s,
              action_to_event_type(action),
              http_client_event_cb,
              app) == 0,
          "Couldn't assign event");
      CHECK(event_add(sock_ctx->ev, NULL) == 0, "Couldn't add event");
    }
    break;
  case CURL_POLL_REMOVE:
    if (sock_ctx != NULL) {
      http_client_sock_ctx_destroy(sock_ctx);
    }
    break;
  }
  return 0;
error:
  return -1;
}

static int http_client_start_timeout(
    CURLM *chandle, long timeout_ms, struct YNoteApp *app) {
  struct timeval timeout;
  (void)chandle;

  CHECK(app != NULL && app->http_client_timer_event != NULL, "Null app");

  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

  if (timeout_ms == -1) {
    event_del(app->http_client_timer_event);
  } else {
    event_add(app->http_client_timer_event, &timeout);
  }

  return 0;
error:
  return -1;
}

static int http_client_init(struct YNoteApp *app) {
  CHECK(app != NULL, "Null app");
  CHECK(
      curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK,
      "Couldn't initialize curl");
  CHECK(
      (app->curl_multi = curl_multi_init()) != NULL,
      "Couldn't initialize curl");
  curl_multi_setopt(
      app->curl_multi, CURLMOPT_SOCKETFUNCTION, http_client_handle_socket);
  curl_multi_setopt(app->curl_multi, CURLMOPT_SOCKETDATA, app);
  curl_multi_setopt(
      app->curl_multi, CURLMOPT_TIMERFUNCTION, http_client_start_timeout);
  curl_multi_setopt(app->curl_multi, CURLMOPT_TIMERDATA, app);
  return 0;
error:
  return -1;
}

static int read_config(struct YNoteApp *app, bstring path) {
  int rc = 0;
  FILE *conf = NULL;
  struct stat filestat;

  CHECK(path != NULL, "Null path");
  CHECK(app != NULL, "Null app");

  CHECK(
      stat(bdatae(path, ""), &filestat) == 0,
      "Couldn't get filestat for %s",
      bdata(path));

  CHECK(S_ISREG(filestat.st_mode), "Config is not a file");
  CHECK(filestat.st_size < 4 * 1024 * 1024L, "Conf file is too big");

  CHECK(
      (rc = luaL_loadfile(app->lua, bdata(path))) == LUA_OK,
      "Couldn't load config: %s",
      lua_tostring(app->lua, -1));
  CHECK(
      (rc = lua_pcall(app->lua, 0, 0, 0)) == LUA_OK,
      "Couldn't evaluate config");

  LUA_CONF_READ_BOOL(app->tg_bot_enabled, tg_bot_enabled, 1);
  if (app->tg_bot_enabled) {
    LUA_CONF_READ_STRING(app->tg_token, tg_token);
  }
  LUA_CONF_READ_STRING(app->dbpath, dbpath);

  LUA_CONF_READ_NUMBER(app->client_timeout, client_timeout, 30);

  LUA_CONF_READ_NUMBER(app->port, port, 8080);

  CHECK(app->port > 0 && app->port < 65535, "Wrong port number");

  rc = 0;

  rv_init(app->users_info.users);
  rv_push(
      app->users_info.users,
      ((struct User){.id = 332994181, .allowed = 1}),
      NULL);
  rv_push(
      app->users_info.users,
      ((struct User){.id = 5793397922, .allowed = 1}),
      NULL);
//  info.u.id = 332994181;
//  app->users_info.u.allowed = 1;
// fallthrough
exit:
  if (conf != NULL) {
    fclose(conf);
  }
  if (app->lua != NULL) {
    lua_settop(app->lua, 0);
  }
  return rc;
error:
  rc = -1;
  goto exit;
}

// Sigint sigterm handler
static void sigint_term_handler(int sig, short events, void *arg) {
  struct YNoteApp *app = arg;
  CHECK(app != NULL, "Null contenxt");
  CHECK(app->evbase != NULL, "Null base");
  CHECK(app->db_handle != NULL, "Null db_handle");

  (void)events;

  switch (sig) {
  case SIGTERM:
    LOG_INFO("Got sigterm");
    break;
  case SIGINT:
    LOG_INFO("Got sigint");
    break;
  default:
    LOG_ERR("Got unexpected signal");
  }
  event_base_loopexit(app->evbase, NULL);
error:
  return;
}

static void bstring_free_cb(const void *data, size_t datalen, void *extra) {
  (void)data;
  (void)datalen;
  bstring str = extra;
  if (str != NULL)
    bdestroy(str);
}

static bstring
json_api_delete_snippet(struct DBWHandler *db_handle, sqlite_int64 id) {
  int err = 0;
  bstring json_str_res = NULL;

  id = dbw_edit_snippet(db_handle, id, NULL, NULL, NULL, NULL, 1, &err);
  if (err == DBW_ERR_NOT_FOUND) {
    json_str_res = bformat("{\"status\": \"snippet %lld not found\"}", id);
    goto exit;
  } else {
    CHECK(err == DBW_OK, "Couldn't delete snippet");
  }
  json_str_res = bformat("{\"status\": \"ok\", \"id\": %lld}", id);

exit:
  return json_str_res;
error:
  if (json_str_res != NULL) {
    bdestroy(json_str_res);
  }
  return NULL;
}

static void ynote_app_destroy(struct YNoteApp *app) {
  CHECK(app != NULL, "Null app");
  if (app->db_handle != NULL) {
    dbw_close(app->db_handle);
  }
  if (app->curl_multi != NULL) {
    curl_multi_cleanup(app->curl_multi);
  }
  if (app->http_client_timer_event != NULL) {
    event_free(app->http_client_timer_event);
  }
  if (app->evbase != NULL) {
    event_base_free(app->evbase);
  }
  if (app->tg_token != NULL) {
    bdestroy(app->tg_token);
  }
  if (app->dbpath != NULL) {
    bdestroy(app->dbpath);
  }
  if (app->conf_path != NULL) {
    bdestroy(app->conf_path);
  }
  if (app->lua != NULL) {
    lua_close(app->lua);
  }
  rv_destroy(app->users_info.users);
  free(app);
error:
  return;
}

static struct YNoteApp *ynote_app_create(int argc, char *argv[]) {
  struct YNoteApp *ret = NULL;
  int err = 0;

  CHECK_MEM(ret = calloc(1, sizeof(struct YNoteApp)));

  if (parse_cli_options(ret, argc, argv) != 0) {
    printf(USAGE, argv[0]);
    goto error;
  }

  CHECK((ret->lua = luaL_newstate()) != NULL, "Couldn't create lua state");
  luaL_openlibs(ret->lua);
  register_ldbwlib(ret->lua);
  register_httpauxlib(ret->lua);

  CHECK(
      read_config(ret, ret->conf_path) == 0,
      "Couldn't read config %s",
      bdata(ret->conf_path));

  CHECK(
      (ret->evbase = event_base_new()) != NULL,
      "Couldn't initialize event base");
  CHECK(
      (ret->http_client_timer_event =
           evtimer_new(ret->evbase, http_client_timer_cb, ret)) != NULL,
      "Couldn't initialize timer");
  ret->db_handle = dbw_connect(DBW_SQLITE3, ret->dbpath, &err);
  CHECK(err == DBW_OK, "Couldn't connect to database");
  CHECK(ret->db_handle != NULL, "Couldn't connect to database");
  return ret;

error:
  if (ret != NULL) {
    ynote_app_destroy(ret);
  }
  return NULL;
}

static int iterate_post(
    void *coninfo_cls,
    enum MHD_ValueKind kind,
    const char *key,
    const char *filename,
    const char *content_type,
    const char *transfer_encoding,
    const char *data,
    uint64_t off,
    size_t size) {
  (void)kind;
  (void)*key;
  (void)*filename;
  (void)*content_type;
  (void)*transfer_encoding;
  (void)*data;
  (void)off;
  (void)size;
  (void)coninfo_cls;

  LOG_DEBUG("name %s", key);
  LOG_DEBUG("data %s", data);
  LOG_DEBUG("filename %s", filename);

  return MHD_YES;
}

static void request_completed(
    void *cls,
    struct MHD_Connection *connection,
    void **con_cls,
    enum MHD_RequestTerminationCode toe) {
  struct ConnInfo *con_info = *con_cls;

  LOG_DEBUG("request_completed called");

  if (NULL == con_info) {
    LOG_DEBUG("Null con_info");
    return;
  }

  ConnInfo_destroy(con_info);
  *con_cls = NULL;
}

typedef enum MHD_Result (*MHDPageHandler)(
    const void *cls, struct MHD_Connection *connection);

static enum MHD_Result post_nginx_upload_iterator(
    void *cls,
    enum MHD_ValueKind kind,
    const char *key,
    const char *filename,
    const char *content_type,
    const char *transfer_encoding,
    const char *data,
    uint64_t off,
    size_t size) {
  (void)kind;
  (void)*key;
  (void)*filename;
  (void)*content_type;
  (void)*transfer_encoding;
  (void)*data;
  (void)off;
  int ret = MHD_YES;
  LOG_DEBUG("name %s", key);
  LOG_DEBUG("data %s", data);
  LOG_DEBUG("filename %s", filename);
  LOG_DEBUG("cotent_type %s", content_type);
  LOG_DEBUG("transfer_encoding %s", transfer_encoding);
  LOG_DEBUG("kind %u", kind);
  LOG_DEBUG("offset %lu", off);
  LOG_DEBUG("size %zu", size);

  struct ConnInfo *ci = cls;
  struct UploadFile new = {0};
  UploadFilesVec *v = ci->userp;

  bstrListEmb *split_str = NULL;

  CHECK(v != NULL, "Null vector");

  if (strrchr(key, '.')) {
    struct tagbstring key_tb;
    btfromcstr(key_tb, key);
    split_str = bsplit_noalloc(&key_tb, '.');
    CHECK(split_str != NULL, "Couldn't split string");
    CHECK(rv_len(*split_str) == 2, "Wrong key");
    CHECK(blength(rv_get(*split_str, 0, NULL)) > 0, "Wrong key");
    CHECK(blength(rv_get(*split_str, 0, NULL)) > 0, "Wrong field_name");

    struct tagbstring value_tb;
    btfromcstr(value_tb, data);

    struct UploadFile *uf = NULL;
    for (size_t i = 0; i < v->n; i++) {
      uf = rv_get(*v, i, NULL);
      if (!bstrcmp(rv_get(*split_str, 0, NULL), uf->field_name)) {
        break;
      }
      uf = NULL;
    }
    if (!bstrcmp(
            rv_get(*split_str, 1, NULL),
            &(struct tagbstring)bsStatic("name"))) {
      new.name = bstrcpy(&value_tb);
      CHECK(new.name != NULL, "Couldn't copy string");
    } else if (!bstrcmp(
                   rv_get(*split_str, 1, NULL),
                   &(struct tagbstring)bsStatic("path"))) {
      new.path = bstrcpy(&value_tb);
      CHECK(new.path != NULL, "Couldn't copy string");
    } else {
      LOG_ERR("unknown field");
      goto exit;
    }
    if (uf == NULL) {
      new.field_name = bstrcpy(rv_get(*split_str, 0, NULL));
      CHECK(new.field_name != NULL, "Couldn't copy string");
      if (v->n >= MAX_UPLOAD_FILES) {
        ci->error = (struct tagbstring)bsStatic(
            "{\"status\": \"Too many files to upload. Max is " STR(
                MAX_UPLOAD_FILES) "\"}");
        goto exit;
      }
      rv_push(*v, new, NULL);
      new = (struct UploadFile){0};
    } else {
      if (new.name != NULL) {
        bdestroy(uf->name);
        uf->name = new.name;
        new.name = NULL;
      } else if (new.path != NULL) {
        bdestroy(uf->path);
        uf->path = new.path;
        new.path = NULL;
      }
    }
  }

exit:
  if (split_str != NULL) {
    bstrListEmb_destroy(split_str);
  }
  if (new.name != NULL) {
    bdestroy(new.name);
  }
  if (new.path != NULL) {
    bdestroy(new.path);
  }
  return ret;
error:
  ret = MHD_NO;
  goto exit;
}

static enum MHD_Result post_snippet_iterator(
    void *cls,
    enum MHD_ValueKind kind,
    const char *key,
    const char *filename,
    const char *content_type,
    const char *transfer_encoding,
    const char *data,
    uint64_t off,
    size_t size) {
  int ret = MHD_YES;
  return ret;
}
static enum MHD_Result post_upload_iterator(
    void *cls,
    enum MHD_ValueKind kind,
    const char *key,
    const char *filename,
    const char *content_type,
    const char *transfer_encoding,
    const char *data,
    uint64_t off,
    size_t size) {
  (void)kind;
  (void)*key;
  (void)*filename;
  (void)*content_type;
  (void)*transfer_encoding;
  (void)*data;
  (void)off;
  int ret = MHD_YES;
  // LOG_DEBUG("name %s", key);
  // LOG_DEBUG("data %s", data);
  // LOG_DEBUG("filename %s", filename);
  // LOG_DEBUG("cotent_type %s", content_type);
  // LOG_DEBUG("transfer_encoding %s", transfer_encoding);
  // LOG_DEBUG("kind %u", kind);
  // LOG_DEBUG("offset %lu", off);
  // LOG_DEBUG("size %zu", size);

  struct ConnInfo *ci = cls;
  struct UploadFile *uf = ci->userp;
  CHECK(uf != NULL, "Null UploadFile struct");

  if (!strcmp(key, "name")) {
    if (uf->name == NULL) {
      uf->name = blk2bstr(data, size);
      CHECK(uf->name != NULL, "Couldn't get field name");
      LOG_DEBUG("file name is %s", bdata(uf->name));
    } else {
      // we already have name, skip data...
      goto exit;
    }
  } else if (!strcmp(key, "file")) {
    if (off > 0 && uf->fd == 0) {
      ci->error = BSS("Cannot upload more than one file");
      goto exit;
    }
    if (uf->filename == NULL) {
      uf->filename = bfromcstr(filename);
    }
    if (uf->fd == 0) {
      uuid_t _bu = {0};
      char uuid[37];
      uuid_generate_random(_bu);
      uuid_unparse_lower(_bu, uuid);
      uf->path = bformat("uploads/tmp/%s", uuid);
      uf->fd = open(bdata(uf->path), O_WRONLY | O_APPEND | O_CREAT, 0644);
      CHECK(uf->fd > 0, "Couldn't create file");
    }
    while (size > 0) {
      int ret = write(uf->fd, data, size);
      CHECK(ret > 0, "Couldn't write to file");
      size -= ret;
    }
  } else {
    // unknown field, skip data...
    goto exit;
  }

exit:
  return ret;
error:
  ret = MHD_NO;
  goto exit;
}

static enum MHD_Result post_create_snippet_from_multipart_response(
    struct MHD_Connection *connection, struct ConnInfo *ci) {
  struct MHD_Response *response = NULL;
  int ret = MHD_NO;
  MHD_RESPONSE_WITH_TAGBSTRING(
      connection,
      MHD_HTTP_NOT_IMPLEMENTED,
      response,
      status_not_implemented,
      ret);
exit:
  return ret;
}

static enum MHD_Result post_create_snippet_from_json_response(
    struct MHD_Connection *connection,
    struct ConnInfo *ci,
    int edit,
    sqlite_int64 snippet_id) {
  const char *edit_str = NULL;
  struct MHD_Response *response = NULL;
  bstring body = (bstring)ci->userp;
  bstring json_str_res = NULL;
  int rc = 0;
  int ret = MHD_NO;

  json_str_res =
      json_api_create_snippet(ci->app->db_handle, body, snippet_id, edit, &rc);
  if (json_str_res == NULL) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, rc, response, status_server_error, ret);
  } else {
    MHD_RESPONSE_WITH_BSTRING(connection, rc, response, json_str_res, ret);
  }
exit:
  return ret;
}

enum filetype {
  FT_NONE = 0,
  FT_DIR,
  FT_FILE,
  FT_OTHER,
  FT_ERR = -1,
};

static int pathExists(const char *path) {
  struct stat info;
  if (stat(path, &info) != 0) {
    if (errno == ENOENT) {
      return FT_NONE;
    } else {
      // stat failed for some other reason
      LOG_ERR("stat failed");
      return FT_ERR;
    }
  }
  if (S_ISREG(info.st_mode)) {
    return FT_FILE;
  }
  if (S_ISDIR(info.st_mode)) {
    return FT_DIR;
  }
  return FT_OTHER;
}

static enum MHD_Result
post_upload_response(struct MHD_Connection *connection, struct ConnInfo *ci) {
  int ret;
  int err = 0;
  bstring response_string = NULL;
  bstring new_path = NULL;
  bstring dirname = NULL;
  struct MHD_Response *response = NULL;
  struct UploadFile *uf = ci->userp;
  struct stat filestat;

  if (uf->filename == NULL) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        BSS("file is required in field file"),
        ret);
  }

  CHECK(response_string = bfromcstr(""), "Couldn't create string");

  err = stat(bdatae(uf->path, ""), &filestat);
  if (err) {
    bformata(
        response_string, "error getting stat for file %s\n", bdata(uf->path));
  }
  if (!S_ISREG(filestat.st_mode)) {
    bformata(response_string, "file %s is not regular\n", bdata(uf->path));
  }

  const int uuid_l = 36;
  dirname =
      bformat("uploads/%.*s/", 2, &bdata(uf->path)[blength(uf->path) - uuid_l]);
  CHECK(dirname != NULL, "Couldn't create string");
  switch (pathExists(bdata(dirname))) {
  case FT_NONE:
    if (mkdir(bdata(dirname), 0755) != 0) {
      LOG_ERR("Couldn't create directory");
      goto error_500;
    };
    break;
  case FT_ERR:
    goto error_500;
  case FT_FILE:
    LOG_ERR("File %s already exists and is not a directory", bdata(dirname));
    goto error_500;
  default:
    break;
  }

  bstring filename;
  if (uf->name) {
    filename = uf->name;
  } else if (uf->filename) {
    filename = uf->filename;
  } else {
    LOG_ERR("Missing filename");
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        BSS("missing filename"),
        ret);
  }
  if (validate_static_path(filename)) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_BAD_REQUEST, response, BSS("wrong filename"), ret);
  }
  new_path = dbw_register_file(
      ci->app->db_handle, uf->path, filename, dirname, NULL, NULL, &err);
  if (err != DBW_OK) {
    bformata(response_string, "Couldn't register %s in DB\n", filename);
  } else {
    bformata(
        response_string,
        "%s ok, new path is %s\n",
        bdata(filename),
        bdata(new_path));
  }

  //  err = stat(bdatae(new_path, ""), &filestat);
  //  if (err == 0 || errno != ENOENT) {
  //    LOG_ERR(
  //        "destination file %s exists or error getting stat",
  //        bdata(new_path));
  //    bformata(response_string, "new path %s is wrong\n", bdata(new_path));
  //  }
  //  err = rename(bdata(uf->path), bdata(new_path));
  //  CHECK(err == 0, "Couldn't move file %s", bdata(uf->name));

  MHD_RESPONSE_WITH_BSTRING(
      connection, MHD_HTTP_OK, response, response_string, ret);

error_500:
  if (response_string != NULL) {
    bdestroy(response_string);
    response_string = NULL;
  }
  MHD_RESPONSE_WITH_TAGBSTRING(
      connection,
      MHD_HTTP_INTERNAL_SERVER_ERROR,
      response,
      status_server_error,
      ret);

error:
  ret = MHD_NO;
  goto exit;
exit:
  if (bdata(uf->path) && pathExists(bdata(uf->path)) == FT_FILE) {
    remove(bdata(uf->path));
  }
  if (new_path != NULL) {
    bdestroy(new_path);
  }
  if (dirname != NULL) {
    bdestroy(dirname);
  }

  return ret;
}

static enum MHD_Result mhd_api_handle_upload(
    struct MHD_Connection *connection,
    struct ConnInfo *ci,
    const char *upload_data,
    size_t *upload_data_size) {
  struct MHD_Response *response = NULL;
  int ret = MHD_NO;

  if (ci->method_name != HTTP_METHOD_POST) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        status_method_not_allowed,
        ret);
  }
  const char *value = MHD_lookup_connection_value(
      connection, MHD_HEADER_KIND, "Content-Length");
  if (value == NULL) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        BSS("Content length header is required"),
        ret);
  }
  {
    int rc = 0;
    uint32_t cl = 0;
    PARSE_INT(strtoll, value, cl, rc);
    if (rc != 0 || cl > MAX_CONTENT_LENGTH) {
      MHD_RESPONSE_WITH_TAGBSTRING(
          connection,
          MHD_HTTP_BAD_REQUEST,
          response,
          BSS("Content length too large"),
          ret);
    }
  }

  if (ci->invocations == 1) {
    CHECK(ci->pp == NULL, "Post process must be null on first invocation");
    if (ci->api_call_name == RESTAPI_NGINX_UPLOAD) {
      ci->pp = MHD_create_post_processor(
          connection, 1024, post_nginx_upload_iterator, ci);
    } else {
      ci->pp =
          MHD_create_post_processor(connection, 1024, post_upload_iterator, ci);
    }
    CHECK(ci->pp != NULL, "Couldn't create post processor");
    ret = MHD_YES;
    goto exit;
  }
  if (*upload_data_size != 0) {
    if (blength(&ci->error) > 0) {
      // skip data if we have error
      *upload_data_size = 0;
      ret = MHD_YES;
      goto exit;
    }
    if (MHD_post_process(ci->pp, upload_data, *upload_data_size) == MHD_NO) {
      (LOG_INFO("post processor returned MHD_NO"));
    }
    *upload_data_size = 0;
    ret = MHD_YES;
    goto exit;
  } else {
    if (blength(&ci->error) > 0) {
      MHD_RESPONSE_WITH_TAGBSTRING(
          connection, MHD_HTTP_BAD_REQUEST, response, ci->error, ret);
    }
    ret = post_upload_response(connection, ci);
    goto exit;
  }
exit:
  return ret;
error:
  ret = MHD_NO;
  goto exit;
}

static void mybdestroy(bstring s) {
  LOG_INFO("mybdestroy invoked");
  bdestroy(s);
}

static enum MHD_Result mhd_api_handle_find_snippets(
    struct MHD_Connection *connection, struct ConnInfo *ci) {
  struct MHD_Response *response = NULL;
  int ret = MHD_NO;
  int err = 0;
  struct tagbstring tbtags = {0};
  bstrListEmb *taglist = NULL;
  const char *tmp_cstr = NULL;
  bstring json_str_res = NULL;
  struct tagbstring snippet_type = {0};

  if (ci->method_name != HTTP_METHOD_GET) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        status_method_not_allowed,
        ret);
  }

  tmp_cstr =
      MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "tags");
  if (tmp_cstr != NULL) {
    if (0 == strlen(tmp_cstr)) {
      taglist = calloc(1, sizeof(bstrListEmb));
      CHECK(taglist != NULL, "Couldn't create empty taglist");
    } else {
      btfromcstr(tbtags, tmp_cstr);
      taglist = bsplit_noalloc(&tbtags, ',');
      CHECK(taglist != NULL, "Couldn't split tags string");
    }
  }
  tmp_cstr =
      MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "type");
  if (tmp_cstr != NULL && strcmp(tmp_cstr, "")) {
    btfromcstr(snippet_type, tmp_cstr);
  }
  json_str_res =
      dbw_find_snippets(ci->app->db_handle, NULL, &snippet_type, taglist, &err);
  if (json_str_res == NULL || err != DBW_OK) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_INTERNAL_SERVER_ERROR,
        response,
        status_server_error,
        ret);
  }
  MHD_RESPONSE_WITH_BSTRING(
      connection, MHD_HTTP_OK, response, json_str_res, ret);
exit:
  if (taglist != NULL) {
    bstrListEmb_destroy(taglist);
  }
  return ret;
error:
  ret = MHD_NO;
  goto exit;
}

static enum MHD_Result collect_raw_data(
    struct ConnInfo *ci,
    int *ret,
    const char *upload_data,
    size_t *upload_data_size) {

  bstring body = (bstring)ci->userp;
  if (ci->invocations == 1) {
    *ret = MHD_YES;
    goto exit;
  }
  if (*upload_data_size != 0) {
    if (blength(&ci->error) > 0) {
      // skip data if we have error
      *upload_data_size = 0;
      *ret = MHD_YES;
      goto exit;
    }
    if (bcatblk(body, upload_data, *upload_data_size) != BSTR_OK) {
      LOG_ERR("Couldn't read body");
      ci->error = status_server_error;
      *upload_data_size = 0;
      *ret = MHD_YES;
      goto exit;
    }
    *upload_data_size = 0;
    *ret = MHD_YES;
    goto exit;
  }
  if (bfindreplace(
          ci->userp,
          &(struct tagbstring)bsStatic("\r\n"),
          &(struct tagbstring)bsStatic("\n"),
          0) != BSTR_OK) {
    LOG_ERR("Couldn't replace string");
    ci->error = status_server_error;
    *ret = MHD_YES;
    goto exit;
  }
  return 0;
exit:
  return 1;
}

static enum MHD_Result mhd_api_handle_lua_with_post(
    struct MHD_Connection *connection,
    struct ConnInfo *ci,
    const char *upload_data,
    size_t *upload_data_size,
    const char *script) {
  struct MHD_Response *response = NULL;
  int ret = MHD_NO;
  bstring resp_str = NULL;
  lua_State *lua = ci->app->lua;
  int status = 200;
  bstring body = (bstring)ci->userp;

  switch (ci->method_name) {
  case HTTP_METHOD_POST:
    if (collect_raw_data(ci, &ret, upload_data, upload_data_size)) {
      goto exit;
    } else {
      if (blength(&ci->error) > 0) {
        MHD_RESPONSE_WITH_TAGBSTRING(
            connection,
            MHD_HTTP_INTERNAL_SERVER_ERROR,
            response,
            ci->error,
            ret);
      }
      LOG_DEBUG("got body %s", bdata(body));
    }
  case HTTP_METHOD_GET:
    break;
  default:
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        status_method_not_allowed,
        ret);
  }
  status = ynote_lua_check_and_execute_file(connection, ci, script);

  switch (status) {
  case -1:
    MHD_RESPONSE_REDIRECT_B(
        connection, MHD_HTTP_FOUND, &BSS("/static/404.html"), ret);
  case -2:
    goto error;
  defaut:
    break;
  };

  resp_str = blk2bstr(lua_tostring(lua, -3), lua_rawlen(lua, -3));
  MHD_RESPONSE_WITH_BSTRING_CT(
      connection, status, response, resp_str, ret, "text/html");

exit:
  return ret;
error:
  MHD_RESPONSE_WITH_TAGBSTRING(
      connection,
      MHD_HTTP_INTERNAL_SERVER_ERROR,
      response,
      status_server_error,
      ret);
}

static const struct tagbstring get_dirs_sql =
    bsStatic("select c.id as id, html_escape(c.name) as name from dirs as a "
             "join dir_to_dirs "
             "as b on a.id = b.dir_id join dirs as c on b.child_id = c.id  "
             " where a.id = ?");
static const struct tagbstring get_snippets_sql = bsStatic(
    "select snippets.id, html_escape(snippets.title), "
    "substr(snippets.content, "
    "1, 50) as content, group_concat(tags.name, ', ') from "
    "snippets left "
    "join snippet_to_tags on snippets.id = snippet_to_tags.snippet_id left "
    "join tags on snippet_to_tags.tag_id = tags.id where snippets.dir = ? "
    "group by snippets.id;");

static enum MHD_Result
mhd_handle_index(struct MHD_Connection *connection, struct ConnInfo *ci) {

  assert(strstartswith(ci->url, "/root"));

  struct MHD_Response *response = NULL;
  sqlite3_stmt *stmt = NULL;
  bstring response_string = NULL;

  sqlite_int64 dir = 1;
  struct tagbstring tbpath = {0};

  int err = 0;
  int ret = MHD_NO;

  if (ci->method_name != HTTP_METHOD_GET) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        status_method_not_allowed,
        ret);
  }

  btfromcstr(tbpath, ci->url);
  CHECK(blength(&tbpath) >= strlen("/root"), "Wrong path");
  bmid2tbstr(tbpath, &tbpath, strlen("/root"), blength(&tbpath));

  if (blength(&tbpath) > 0) {
    CHECK(
        (dir = dbw_path_descend(ci->app->db_handle, &tbpath, NULL)) > 0,
        "Wrong path");
  }

  response_string = bfromcstr("");
  CHECK(response_string != NULL, "Couldn't create string");
  HTML_BCONCAT(response_string, (bstring)&web_static_main_header);

  CHECK(
      sqlite3_prepare_v2(
          ci->app->db_handle->conn,
          bdata(&get_dirs_sql),
          blength(&get_dirs_sql) + 1,
          &stmt,
          NULL) == SQLITE_OK,
      "Couldn't prepare statement: %s",
      sqlite3_errmsg(ci->app->db_handle->conn));

  CHECK(
      sqlite3_bind_int64(stmt, 1, dir) == SQLITE_OK,
      "Couldn't bind parameter to statement");

  CHECK(
      (err = sqlite3_step(stmt), err == SQLITE_DONE || err == SQLITE_ROW),
      "Couldn't select snippets");

  HTML_BCATSCTR(
      response_string,
      "<div class=\"main\"> "
      "<p class=\"item-list\"> ");
  if (err == SQLITE_ROW) {
    do {
      HTML_BFORMATA(
          response_string,
          "<a rel=\"noopener noreferrer\" "
          "href=\"//localhost:%d%s/%s\" "
          "class=\"list-item\"> 📁:%lld <span class=\"muted\">[</span><span "
          "class=\"identifier\">%s</span><span class=\"muted\">]</span>"
          "</a><br>",
          ci->app->port,
          ci->url,
          sqlite3_column_text(stmt, 1),
          sqlite3_column_int64(stmt, 0),
          sqlite3_column_text(stmt, 1));

    } while (err = sqlite3_step(stmt), err == SQLITE_ROW);
  }

  CHECK(
      sqlite3_prepare_v2(
          ci->app->db_handle->conn,
          bdata(&get_snippets_sql),
          blength(&get_snippets_sql) + 1,
          &stmt,
          NULL) == SQLITE_OK,
      "Couldn't prepare statement: %s",
      sqlite3_errmsg(ci->app->db_handle->conn));

  CHECK(
      sqlite3_bind_int64(stmt, 1, dir) == SQLITE_OK,
      "Couldn't bind parameter to statement");

  CHECK(
      (err = sqlite3_step(stmt), err == SQLITE_DONE || err == SQLITE_ROW),
      "Couldn't select snippets");

  if (err == SQLITE_ROW) {
    do {
      HTML_BFORMATA(
          response_string,
          "<a rel=\"noopener noreferrer\" "
          "href=\"//localhost:%d/get_snippet/%lld\" "
          "class=\"list-item\"> ID:%lld <span class=\"muted\">[</span><span "
          "class=\"identifier\">%s</span><span class=\"muted\">]</span> %s "
          "</a><br>",
          ci->app->port,
          sqlite3_column_int64(stmt, 0),
          sqlite3_column_int64(stmt, 0),
          sqlite3_column_text(stmt, 1),
          sqlite3_column_text(stmt, 2));

    } while (err = sqlite3_step(stmt), err == SQLITE_ROW);
  }

  HTML_BCATSCTR(
      response_string,
      "</div> "
      "</p> ");

  CHECK(
      err == SQLITE_DONE,
      "DB error: %s",
      sqlite3_errmsg(ci->app->db_handle->conn));
  sqlite3_finalize(stmt);
  stmt = NULL;
  HTML_BCONCAT(response_string, (bstring)&web_static_main_footer);

  MHD_RESPONSE_WITH_BSTRING_CT(
      connection, MHD_HTTP_OK, response, response_string, ret, "text/html");

exit:
  if (stmt != NULL) {
    sqlite3_finalize(stmt);
  }
  return ret;
error:
  if (response_string != NULL) {
    bdestroy(response_string);
  }
  MHD_RESPONSE_WITH_TAGBSTRING(
      connection,
      MHD_HTTP_INTERNAL_SERVER_ERROR,
      response,
      status_server_error,
      ret);
}

static enum MHD_Result mhd_api_handle_delete_snippet(
    struct MHD_Connection *connection, struct ConnInfo *ci) {
  struct MHD_Response *response = NULL;
  int ret = MHD_NO;
  sqlite_int64 id = 0;
  int rc = 0;
  bstring json_str_res = NULL;

  if (ci->method_name != HTTP_METHOD_DELETE) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        status_method_not_allowed,
        ret);
  }
  const char *value =
      MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "id");
  if (value == NULL) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_BAD_REQUEST, response, status_id_required, ret);
  }
  PARSE_INT(strtoll, value, id, rc);
  if (rc == 1) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_BAD_REQUEST, response, status_id_required, ret);
  }
  json_str_res = json_api_delete_snippet(ci->app->db_handle, id);
  if (json_str_res == NULL) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_INTERNAL_SERVER_ERROR,
        response,
        status_server_error,
        ret);
  } else {
    MHD_RESPONSE_WITH_BSTRING(
        connection, MHD_HTTP_OK, response, json_str_res, ret);
  }
exit:
  return ret;
error:
  ret = MHD_NO;
  goto exit;
}

// Consumes json
static bstring json_snippet_to_html(bstring json, int edit) {
  bstring ret = NULL;
  json_value *parsed_snippet = NULL;
  json_value *json_result = NULL;
  json_value *json_tmp = NULL;
  json_value *json_id = NULL;

  CHECK(bdata(json) != NULL, "NULL json");

  ret = bfromcstr("");
  CHECK(ret != NULL, "Couldn't create string");

  parsed_snippet = json_parse(bdata(json), blength(json));
  CHECK(parsed_snippet != NULL, "Couldn't parse json");

  CHECK(
      parsed_snippet->type == json_object,
      "Wrong json %d",
      parsed_snippet->type);

  JSON_GET_ENSURE2(parsed_snippet, json_result, "result", json_object);
  JSON_GET_ENSURE2(json_result, json_tmp, "title", json_string);
  JSON_GET_ENSURE2(json_result, json_id, "id", json_integer);

  HTML_BCONCAT(ret, (bstring)&web_static_snippet_header);
  HTML_BCATSCTR(ret, "<div class=\"main\">");
  HTML_BFORMATA(ret, "<h1>%s</h1>", json_tmp->u.string.ptr);

  JSON_GET_ENSURE2(json_result, json_tmp, "content", json_string);

  if (edit) {
    HTML_BFORMATA(
        ret,
        "<form accept-charset=\"UTF-8\""
        " enctype=\"text/plain\""
        " action=\"/api/create_snippet?edit=true&id=%d\" "
        " method=\"post\">"
        "  <textarea "
        "    class=\"content\""
        "    cols=\"70\""
        "    id=\"content\""
        "    name=\"content\""
        "    rows=\"30\">"
        "%s%s",
        json_id->u.integer,
        json_tmp->u.string.ptr,
        "  </textarea>"
        "<br><br><input type=\"submit\" value=\"save\"> "
        "</form>");
  } else {
    HTML_BFORMATA(ret, "%s", json_tmp->u.string.ptr);
  }
  HTML_BCATSCTR(ret, "</div>");

  HTML_BCONCAT(ret, (bstring)&web_static_main_footer);

  // fallthrough
exit:
  if (json != NULL) {
    bdestroy(json);
  }
  if (parsed_snippet != NULL) {
    json_value_free(parsed_snippet);
  }

  return ret;
error:
  if (ret != NULL) {
    bdestroy(ret);
    ret = NULL;
  }
  goto exit;
}

// TODO: we need better path validation
static int validate_static_path(bstring path) {
  if (bdata(path) == NULL) {
    return -1;
  }
  if (binstr(path, 0, &BSS(".."))) {
    return 1;
  }
  if (binchr(path, 0, &BSS("/"))) {
    return 2;
  }
  if (blength(path) < 1 || blength(path) > 255) {
    return 3;
  }
  return 0;
}

static enum MHD_Result
mhd_api_handle_static(struct MHD_Connection *connection, struct ConnInfo *ci) {
  int ret = MHD_NO;
  int fd = 0;
  struct stat filestat;
  struct MHD_Response *response = NULL;
  struct tagbstring tburl = {0};
  struct tagbstring tbpath = {0};
  bstring path = NULL;

  btfromcstr(tburl, ci->url);
  if (blength(&tburl) < 1) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_BAD_REQUEST, response, status_wrong_path, ret);
  }
  if ((!strncmp(bdata(&tburl), "/static/", strlen("/static/")))) {
    bmid2tbstr(tbpath, &tburl, strlen("/static/"), blength(&tburl));
  } else {
    tbpath = tburl;
  }

  if (!validate_static_path(&tbpath)) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_BAD_REQUEST, response, status_wrong_path, ret);
  }

  path = bformat("static/www/%s", bdata(&tbpath));
  CHECK(path != NULL, "Null path");

  if (!validate_static_path(&tbpath)) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_BAD_REQUEST, response, status_wrong_path, ret);
  }

  LOG_DEBUG("trying to open %s", bdata(path));

  if (stat(bdatae(path, ""), &filestat) != 0) {
    LOG_ERR("Couldn't stat file %s", bdatae(path, ""));
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_BAD_REQUEST, response, status_couldnt_stat, ret);
  }
  if (!S_ISREG(filestat.st_mode)) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        status_wrong_file_type,
        ret);
  }

  fd = open(bdata(path), O_RDONLY);
  if (fd < 0) {
    errno = 0;
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_BAD_REQUEST, response, status_couldnt_open, ret);
  }

  (response) = MHD_create_response_from_fd((size_t)filestat.st_size, fd);
  MHD_del_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "");
  (ret) = MHD_queue_response(connection, MHD_HTTP_OK, response);
  MHD_destroy_response((response));
  goto exit;
exit:
  if (path != NULL) {
    bdestroy(path);
  }
  return ret;
error:
  MHD_RESPONSE_WITH_TAGBSTRING(
      connection,
      MHD_HTTP_INTERNAL_SERVER_ERROR,
      response,
      status_server_error,
      ret);
}

static const struct tagbstring get_snippet_sql = bsStatic(
    "      SELECT snippets.id as id,"
    "             html_escape(title),"
    "             md2html(content),"
    "             snippet_types.name AS type,"
    "             datetime(created, 'localtime') AS created,"
    "             datetime(updated, 'localtime') AS updated,"
    "             group_concat(tags.name, ', ') "
    " FROM " SNIPPETS_TABLE "               LEFT JOIN " SNIPPET_TYPES_TABLE
    " ON " SNIPPETS_TABLE "  .type = " SNIPPET_TYPES_TABLE ".id"
    "               LEFT JOIN " SNIPPET_TO_TAGS_TABLE " ON " SNIPPETS_TABLE
    "  .id = " SNIPPET_TO_TAGS_TABLE ".snippet_id"
    "               LEFT JOIN " TAGS_TABLE " ON " SNIPPET_TO_TAGS_TABLE
    "  .tag_id = " TAGS_TABLE ".id"
    "      WHERE " SNIPPETS_TABLE ".id=?");

static const struct tagbstring get_snippet_to_edit_sql = bsStatic(
    "      SELECT snippets.id as id,"
    "             title,"
    "             content,"
    "             snippet_types.name AS type,"
    "             datetime(created, 'localtime') AS created,"
    "             datetime(updated, 'localtime') AS updated,"
    "             group_concat(tags.name, ', ') "
    " FROM " SNIPPETS_TABLE "               LEFT JOIN " SNIPPET_TYPES_TABLE
    " ON " SNIPPETS_TABLE "  .type = " SNIPPET_TYPES_TABLE ".id"
    "               LEFT JOIN " SNIPPET_TO_TAGS_TABLE " ON " SNIPPETS_TABLE
    "  .id = " SNIPPET_TO_TAGS_TABLE ".snippet_id"
    "               LEFT JOIN " TAGS_TABLE " ON " SNIPPET_TO_TAGS_TABLE
    "  .tag_id = " TAGS_TABLE ".id"
    "      WHERE " SNIPPETS_TABLE ".id=?");

static enum MHD_Result
mhd_handle_get_snippet(struct MHD_Connection *connection, struct ConnInfo *ci) {
  struct MHD_Response *response = NULL;
  int ret = MHD_NO;
  sqlite_int64 id = 0;
  int rc = 0;
  int return_html = 0;
  const char *header_str = NULL;
  const char *edit_str = NULL;
  char edit = 0;
  int err = 0;
  sqlite3_stmt *stmt = NULL;
  bstring response_string = NULL;
  bstrListEmb *split_path = NULL;
  json_value *parsed_snippet = NULL;

  edit_str =
      MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "edit");
  if (edit_str != NULL && biseqcstrcaseless(&s_true, edit_str)) {
    edit = 1;
  }

  if (ci->method_name != HTTP_METHOD_GET) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        status_method_not_allowed,
        ret);
  }
  CHECK(
      (split_path = bcstrsplit_noalloc(ci->url, '/')) != NULL,
      "Couldn't split line");

  if (split_path->n != 3) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_BAD_REQUEST, response, status_wrong_path, ret);
  }

  PARSE_INT(strtoll, bdata(&split_path->a[2]), id, rc);
  if (rc == 1) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_BAD_REQUEST, response, status_id_required, ret);
  }
  bstrListEmb_destroy(split_path);
  split_path = NULL;

  bstring query = (bstring)(edit ? &get_snippet_to_edit_sql : &get_snippet_sql);

  CHECK(
      sqlite3_prepare_v2(
          ci->app->db_handle->conn,
          bdata(query),
          blength(query) + 1,
          &stmt,
          NULL) == SQLITE_OK,
      "Couldn't prepare statement: %s",
      sqlite3_errmsg(ci->app->db_handle->conn));

  CHECK(
      sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK,
      "Couldn't bind parameter to statement");

  CHECK(
      (err = sqlite3_step(stmt), err == SQLITE_DONE || err == SQLITE_ROW),
      "Couldn't select snippets");
  if (err == SQLITE_DONE) {

    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_NOT_FOUND,
        response,
        status_snippet_not_found,
        ret);
  }

  response_string = bfromcstr("");
  CHECK(response_string != NULL, "Couldn't create string");

  HTML_BCONCAT(response_string, (bstring)&web_static_snippet_header);
  HTML_BCATSCTR(response_string, "<div class=\"main\">");
  HTML_BFORMATA(response_string, "<h1>%s</h1>", sqlite3_column_text(stmt, 1));

  if (edit) {
    HTML_BFORMATA(
        response_string,
        "<form accept-charset=\"UTF-8\""
        " enctype=\"text/plain\""
        " action=\"/api/create_snippet?edit=true&id=%lld\" "
        " method=\"post\">"
        "  <textarea "
        "    class=\"content\""
        "    cols=\"70\""
        "    id=\"content\""
        "    name=\"content\""
        "    rows=\"30\">"
        "+++\n"
        "title = %s\n"
        "type = %s\n"
        "tags = %s\n"
        "+++\n"
        "%s%s",
        sqlite3_column_int64(stmt, 0),
        sqlite3_column_text(stmt, 1),
        sqlite3_column_text(stmt, 3),
        sqlite3_column_text(stmt, 6),
        sqlite3_column_text(stmt, 2),
        "  </textarea>"
        "<br><br><input type=\"submit\" value=\"save\"> "
        "</form>");
  } else {
    HTML_BFORMATA(response_string, "%s", sqlite3_column_text(stmt, 2));
  }
  HTML_BCATSCTR(response_string, "</div>");

  HTML_BCONCAT(response_string, (bstring)&web_static_main_footer);

  MHD_RESPONSE_WITH_BSTRING_CT(
      connection, MHD_HTTP_OK, response, response_string, ret, "text/html");

response_500:
  if (response_string != NULL) {
    bdestroy(response_string);
  }
  MHD_RESPONSE_WITH_TAGBSTRING(
      connection,
      MHD_HTTP_INTERNAL_SERVER_ERROR,
      response,
      status_server_error,
      ret);
exit:
  if (split_path != NULL) {
    bstrListEmb_destroy(split_path);
  }
  return ret;
error:
  goto response_500;
}

static enum MHD_Result mhd_api_handle_get_snippet(
    struct MHD_Connection *connection, struct ConnInfo *ci) {
  struct MHD_Response *response = NULL;
  int ret = MHD_NO;
  sqlite_int64 id = 0;
  int rc = 0;
  int return_html = 0;
  const char *header_str = NULL;
  const char *edit_str = NULL;
  char edit = 0;
  int ret_code = 200;
  bstring str_res = NULL;
  bstrListEmb *split_header_line = NULL;
  json_value *parsed_snippet = NULL;
  json_value *json_tmp = NULL;

  edit_str =
      MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "edit");
  if (edit_str != NULL && biseqcstrcaseless(&s_true, edit_str)) {
    edit = 1;
  }

  if (ci->at == HTTP_ACCEPT_TEXT_HTML) {
    return_html = 1;
  }
  LOG_DEBUG("accept %d", return_html);
  if (ci->method_name != HTTP_METHOD_GET) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        status_method_not_allowed,
        ret);
  }
  const char *value =
      MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "id");
  if (value == NULL) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_BAD_REQUEST, response, status_id_required, ret);
  }
  PARSE_INT(strtoll, value, id, rc);
  if (rc == 1) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_BAD_REQUEST, response, status_id_required, ret);
  }
  str_res = json_api_get_snippet(ci->app->db_handle, id, !edit, &ret_code);
  LOG_DEBUG("str_res is %s", bdata(str_res));
  if (str_res == NULL) {
    goto response_500;
  }
  if (return_html) {
    str_res = json_snippet_to_html(str_res, edit);
    if (str_res == NULL) {
      goto response_500;
    }
    MHD_RESPONSE_WITH_BSTRING_CT(
        connection, ret_code, response, str_res, ret, "text/html");
  } else {
    MHD_RESPONSE_WITH_BSTRING(connection, ret_code, response, str_res, ret);
  }

response_500:
  if (str_res != NULL) {
    bdestroy(str_res);
  }
  MHD_RESPONSE_WITH_TAGBSTRING(
      connection,
      MHD_HTTP_INTERNAL_SERVER_ERROR,
      response,
      status_server_error,
      ret);
exit:
  if (split_header_line != NULL) {
    bstrListEmb_destroy(split_header_line);
  }
  if (parsed_snippet != NULL) {
    json_value_free(parsed_snippet);
  }
  return ret;
error:
  goto response_500;
}

static void mhd_log(void *cls, const char *fm, va_list ap) {
  int ret;
  bstring b = NULL;

  (void)cls;

  bvalformata(ret, b = bfromcstr(""), fm, ap);

  if (BSTR_OK == ret) {
    if (bdata(b) != NULL && blength(b) > 0) {
      // remove extra newline
      bdata(b)[blength(b) - 1] = '\0';
    }
    LOG_ERR("%s", bdata(b));
  }
  bdestroy(b);
}
struct ConnInfo *ynote_get_conn_info(struct LuaCtx *lc) {
  return lc->ci;
}
int ynote_get_port(struct LuaCtx *lc) { return lc->ci->app->port; }
struct LDBWCtx *ynote_get_ldbwctx(struct LuaCtx *lc) {
  return lc->ldbwctx;
}

static int ynote_lua_check_and_execute_file(
    struct MHD_Connection *conn, struct ConnInfo *ci, const char *path) {
  int status = 200;
  lua_State *lua = ci->app->lua;
  struct LuaCtx luactx = {0};
  struct stat filestat;
  struct LDBWCtx *ldbwctx = NULL;

  if (stat(path, &filestat) != 0) {
    if (errno == ENOENT) {
      return -1;
    }
    LOG_ERR("Couldn't stat file %s", path);
    return -2;
  }

  if (!S_ISREG(filestat.st_mode)) {
    return -1;
  }

  CHECK(luaL_loadfile(lua, path) == 0, "Couldn't load lua file");
  CHECK(
      lua_pcall(lua, 0, 1, 0) == 0,
      "Couldn't execute lua file: %s",
      lua_tostring(lua, -1));

  ldbwctx = LDBWCtx_create();
  CHECK(ldbwctx != NULL, "Couldn't create database context");

  luactx.ci = ci;
  luactx.ldbwctx = ldbwctx;
  luactx.conn = conn;

  lua_pushlightuserdata(lua, &luactx);
  CHECK(
      lua_pcall(lua, 1, 3, 0) == 0,
      "Couldn't execute lua file: %s",
      lua_tostring(lua, -1));

  status = lua_tonumber(lua, -2);
  if (!status) {
    status = MHD_HTTP_OK;
  }
  LOG_DEBUG("Lua returned status %d", status);

  // Fallthrough
exit:
  if (ldbwctx != NULL) {
    LDBWCtx_destroy(ldbwctx);
  }
  return status;
error:
  status = -2;
  goto exit;
}

static enum MHD_Result mhd_handle_lua(
    struct MHD_Connection *connection,
    struct ConnInfo *ci,
    const char *upload_data,
    size_t *upload_data_size) {
  struct MHD_Response *response = NULL;
  struct tagbstring tbpath = {0};
  struct stat filestat;
  struct LDBWCtx *ldbwctx = NULL;
  int status = MHD_HTTP_OK;
  int ret = MHD_NO;
  bstring resp_str = NULL;
  bstring path = NULL;
  lua_State *lua = ci->app->lua;

  ldbwctx = LDBWCtx_create();
  CHECK(ldbwctx != NULL, "Couldn't create database context");

  if (ci->api_call_name != HTTP_PATH_INDEX) {
    btfromcstr(tbpath, ci->url);
    if (!validate_static_path(&tbpath)) {
      MHD_RESPONSE_WITH_TAGBSTRING(
          connection, MHD_HTTP_BAD_REQUEST, response, status_wrong_path, ret);
    }
    if (!bstrstartswith(&tbpath, &BSS("/lua/"))) {
      MHD_RESPONSE_WITH_TAGBSTRING(
          connection, MHD_HTTP_BAD_REQUEST, response, status_wrong_path, ret);
    }

    bmid2tbstr(tbpath, &tbpath, strlen("/lua/"), blength(&tbpath));

    if (bstrendswith(&tbpath, &BSS(".lua"))) {
      path = bformat("luahttp/%s", bdata(&tbpath));
    } else if (bstrstartswith(&tbpath, &BSS("get_snippet/"))) {
      path = bformat("luahttp/%s", "get_snippet.lua");
    } else {
      MHD_RESPONSE_WITH_TAGBSTRING(
          connection, MHD_HTTP_BAD_REQUEST, response, status_wrong_path, ret);
    }
  } else {
    path = bformat("luahttp/%s", "index.lua");
  }
  CHECK(path != NULL, "Null path");
  status = ynote_lua_check_and_execute_file(connection, ci, bdata(path));

  switch (status) {
  case -1:
    MHD_RESPONSE_REDIRECT_B(
        connection, MHD_HTTP_FOUND, &BSS("/static/404.html"), ret);
  case -2:
    goto error;
  defaut:
    break;
  };

  resp_str = blk2bstr(lua_tostring(lua, -3), lua_rawlen(lua, -3));
  CHECK(resp_str != NULL, "Couldn't copy body");

  // Caution -- here we manually create response, don't use CHECK()
  // to prevent double response creation and thus memory leakage
  response = MHD_create_response_from_buffer_with_free_callback_cls(
      blength(resp_str),
      bdata(resp_str),
      (MHD_ContentReaderFreeCallback)bdestroy_silent,
      resp_str);

  MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html");

  int table = lua_gettop(lua);

  if (lua_istable(lua, table)) {
    lua_pushnil(lua);
    while (lua_next(lua, table) != 0) {
      if (!lua_isstring(lua, -2)) {
        continue;
      }
      const char *key = lua_tostring(lua, -2);
      const char *value = lua_tostring(lua, -1);
      MHD_add_response_header(response, key, value);
      lua_pop(lua, 1);
    }
  }

  ret = MHD_queue_response(connection, status, response);
  MHD_destroy_response(response);
  goto exit;

exit:
  if (ldbwctx != NULL) {
    LDBWCtx_destroy(ldbwctx);
  }
  lua_settop(lua, 0);
  if (path != NULL) {
    bdestroy(path);
  }

  return ret;
error:
  MHD_RESPONSE_WITH_TAGBSTRING(
      connection,
      MHD_HTTP_INTERNAL_SERVER_ERROR,
      response,
      status_server_error,
      ret);
}

static int mhd_handler(
    struct YNoteApp *app,
    struct MHD_Connection *connection,
    const char *url,
    const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls) {
  (void)version;
  int ret = MHD_NO;
  struct MHD_Response *response = NULL;
  struct ConnInfo *ci = NULL;

  if (*con_cls == NULL) {
    enum HTTPServerCallName call_name;
    enum HTTPServerMethodName method_name;

    if (!strcmp(url, "/command")) {
      call_name = RESTAPI_COMMAND;
    } else if (!strcmp(url, "/upload")) {
      call_name = RESTAPI_UPLOAD;
    } else if (!strcmp(url, "/api/get_snippet")) {
      call_name = RESTAPI_GET_SNIPPET;
    } else if (!strcmp(url, "/api/create_snippet")) {
      call_name = RESTAPI_CREATE_SNIPPET;
    } else if (!strcmp(url, "/api/find_snippets")) {
      call_name = RESTAPI_FIND_SNIPPETS;
    } else if (!strcmp(url, "/api/delete_snippet")) {
      call_name = RESTAPI_DELETE_SNIPPET;
    } else if (!strcmp(url, "/api/upload")) {
      call_name = RESTAPI_NGINX_UPLOAD;
    } else if (strstartswith(url, "/static/")) {
      call_name = RESTAPI_STATIC;
    } else if (strstartswith(url, "/get_snippet/")) {
      call_name = HTTP_PATH_GET_SNIPPET;
    } else if (!strcmp(url, "/root") || strstartswith(url, "/root/")) {
      call_name = HTTP_PATH_INDEX;
    } else if (!strcmp(url, "/lua") || strstartswith(url, "/lua/")) {
      call_name = HTTP_PATH_LUA;
    } else {
      call_name = RESTAPI_UNKNOWN;
    }

    if (!strcmp(method, "GET")) {
      method_name = HTTP_METHOD_GET;
    } else if (!strcmp(method, "POST")) {
      method_name = HTTP_METHOD_POST;
    } else if (!strcmp(method, "DELETE")) {
      method_name = HTTP_METHOD_DELETE;
    } else if (!strcmp(method, "PUT")) {
      method_name = HTTP_METHOD_PUT;
    } else {
      method_name = HTTP_METHOD_OTHER;
    }

    enum ConnInfoType cit = 0;
    ci = ConnInfo_create(
        cit, method_name, method, call_name, connection, url, app);
    CHECK(ci != NULL, "Couldn't create con_cls");
    *con_cls = ci;
  }

  ci = *con_cls;
  ci->invocations++;

  switch (ci->api_call_name) {
  case RESTAPI_COMMAND:
    ret = mhd_api_handle_lua_with_post(
        connection, ci, upload_data, upload_data_size, "luahttp/command.lua");
    goto exit;
  case RESTAPI_GET_SNIPPET:
    ret = mhd_api_handle_get_snippet(connection, ci);
    goto exit;
  case HTTP_PATH_GET_SNIPPET:
    ret = mhd_handle_get_snippet(connection, ci);
    goto exit;
  case RESTAPI_CREATE_SNIPPET:
    ret = mhd_api_handle_lua_with_post(
        connection,
        ci,
        upload_data,
        upload_data_size,
        "luahttp/create_snippet.lua");
    goto exit;
  case RESTAPI_FIND_SNIPPETS:
    ret = mhd_api_handle_find_snippets(connection, ci);
    goto exit;
  case RESTAPI_DELETE_SNIPPET:
    ret = mhd_api_handle_delete_snippet(connection, ci);
    goto exit;
  case RESTAPI_STATIC:
    ret = mhd_api_handle_static(connection, ci);
    goto exit;
  case RESTAPI_UPLOAD:
  case RESTAPI_NGINX_UPLOAD:
    ret = mhd_api_handle_upload(connection, ci, upload_data, upload_data_size);
    goto exit;
  case HTTP_PATH_LUA:
    ret = mhd_handle_lua(connection, ci, upload_data, upload_data_size);
    goto exit;
  case HTTP_PATH_INDEX:
    switch (ci->at) {
    case HTTP_ACCEPT_TEXT_HTML:
      // ret = mhd_handle_index(connection, ci);
      ret = mhd_handle_lua(connection, ci, upload_data, upload_data_size);
      goto exit;
    default:
    case HTTP_ACCEPT_APPLICATION_JSON:
    case HTTP_ACCEPT_OTHER:
      MHD_RESPONSE_WITH_TAGBSTRING(
          connection, MHD_HTTP_OK, response, status_ok, ret);
    }
  case RESTAPI_UNKNOWN:
  default:
    MHD_RESPONSE_REDIRECT_TB(connection, MHD_HTTP_FOUND, &BSS("/root"), ret);
  }
exit:
  LOG_DEBUG("ret is %d, uri is %s, method %s", ret, url, method);
  return ret;
error:
  if (ci != NULL) {
    ConnInfo_destroy(ci);
    ci = NULL;
    if (*con_cls != NULL) {
      *con_cls = NULL;
    }
  }
  MHD_RESPONSE_WITH_TAGBSTRING(
      connection, 500, response, status_server_error, ret);
  goto exit;
}

int main(int argc, char *argv[]) {
  int rc = 0;
  rc = 0;
  struct YNoteApp *app = NULL;
  struct event *intterm_event = NULL;

  if (argc != 3) {
    goto usage;
  }

  app = ynote_app_create(argc, argv);
  CHECK(app != NULL, "Couldn't create app");

  if (app->tg_bot_enabled) {
    CHECK(http_client_init(app) == 0, "Couldn't initialize http client");

    http_client_get_updates_req(app);
  }

  CHECK(
      (intterm_event = evsignal_new(
           app->evbase, SIGTERM, sigint_term_handler, app)) != NULL,
      "Couldn't create sigterm handler");

  CHECK(
      event_add(intterm_event, NULL) == 0,
      "Couldn't add sigterm handler to event loop");

  CHECK(
      (intterm_event =
           evsignal_new(app->evbase, SIGINT, sigint_term_handler, app)) != NULL,
      "Couldn't create sigint handler");

  CHECK(
      event_add(intterm_event, NULL) == 0,
      "Couldn't add sigint handler to event loop");

  struct MHD_Daemon *daemon;

  daemon = MHD_start_daemon(
      MHD_USE_EPOLL_INTERNAL_THREAD | MHD_USE_ERROR_LOG,
      app->port,
      NULL,
      NULL,
      (MHD_AccessHandlerCallback)mhd_handler,
      app,
      MHD_OPTION_EXTERNAL_LOGGER,
      (MHD_LogCallback)mhd_log,
      NULL,
      MHD_OPTION_NOTIFY_COMPLETED,
      (MHD_RequestCompletedCallback)request_completed,
      NULL,
      MHD_OPTION_END);

  LOG_INFO("Server started, port %d", app->port);

  event_base_dispatch(app->evbase);

exit:
  if (app != NULL) {
    ynote_app_destroy(app);
  }
  curl_global_cleanup();
  MHD_stop_daemon(daemon);

  return rc;
error:
  rc = 1;
  goto exit;
usage:
  printf(USAGE, argv[0]);
  goto error;
}
