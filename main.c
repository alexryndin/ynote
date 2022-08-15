#include <bbstrlib.h>
#include <bstrlib.h>
#include <curl/curl.h>
#include <dbg.h>
#include <dbw.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <json-builder.h>
#include <json.h>
#include <lauxlib.h>
#include <lualib.h>
#include <md4c-html.h>
#include <md4c.h>
#include <microhttpd.h>
#include <rvec.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>

#ifndef BUF_LEN
#define BUF_LEN 4096
#endif

#define MAX_UPLOAD_FILES 20

#define STR_HELPER(x) #x
#define STR(x)        STR_HELPER(x)

#define USAGE "Usage: %s -c|--conf config path\n"

static struct tagbstring s_true = bsStatic("true");

static const struct tagbstring status_ok = bsStatic("{\"status\": \"ok\"}");

static const struct tagbstring status_method_not_allowed =
    bsStatic("{\"status\": \"error\", \"msg\": \"method not allowed\"}");

static const struct tagbstring status_server_error =
    bsStatic("{\"status\": \"error\", \"msg\": \"server error\"}");

static const struct tagbstring status_id_required =
    bsStatic("{\"status\": \"error\", \"msg\": \"id required\"}");

static const struct tagbstring status_snippet_not_found =
    bsStatic("{\"status\": \"error\", \"msg\": \"snippet not found\"}");

static const char *const getUpdatesUrl =
    "https://api.telegram.org/bot%s/getUpdates?timeout=%d&offset=%d";

static const char *const sendMessagelUrl =
    "https://api.telegram.org/bot%s/sendMessage?chat_id=%d&text=%s";

#define MHD_RESPONSE_WITH_BSTRING(connection, status, response, s, ret)  \
  do {                                                                   \
    (response) = MHD_create_response_from_buffer_with_free_callback_cls( \
        blength((s)),                                                    \
        bdata((s)),                                                      \
        (MHD_ContentReaderFreeCallback)bdestroy,                         \
        (s));                                                            \
    MHD_add_response_header(                                             \
        response, MHD_HTTP_HEADER_CONTENT_ENCODING, "application/json"); \
    (ret) = MHD_queue_response((connection), (status), (response));      \
    MHD_destroy_response((response));                                    \
    goto exit;                                                           \
                                                                         \
  } while (0)

#define MHD_RESPONSE_WITH_TAGBSTRING(connection, status, response, s, ret) \
  do {                                                                     \
    (response) = MHD_create_response_from_buffer(                          \
        blength(&(s)), bdata(&(s)), MHD_RESPMEM_PERSISTENT);               \
    MHD_add_response_header(                                               \
        response, MHD_HTTP_HEADER_CONTENT_ENCODING, "application/json");   \
    (ret) = MHD_queue_response((connection), (status), (response));        \
    MHD_destroy_response((response));                                      \
    goto exit;                                                             \
                                                                           \
  } while (0)

#define INTERNAL_ERROR_HANDLE                        \
  error:                                             \
  rc = 500;                                          \
  reason = "Internal Server Error";                  \
  if (resp != NULL) {                                \
    evbuffer_drain(resp, evbuffer_get_length(resp)); \
    if (evbuffer_add_printf(resp, "500") <= 0) {     \
      evbuffer_free(resp);                           \
      resp = NULL;                                   \
    };                                               \
  }                                                  \
  goto exit

#define BAD_REQ_HANDLE                                                         \
  bad_request:                                                                 \
  rc = 403;                                                                    \
  reason = "Bad Request";                                                      \
  bad_request_msg = bad_request_msg == NULL ? "Bad request" : bad_request_msg; \
  CHECK(                                                                       \
      evbuffer_add_printf(                                                     \
          resp, "{\"status\": \"error\", \"msg\": \"%s\"}", bad_request_msg) > \
          0,                                                                   \
      "Couldn't append to response buffer");                                   \
  goto exit

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

#define JSON_GET_ITEM(json, obj, index)                        \
  do {                                                         \
                                                               \
    json_value *ret = NULL;                                    \
    if ((json) == NULL) {                                      \
      obj = NULL;                                              \
      break;                                                   \
    }                                                          \
    if (json->type != json_object) {                           \
      obj = NULL;                                              \
      break;                                                   \
    }                                                          \
                                                               \
    for (unsigned int i = 0; i < json->u.object.length; ++i) { \
      if (!strcmp(json->u.object.values[i].name, index)) {     \
        ret = (json->u).object.values[i].value;                \
        break;                                                 \
      }                                                        \
    }                                                          \
    obj = ret;                                                 \
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

enum TgState {
  TGS_ROOT,
  TGS_GET_BY_ID,
};
struct User {
  uint id;
  char allowed;
  enum TgState tg_state;
};

struct UsersInfo {
  struct User u;
};

struct YNoteApp {
  struct event_base *evbase;
  uint client_timeout;
  int port;
  int mhd_port;
  uint updates_offset;
  struct UsersInfo users_info;
  void *db_handle;
  CURLM *curl_multi;
  bstring tg_token;
  struct event *http_client_timer_event;
  int http_clients_running;
  bstring dbpath;
  bstring conf_path;
  lua_State *lua;
  int tg_bot_enabled;
};

int parse_cli_options(struct YNoteApp *app, int argc, char *argv[]) {
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

struct User *get_user(struct UsersInfo *ui, unsigned id) {
  CHECK(ui != NULL, "Null UsersInfo");
  if (id == ui->u.id)
    return &ui->u;
error:
  return NULL;
}

enum HTTPReqType {
  TG_GET_UPDATES,
  TG_SEND_MSG,
};

enum HTTPServerRestCallName {
  RESTAPI_UNKNOWN = 0,
  RESTAPI_CREATE_SNIPPET = 1,
  RESTAPI_GET_SNIPPET,
  RESTAPI_DELETE_SNIPPET,
  RESTAPI_FIND_SNIPPETS,
  RESTAPI_UPLOAD,
};

enum HTTPServerMethodName {
  RESTMETHOD_OTHER = 0,
  RESTMETHOD_POST,
  RESTMETHOD_GET,
  RESTMETHOD_PUT,
  RESTMETHOD_DELETE,
};

struct HTTPReqInfo {
  enum HTTPReqType req_type;
  bstring res;
  bstring url;
};

struct HTTPSockCtx {
  struct event *ev;
  curl_socket_t sock;
};

static int http_client_add_req(
    struct YNoteApp *app,
    CURL *easy,
    enum HTTPReqType,
    bstring url,
    void *data);

static int http_client_send_msg_req(
    struct YNoteApp *app, unsigned chat_id, bstring msg, char escape_msg);

static int http_client_get_updates_req(struct YNoteApp *app);

static int tg_answer_snippet(struct YNoteApp *app, bstring str_id, int to) {
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
      int from_id = 0;
      struct tagbstring text = {0};
      char *name = NULL;
      char *lastname = NULL;
      json_value *json_from = NULL;
      json_value **messages = json_tmp->u.array.values;

      int err = 0;
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
        CHECK(
            json_tmp != NULL && json_tmp->type == json_string, "Bad response");
        name = json_tmp->u.string.ptr;

        JSON_GET_ITEM(json_from, json_tmp, "last_name");
        CHECK(
            json_tmp != NULL && json_tmp->type == json_string, "Bad response");
        lastname = json_tmp->u.string.ptr;

        JSON_GET_ITEM(json_from, json_tmp, "is_bot");
        CHECK(
            json_tmp != NULL && json_tmp->type == json_boolean, "Bad response");
        LOG_DEBUG(
            "%s %s %s (id %d) wrote %s",
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
              if (!strcmp(bdata(vargs->entry[0]), "/get_id")) {
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
    struct YNoteApp *app, unsigned chat_id, bstring msg, char escape_msg) {
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
  int client_timeout = 60;
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
      "Couldn't load config");
  CHECK(
      (rc = lua_pcall(app->lua, 0, 0, 0)) == LUA_OK,
      "Couldn't evaluate config");

  LUA_CONF_READ_STRING(app->tg_token, tg_token);
  LUA_CONF_READ_STRING(app->dbpath, dbpath);

  LUA_CONF_READ_NUMBER(app->client_timeout, client_timeout, 30);
  LUA_CONF_READ_NUMBER(app->port, port, 8080);
  LUA_CONF_READ_NUMBER(app->mhd_port, mhd_port, 8083);

  CHECK(app->port > 0 && app->port < 65535, "Wrong port number");

  rc = 0;

  app->users_info.u.id = 332994181;
  app->users_info.u.allowed = 1;
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

// read whole input buffer into json_str
static bstring get_bstr_body(struct evbuffer *ev_buf, bstring buf) {
  bstring ret = NULL;
  int bstring_is_allocated = 0;
  if (buf != NULL) {
    ret = buf;
    bstring_is_allocated = 1;
  } else {
    ret = bfromcstralloc(BUF_LEN, "");
    CHECK_MEM(ret);
  }
  while (evbuffer_get_length(ev_buf)) {
    int n;
    if ((ret->mlen - blength(ret)) < 2) {
      CHECK((ret->mlen - blength(ret)) > 0, "Wrong string");
      CHECK(
          ballocmin(ret, ret->mlen * 2) == BSTR_OK,
          "Couldn't reallocate string");
    }
    n = evbuffer_remove(
        ev_buf, ret->data + blength(ret), ret->mlen - blength(ret) - 1);
    CHECK(n >= 0, "Couldn't read from input ev_buffer");
    ret->slen += n;
    bdata(ret)[blength(ret)] = '\0';
  }

  return ret;

error:
  if (bstring_is_allocated && ret != NULL) {
    bdestroy(ret);
  }
  return NULL;
}

static void
api_upload_file(struct evhttp_request *req, const struct YNoteApp *app) {
  char *reason = "OK";
  int rc = 200;
  struct evbuffer *resp = NULL;
  bstring body = NULL;
  struct evbuffer *ibuf = NULL;
  struct evkeyvalq queries = {0};

  struct tagbstring header_tbstr = {0};
  struct tagbstring tmp_tbstr = {0};
  bstring boundary = NULL;

  bstrListEmb *split_headers = NULL;
  bstrListEmb *split_line = NULL;
  bstrListEmb *split_subline = NULL;

  const char *header_str = NULL;

  (void)app;

  ibuf = evhttp_request_get_input_buffer(req);
  body = get_bstr_body(ibuf, NULL);
  header_str =
      evhttp_find_header(evhttp_request_get_input_headers(req), "content-type");
  LOG_DEBUG("Got content-type %s", header_str);
  CHECK(header_str != NULL, "Content-type is missing");

  cstr2tbstr(header_tbstr, header_str);
  struct tagbstring query = bsStatic("multipart/form-data; boundary=");

  CHECK(
      bstrncmp(&header_tbstr, &query, blength(&query)) == 0,
      "mutipart/form-data is expected");

  CHECK(
      (split_line = bsplit_noalloc(&header_tbstr, ' ')) != NULL,
      "Couldn't split line");

  CHECK(rv_len(*split_line) >= 2, "wrong line format");

  CHECK(
      (split_subline = bsplit_noalloc(rv_get(*split_line, 1, NULL), '=')) !=
          NULL,
      "Couldn't split line");

  CHECK(rv_len(*split_subline) >= 2, "wrong line format");

  boundary = bstrcpy(rv_get(*split_subline, 1, NULL));
  CHECK(boundary != NULL, "Couldn't create string");

  bstrListEmb_destroy(split_subline);
  split_subline = NULL;
  bstrListEmb_destroy(split_line);
  split_line = NULL;

  LOG_INFO("boundary = %s", bdata(boundary));

  bassignmidstr(
      &header_tbstr, &header_tbstr, blength(&query), blength(&header_tbstr));

  LOG_DEBUG("Got body %s", bdata(body));
  LOG_DEBUG("Got body decoded %s", evhttp_decode_uri(bdata(body)));
  LOG_INFO("File uploaded");

  resp = evbuffer_new();
  CHECK_MEM(resp);
  evhttp_add_header(
      evhttp_request_get_output_headers(req),
      "Content-Type",
      "application/json");

  CHECK(
      evbuffer_add_printf(resp, "{\"status\": \"ok\"}"),
      "Couldn't append to response buffer");

exit:
  if (resp != NULL) {
    evhttp_send_reply(req, rc, reason, resp);
  } else {
    evhttp_send_reply(req, rc, reason, NULL);
  }
  evbuffer_free(resp);
  if (body != NULL) {
    bdestroy(body);
  }
  if (boundary != NULL) {
    bdestroy(boundary);
  }
  if (split_subline != NULL) {
    bstrListEmb_destroy(split_subline);
  }
  if (split_line != NULL) {
    bstrListEmb_destroy(split_line);
  }
  return;

error:
  rc = 500;
  reason = "Internal Server Error";
  if (resp != NULL) {
    evbuffer_drain(resp, evbuffer_get_length(resp));
    if (evbuffer_add_printf(resp, "500") <= 0) {
      evbuffer_free(resp);
      resp = NULL;
    };
  }
  goto exit;
}

static void
json_api_cb(struct evhttp_request *req, const struct YNoteApp *app) {
  char *reason = "OK";
  int rc = 200;
  struct evbuffer *resp = NULL;

  (void)app;

  resp = evbuffer_new();
  CHECK_MEM(resp);
  evhttp_add_header(
      evhttp_request_get_output_headers(req),
      "Content-Type",
      "application/json");

  LOG_DEBUG(
      "Got request for path %s",
      evhttp_uri_get_path(evhttp_request_get_evhttp_uri(req)));

  CHECK(
      evbuffer_add_printf(resp, "{\"status\": \"ok\"}"),
      "Couldn't append to response buffer");

exit:
  if (resp != NULL) {
    evhttp_send_reply(req, rc, reason, resp);
  } else {
    evhttp_send_reply(req, rc, reason, NULL);
  }
  evbuffer_free(resp);
  return;

error:
  rc = 500;
  reason = "Internal Server Error";
  if (resp != NULL) {
    evbuffer_drain(resp, evbuffer_get_length(resp));
    if (evbuffer_add_printf(resp, "500") <= 0) {
      evbuffer_free(resp);
      resp = NULL;
    };
  }
  goto exit;
}

static void simple_free_cb(const void *data, size_t datalen, void *extra) {
  (void)datalen;
  (void)extra;
  free((void *)data);
}

static void bstring_free_cb(const void *data, size_t datalen, void *extra) {
  (void)data;
  (void)datalen;
  bstring str = extra;
  if (str != NULL)
    bdestroy(str);
}

void bstring_append(const MD_CHAR *ptr, MD_SIZE size, void *str) {
  CHECK(str != NULL, "Null str");
  CHECK(bcatblk(str, ptr, size) == BSTR_OK, "Couldn't append to string");

error:
  return;
}

int render_json(bstring *json_str) {
  int rc = 0;
  json_value *json = NULL;
  json_value *json_tmp = NULL;
  json_value *json_result = NULL;
  bstring new_json_str = NULL;
  bstring html_str = NULL;

  json_settings js = {.value_extra = json_builder_extra};
  json_serialize_opts jso = {.mode = json_serialize_mode_packed};
  CHECK(json_str != NULL && bdata(*json_str) != NULL, "Null json");

  json = json_parse_ex(&js, bdata(*json_str), blength(*json_str), NULL);

  CHECK(json != NULL, "Couldn't parse json");

  JSON_GET_ITEM(json, json_result, "result");
  CHECK(json_result != NULL, "Incorrect json");

  JSON_GET_ITEM(json_result, json_tmp, "type");
  CHECK(json_tmp != NULL && json_tmp->type == json_string, "Incorrect json");

  LOG_DEBUG(
      "type is %s, len is %d",
      json_tmp->u.string.ptr,
      json_tmp->u.string.length);

  if (!strcmp(json_tmp->u.string.ptr, "markdown")) {
    JSON_GET_ITEM(json_result, json_tmp, "content");
    CHECK(json_tmp != NULL && json_tmp->type == json_string, "Incorrect json");

    html_str = bfromcstr("");
    CHECK(html_str != NULL, "Couldn't create string");

    CHECK(
        md_html(
            json_tmp->u.string.ptr,
            json_tmp->u.string.length,
            bstring_append,
            html_str,
            0,
            0) == 0,
        "Couldn't render markdown snippet");

    CHECK(bdata(html_str) != NULL, "Couldn't render markdown");

    free(json_tmp->u.string.ptr);
    json_tmp->u.string.ptr = bdata(html_str);
    json_tmp->u.string.length = blength(html_str);

    html_str->data = NULL;
    free(html_str);
    html_str = NULL;
    CHECK(
        (new_json_str = bfromcstralloc(json_measure_ex(json, jso), "")) != NULL,
        "Coudn't create string");

    json_serialize_ex(bdata(new_json_str), json, jso);
    CHECK(bdestroy(*json_str) == BSTR_OK, "Couldn't destory old json");
    new_json_str->slen = new_json_str->mlen - 1;
    *json_str = new_json_str;
    new_json_str = NULL;
  }
  LOG_DEBUG("%s", bdata(*json_str));

exit:
  if (json != NULL) {
    json_value_free(json);
  }
  if (new_json_str != NULL) {
    bdestroy(new_json_str);
  }
  if (html_str != NULL) {
    bdestroy(html_str);
  }
  return rc;
error:
  rc = -1;
  goto exit;
}

static bstring
json_api_delete_snippet(const struct YNoteApp *app, sqlite_int64 id) {
  int err = 0;
  bstring json_str_res = NULL;

  id = dbw_edit_snippet(app->db_handle, id, NULL, NULL, NULL, NULL, 1, &err);
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
static bstring
json_api_get_snippet(const struct YNoteApp *app, sqlite_int64 id, int render) {
  int err = 0;
  bstring json_str_res = NULL;

  json_str_res = dbw_get_snippet(app->db_handle, id, &err);
  if (err == DBW_ERR_NOT_FOUND) {
    bdestroy(json_str_res);
    json_str_res =
        bfromcstr("{\"status\": \"error\", \"msg\": \"snippet not found\"}");
    goto exit;
  }
  CHECK(
      json_str_res != NULL && blength(json_str_res) > 0 && err == DBW_OK,
      "Couldn't get snippets");

  if (render) {
    CHECK(render_json(&json_str_res) == 0, "Couldn't render json");
  }

exit:
  return json_str_res;
error:
  if (json_str_res != NULL) {
    bdestroy(json_str_res);
  }
  return NULL;
}

static void ev_json_api_get_snippet(
    struct evhttp_request *req, const struct YNoteApp *app) {
  char *reason = "OK";
  int ret_code = 200;
  int err = 0;
  struct evbuffer *resp = NULL;
  char edit = 0;
  const char *id_str = NULL;
  const char *edit_str = NULL;
  sqlite_int64 id = 0;
  struct evkeyvalq queries;
  const char *bad_request_msg = NULL;
  bstring json_str_res = NULL;
  int rc = 0;

  resp = evbuffer_new();
  CHECK_MEM(resp);

  evhttp_add_header(
      evhttp_request_get_output_headers(req),
      "Content-Type",
      "application/json; charset=UTF-8");

  CHECK(
      evhttp_parse_query_str(
          evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req)), &queries) ==
          0,
      "Couldn't parse query str");
  id_str = evhttp_find_header(&queries, "id");
  if (id_str == NULL) {
    bad_request_msg = bdata(&status_id_required);
    goto bad_request;
  }
  PARSE_INT(strtoll, id_str, id, rc);
  if (rc == 1) {
    bad_request_msg = bdata(&status_id_required);
    goto bad_request;
  }
  edit_str = evhttp_find_header(&queries, "edit");
  if (edit_str != NULL && biseqcstrcaseless(&s_true, edit_str)) {
    edit = 1;
  }
  LOG_DEBUG("json_api_got_snippet got %lld", id);
  json_str_res = json_api_get_snippet(app, id, !edit);
  if (json_str_res == NULL) {
    bad_request_msg = "{\"status\": \"snippet not found\"}";
    goto bad_request;
  }

  CHECK(
      evbuffer_add_reference(
          resp,
          bdata(json_str_res),
          blength(json_str_res),
          bstring_free_cb,
          json_str_res) == 0,
      "Couldn't append json to output buffer");

  // bstring should be freed by bstring_free_cb then
  json_str_res = NULL;
exit:
  evhttp_clear_headers(&queries);
  if (resp != NULL) {
    evhttp_send_reply(req, ret_code, reason, resp);
  } else {
    evhttp_send_reply(req, ret_code, reason, NULL);
  }
  evbuffer_free(resp);
  if (json_str_res != NULL) {
    bdestroy(json_str_res);
  }
  return;

error:
  ret_code = 500;
  reason = "Internal Server Error";
  if (resp != NULL) {
    evbuffer_drain(resp, evbuffer_get_length(resp));
    if (evbuffer_add_printf(resp, "500") <= 0) {
      evbuffer_free(resp);
      resp = NULL;
    };
  }
  goto exit;
bad_request:
  ret_code = 403;
  reason = "Bad Request";
  bad_request_msg = bad_request_msg == NULL ? "Bad request" : bad_request_msg;
  CHECK(
      evbuffer_add_printf(resp, "%s", bad_request_msg),
      "Couldn't append to response buffer");
  goto exit;
}

static void
json_api_find_snippets(struct evhttp_request *req, const struct YNoteApp *app) {
  char *reason = "OK";
  int rc = 200;
  int err = 0;
  struct evbuffer *resp = NULL;
  struct evkeyvalq queries;
  bstrListEmb *taglist = NULL;
  const char *tmp_cstr = NULL;
  bstring json_str_res = NULL;
  struct tagbstring snippet_type = {0};

  resp = evbuffer_new();
  CHECK_MEM(resp);

  evhttp_add_header(
      evhttp_request_get_output_headers(req),
      "Content-Type",
      "application/json; charset=UTF-8");

  CHECK(
      evhttp_parse_query_str(
          evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req)), &queries) ==
          0,
      "Couldn't parse query str");

  tmp_cstr = evhttp_find_header(&queries, "tags");
  if (tmp_cstr != NULL) {
    if (!strcmp(tmp_cstr, "")) {
      taglist = calloc(1, sizeof(bstrListEmb));
      CHECK(taglist != NULL, "Couldn't create empty taglist");
    } else {
      struct tagbstring tagstr = {0};
      btfromcstr(tagstr, tmp_cstr);
      LOG_DEBUG("%s, %s", tmp_cstr, bdata(&tagstr));
      taglist = bsplit_noalloc(&tagstr, ',');
      CHECK(taglist != NULL, "Couldn't split tags string");
    }
  }

  tmp_cstr = evhttp_find_header(&queries, "type");
  if (tmp_cstr != NULL && strcmp(tmp_cstr, "")) {
    btfromcstr(snippet_type, tmp_cstr);
  }

  json_str_res =
      dbw_find_snippets(app->db_handle, NULL, &snippet_type, taglist, &err);

  CHECK(
      json_str_res != NULL && blength(json_str_res) > 0 && err == DBW_OK,
      "Couldn't get snippets");

  CHECK(
      evbuffer_add_reference(
          resp,
          bdata(json_str_res),
          blength(json_str_res),
          bstring_free_cb,
          json_str_res) == 0,
      "Couldn't append json to output buffer");

  // bstring should be free by bstring_free_cb then
  json_str_res = NULL;
exit:
  evhttp_clear_headers(&queries);
  if (resp != NULL) {
    evhttp_send_reply(req, rc, reason, resp);
  } else {
    evhttp_send_reply(req, rc, reason, NULL);
  }
  evbuffer_free(resp);
  if (json_str_res != NULL) {
    bdestroy(json_str_res);
  }
  if (taglist != NULL) {
    bstrListEmb_destroy(taglist);
  }
  return;

error:
  rc = 500;
  reason = "Internal Server Error";
  if (resp != NULL) {
    evbuffer_drain(resp, evbuffer_get_length(resp));
    if (evbuffer_add_printf(resp, "500") <= 0) {
      evbuffer_free(resp);
      resp = NULL;
    };
  }
  goto exit;
}

static void ev_json_api_delete_snippet(
    struct evhttp_request *req, const struct YNoteApp *app) {
  char *reason = "OK";
  int rc = 200;
  int err = 0;
  struct evbuffer *resp = NULL;
  struct evkeyvalq queries;
  sqlite_int64 snippet_id = 0;
  char *tmp_cstr = NULL;
  char *bad_request_msg = NULL;
  bstring json_str_res = NULL;

  resp = evbuffer_new();
  CHECK_MEM(resp);

  evhttp_add_header(
      evhttp_request_get_output_headers(req),
      "Content-Type",
      "application/json; charset=UTF-8");

  CHECK(
      evhttp_parse_query_str(
          evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req)), &queries) ==
          0,
      "Couldn't parse query str");

  tmp_cstr = (char *)evhttp_find_header(&queries, "id");
  if (tmp_cstr == NULL) {
    bad_request_msg = "id is required when deleting snippet";
    goto bad_request;
  }
  PARSE_INT(strtoll, tmp_cstr, snippet_id, rc);
  if (rc == 1) {
    bad_request_msg = "malformed id";
    goto bad_request;
  }
  json_str_res = json_api_delete_snippet(app, snippet_id);
  CHECK(json_str_res != NULL, "Couldn't delete snippet");
  CHECK(
      evbuffer_add_reference(
          resp,
          bdata(json_str_res),
          blength(json_str_res),
          bstring_free_cb,
          json_str_res) == 0,
      "Couldn't append json to output buffer");

  // bstring should be freed by bstring_free_cb then
  json_str_res = NULL;

exit:
  evhttp_clear_headers(&queries);
  if (resp != NULL) {
    evhttp_send_reply(req, rc, reason, resp);
  } else {
    evhttp_send_reply(req, rc, reason, NULL);
  }
  evbuffer_free(resp);
  if (json_str_res != NULL) {
    bdestroy(json_str_res);
  }
  return;

  INTERNAL_ERROR_HANDLE;
  BAD_REQ_HANDLE;
}

static bstring json_api_create_snippet(
    const struct YNoteApp *app,
    bstring json_req,
    sqlite_int64 snippet_id,
    int edit,
    int *ec) {
  bstring ret = NULL;
  json_value *json = NULL;
  int err = 0;

  bstrListEmb tags = {0};

  CHECK(bdata(json_req) != NULL, "Null string");
  json = json_parse(bdata(json_req), blength(json_req));

  if (json == NULL) {
    ret = bfromcstr("{\"status\": \"JSON Malformed\"}");
    goto error_403;
  }
  if ((json->type) != json_object) {
    ret = bfromcstr("{\"status\": \"Dict required\"}");
    goto error_403;
  }

  struct tagbstring title = {0};
  struct tagbstring content = {0};
  struct tagbstring type = {0};

  json_value *jtitle = NULL, *jcontent = NULL, *jtype = NULL;

  JSON_GET_ITEM(json, jtitle, "title");
  JSON_GET_ITEM(json, jcontent, "content");
  JSON_GET_ITEM(json, jtype, "type");

// In this macro we check that json values we got above are strings
// and that they are not NULL if we are creating snippet (not editing)
// otherwise just check they are strings, and then assign they to the
// corresponging tagbstrings
#define CHECK_J(tbstr, edit)                                         \
  do {                                                               \
    if (!(edit)) {                                                   \
      if ((j##tbstr) == NULL || (j##tbstr)->type != json_string) {   \
        ret = bfromcstr("{\"status\": \"" #tbstr                     \
                        " required and must be string");             \
        goto error_403;                                              \
      }                                                              \
    } else {                                                         \
      if ((j##tbstr) != NULL && (j##tbstr)->type != json_string) {   \
        ret = bfromcstr("{\"status\": \"" #tbstr " must be string"); \
        goto error_403;                                              \
      }                                                              \
    }                                                                \
    if ((j##tbstr) != NULL) {                                        \
      btfromcstr(tbstr, (j##tbstr)->u.string.ptr);                   \
    }                                                                \
  } while (0)

  CHECK_J(title, edit);
  CHECK_J(content, edit);
  CHECK_J(type, edit);
  LOG_DEBUG("type is %s", bdata(&type));
  LOG_DEBUG("title is %s", bdata(&title));

#undef CHECK_J

  json_value *jtags = NULL;
  JSON_GET_ITEM(json, jtags, "tags");
  if (jtags != NULL && jtags->type == json_array) {

    /* Manual bstrList handling to eliminate unnecessary mallocs */

    struct tagbstring tbtmp = {0};
    for (unsigned int i = 0; i < jtags->u.array.length; i++) {
      if (jtags->u.array.values[i]->type != json_string) {
        ret = bfromcstr("{\"status\": \"tags must be an array of strings\"");
        goto error_403;
      }

      blk2tbstr(
          tbtmp,
          jtags->u.array.values[i]->u.string.ptr,
          jtags->u.array.values[i]->u.string.length);

      rv_push(tags, tbtmp, NULL);
    }
  }

  if (edit) {
    snippet_id = dbw_edit_snippet(
        app->db_handle, snippet_id, &title, &content, &type, &tags, 0, &err);
  } else {
    snippet_id =
        dbw_new_snippet(app->db_handle, &title, &content, &type, &tags, &err);
  }
  if (err == DBW_ERR_NOT_FOUND) {
    ret = bfromcstr("{\"status\": \"error\", \"msg\": \"wrong type\"");
    goto error_403;
  } else if (err == DBW_ERR_ALREADY_EXISTS) {
    ret = bfromcstr("{\"status\": \"error\", \"msg\": \"already exists error. "
                    "possibly snippet with this "
                    "title alredy exists\"}");
    goto error_403;

  } else if (err != DBW_OK) {
    goto error;
  }
  ret = bformat("{\"status\": \"ok\", \"id\": %lld}", snippet_id);

  if (ec != NULL) {
    *ec = 200;
  }
exit:
  if (json != NULL) {
    json_value_free(json);
  }
  rv_destroy(tags);
  return ret;
error_403:
  if (ec != NULL) {
    *ec = 403;
  }
  goto exit;
error:
  if (ec != NULL) {
    *ec = 500;
  }
  goto exit;
}

static void ev_json_api_create_snippet(
    struct evhttp_request *req, const struct YNoteApp *app) {
  int rc = 200;
  int err = 0;
  char *reason = "OK";
  char *cbuf = NULL;
  char *bad_request_msg = NULL;
  struct evbuffer *ibuf = NULL;
  struct evbuffer *resp = NULL;
  bstring json_str = NULL;
  sqlite_int64 snippet_id = 0;
  struct evkeyvalq queries = {0};
  char edit = 0;
  char *tmp_cstr = NULL;
  bstring response = NULL;

  resp = evbuffer_new();
  CHECK_MEM(resp);

  CHECK(
      evhttp_parse_query_str(
          evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req)), &queries) ==
          0,
      "Couldn't parse query str");

  tmp_cstr = (char *)evhttp_find_header(&queries, "edit");
  if (tmp_cstr != NULL) {
    LOG_DEBUG("tmp_cstr %s", tmp_cstr);
    if (biseqcstrcaseless(&s_true, tmp_cstr)) {
      edit = 1;
      tmp_cstr = (char *)evhttp_find_header(&queries, "id");
      if (tmp_cstr == NULL) {
        bad_request_msg = "id is required when editing snippet";
        goto bad_request;
      }
      PARSE_INT(strtoll, tmp_cstr, snippet_id, rc);
      if (rc == 1) {
        bad_request_msg = "malformed id";
        goto bad_request;
      }
    }
  }

  cbuf = malloc(BUF_LEN);
  CHECK_MEM(cbuf);

  json_str = bfromcstralloc(BUF_LEN, "");
  CHECK_MEM(json_str);

  switch (evhttp_request_get_command(req)) {
  case EVHTTP_REQ_POST:
    break;
  default:
    rc = 405;
    reason = "Method not allowed";
    CHECK(
        evbuffer_add_printf(resp, "405: Method not allowed") != -1,
        "Couldn't add to buf");
    goto exit;
  }

  ibuf = evhttp_request_get_input_buffer(req);
  // read whole input buffer into json_str
  json_str = get_bstr_body(ibuf, json_str);
  CHECK(json_str != NULL, "Couldn't read body");
  while (evbuffer_get_length(ibuf)) {
    int n;
    if ((json_str->mlen - blength(json_str)) < 2) {
      CHECK((json_str->mlen - blength(json_str)) > 0, "Wrong string");
      CHECK(
          ballocmin(json_str, json_str->mlen * 2) == BSTR_OK,
          "Couldn't reallocate string");
    }
    n = evbuffer_remove(
        ibuf,
        json_str->data + blength(json_str),
        json_str->mlen - blength(json_str) - 1);
    CHECK(n >= 0, "Couldn't read from input buffer");
    json_str->slen += n;
    bdata(json_str)[blength(json_str)] = '\0';
  }

  LOG_DEBUG(
      "Got json(?) %.100s, blength = %d, mlength = %d",
      bdata(json_str),
      blength(json_str),
      json_str->mlen);

  response = json_api_create_snippet(app, json_str, snippet_id, edit, &rc);
  CHECK(response != NULL, "Couldn't create snippet");

  evhttp_add_header(
      evhttp_request_get_output_headers(req),
      "Content-Type",
      "application/json");

  CHECK(
      evbuffer_add(resp, bdata(response), blength(response)) == 0,
      "Couldn't append to response buffer");

exit:
  if (response != NULL) {
    bdestroy(response);
  }
  if (json_str != NULL) {
    bdestroy(json_str);
  }
  if (cbuf != NULL) {
    free(cbuf);
  }
  if (resp != NULL) {
    evhttp_send_reply(req, rc, reason, resp);
  } else {
    evhttp_send_reply(req, rc, reason, NULL);
  }
  evbuffer_free(resp);
  return;

  INTERNAL_ERROR_HANDLE;
  BAD_REQ_HANDLE;
}

void ynote_app_destroy(struct YNoteApp *app) {
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
  free(app);
error:
  return;
}

struct YNoteApp *ynote_app_create(int argc, char *argv[]) {
  struct YNoteApp *ret = NULL;
  int err = 0;

  CHECK_MEM(ret = calloc(1, sizeof(struct YNoteApp)));

  if (parse_cli_options(ret, argc, argv) != 0) {
    printf(USAGE, argv[0]);
    goto error;
  }

  CHECK((ret->lua = luaL_newstate()) != NULL, "Couldn't create lua state");
  luaL_openlibs(ret->lua);

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
  struct connection_info_struct *con_info = coninfo_cls;

  LOG_DEBUG("name %s", key);
  LOG_DEBUG("data %s", data);
  LOG_DEBUG("filename %s", filename);

  return MHD_YES;
}

struct UploadFile {
  bstring field_name;
  bstring name;
  bstring path;
};

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
  return;
}

typedef rvec_t(struct UploadFile) UploadFilesVec;

enum ConnInfoType {
  CIT_POST_RAW,
  CIT_POST_FORM,
  CIT_OTHER,
};

struct ConnInfo {
  struct YNoteApp *app;
  uint64_t invocations;
  enum ConnInfoType type;
  enum HTTPServerRestCallName api_call_name;
  enum HTTPServerMethodName method_name;
  void *userp;
  struct MHD_PostProcessor *pp;
  struct tagbstring error;
};

static struct ConnInfo *ConnInfo_create(
    enum ConnInfoType ct,
    enum HTTPServerMethodName method_name,
    enum HTTPServerRestCallName api_call_name,
    struct YNoteApp *app) {
  struct ConnInfo *ci = calloc(1, sizeof(struct ConnInfo));
  CHECK_MEM(ci);
  if (ct == CIT_POST_RAW) {
    CHECK((ci->userp = bfromcstr("")) != NULL, "Couldn't create con_cls");
  } else if (ct == CIT_POST_FORM) {
    CHECK(
        (ci->userp = calloc(1, sizeof(UploadFilesVec))) != NULL,
        "Couldn't create con_cls");
  }
  ci->app = app;

  ci->api_call_name = api_call_name;
  ci->method_name = method_name;

  ci->type = ct;

  return ci;
error:
  return NULL;
}

static void ConnInfo_destroy(struct ConnInfo *ci) {
  if (ci != NULL) {
    if (ci->userp != NULL) {
      if (ci->type == CIT_POST_RAW) {
        bdestroy((bstring)(ci->userp));
      } else if (ci->type == CIT_POST_FORM) {
        UploadFilesVec *v = ci->userp;
        for (int i = 0; i < v->n; i++) {
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
      }
    }
    if (ci->pp != NULL) {
      MHD_destroy_post_processor(ci->pp);
    }
    free(ci);
  }
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

  CHECK(v != NULL, "Null vector");

  bstrListEmb *split_str = NULL;

  if (strrchr(key, '.')) {
    struct genBstrList gl = {0};
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
    for (int i = 0; i < v->n; i++) {
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

static enum MHD_Result post_iterator(
    void *cls,
    enum MHD_ValueKind kind,
    const char *key,
    const char *filename,
    const char *content_type,
    const char *transfer_encoding,
    const char *data,
    uint64_t off,
    size_t size) {
  LOG_DEBUG("name %s", key);
  LOG_DEBUG("data %s", data);
  LOG_DEBUG("filename %s", filename);
  LOG_DEBUG("cotent_type %s", content_type);
  LOG_DEBUG("transfer_encoding %s", transfer_encoding);
  LOG_DEBUG("kind %u", kind);
  LOG_DEBUG("offset %lu", off);
  LOG_DEBUG("size %zu", size);
  bstring str = cls;
  bcatblk(str, &data[off], size);

  return MHD_YES;
}

static enum MHD_Result
post_upload_response(struct MHD_Connection *connection, struct ConnInfo *ci) {
  int ret;
  int err = 0;
  bstring response_string = NULL;
  bstring new_path = NULL;
  struct MHD_Response *response = NULL;
  UploadFilesVec *v = ci->userp;
  struct UploadFile *uf = NULL;
  struct stat filestat;

  CHECK(response_string = bfromcstr(""), "Couldn't create string");

  for (int i = 0; i < v->n; i++) {
    uf = rv_get(*v, i, NULL);
    if (!bdata(uf->name)) {
      LOG_ERR("NULL filename");
      continue;
    }
    err = stat(bdatae(uf->path, ""), &filestat);
    if (err) {
      bformata(
          response_string, "error getting stat for file %s\n", bdata(uf->path));
      continue;
    }
    if (!S_ISREG(filestat.st_mode)) {
      bformata(response_string, "file %s is not regular\n", bdata(uf->path));
      continue;
    }
    new_path = bformat("uploads/%s", bdata(uf->name));
    err = stat(bdatae(new_path, ""), &filestat);
    if (err == 0 || errno != ENOENT) {
      LOG_ERR(
          "destination file %s exists or error getting stat", bdata(new_path));
      bformata(response_string, "new path %s is wrong\n", bdata(new_path));
      continue;
    }
    err = rename(bdata(uf->path), bdata(new_path));
    CHECK(err == 0, "Couldn't move file %s", bdata(uf->name));
    dbw_register_file(ci->app->db_handle, uf->name, new_path, NULL, NULL, &err);
    if (err != DBW_OK) {
      bformata(
          response_string,
          "Couldn't register %s in DB\n",
          bdata(uf->field_name));
    } else {
      bformata(
          response_string,
          "%s ok, new path is %s\n",
          bdata(uf->field_name),
          bdata(new_path));
      uf = NULL;
    }
  }

  MHD_RESPONSE_WITH_BSTRING(
      connection, MHD_HTTP_OK, response, response_string, ret);

error:
  ret = MHD_NO;
  goto exit;
exit:
  if (new_path) {
    bdestroy(new_path);
  }
  return ret;
}

static enum MHD_Result mhd_api_upload(
    struct MHD_Connection *connection,
    struct ConnInfo *ci,
    const char *upload_data,
    size_t *upload_data_size) {
  struct MHD_Response *response = NULL;
  int ret = MHD_NO;
  int edit = 0;
  int rc = 0;
  const char *edit_str = NULL;
  bstring body = (bstring)ci->userp;
  bstring json_str_res = NULL;

  edit_str =
      MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "edit");

  if (edit_str != NULL && biseqcstrcaseless(&s_true, edit_str)) {
    edit = 1;
  }
  if (ci->method_name != RESTMETHOD_POST) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        status_method_not_allowed,
        ret);
  }
  if (ci->invocations == 1) {
    CHECK(ci->pp == NULL, "Post process must be null on first invocation");
    ci->pp =
        MHD_create_post_processor(connection, 1024, post_upload_iterator, ci);
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
    CHECK(
        MHD_post_process(ci->pp, upload_data, *upload_data_size) == MHD_YES,
        "Could't post_process");
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

static enum MHD_Result
mhd_api_find_snippets(struct MHD_Connection *connection, struct ConnInfo *ci) {
  struct MHD_Response *response = NULL;
  int ret = MHD_NO;
  sqlite_int64 id = 0;
  int rc = 0;
  const char *edit_str = NULL;
  char edit = 0;
  int err = 0;
  struct tagbstring tbtags = {0};
  bstrListEmb *taglist = NULL;
  const char *tmp_cstr = NULL;
  bstring json_str_res = NULL;
  struct tagbstring snippet_type = {0};

  if (ci->method_name != RESTMETHOD_GET) {
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

static enum MHD_Result mhd_api_create_snippet(
    struct MHD_Connection *connection,
    struct ConnInfo *ci,
    const char *upload_data,
    size_t *upload_data_size) {
  struct MHD_Response *response = NULL;
  int ret = MHD_NO;
  int edit = 0;
  int rc = 0;
  const char *edit_str = NULL;
  bstring body = (bstring)ci->userp;
  bstring json_str_res = NULL;

  edit_str =
      MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "edit");

  if (edit_str != NULL && biseqcstrcaseless(&s_true, edit_str)) {
    edit = 1;
  }
  if (ci->method_name != RESTMETHOD_POST) {
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection,
        MHD_HTTP_BAD_REQUEST,
        response,
        status_method_not_allowed,
        ret);
  }
  if (ci->invocations == 1) {
    ret = MHD_YES;
    goto exit;
  }
  if (*upload_data_size != 0) {
    CHECK(
        bcatblk(body, upload_data, *upload_data_size) == BSTR_OK,
        "Couldn't read body");
    *upload_data_size = 0;
    ret = MHD_YES;
    goto exit;
  } else {
    sqlite_int64 snippet_id = 0;
    if (edit) {
      const char *value =
          MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "id");
      if (value == NULL) {
        MHD_RESPONSE_WITH_TAGBSTRING(
            connection,
            MHD_HTTP_BAD_REQUEST,
            response,
            status_id_required,
            ret);
      }
      PARSE_INT(strtoll, value, snippet_id, rc);
      if (rc == 1) {
        MHD_RESPONSE_WITH_TAGBSTRING(
            connection,
            MHD_HTTP_BAD_REQUEST,
            response,
            status_id_required,
            ret);
      }
    }
    json_str_res =
        json_api_create_snippet(ci->app, body, snippet_id, edit, &rc);
    if (json_str_res == NULL) {
      MHD_RESPONSE_WITH_TAGBSTRING(
          connection, rc, response, status_server_error, ret);
    } else {
      MHD_RESPONSE_WITH_BSTRING(connection, rc, response, json_str_res, ret);
    }
  exit:
    return ret;
  error:
    ret = MHD_NO;
    goto exit;
  }
}

static enum MHD_Result
mhd_api_delete_snippet(struct MHD_Connection *connection, struct ConnInfo *ci) {
  struct MHD_Response *response = NULL;
  int ret = MHD_NO;
  sqlite_int64 id = 0;
  int rc = 0;
  int err = 0;
  const char *edit_str = NULL;
  char edit = 0;
  bstring json_str_res = NULL;

  edit_str =
      MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "edit");
  if (edit_str != NULL && biseqcstrcaseless(&s_true, edit_str)) {
    edit = 1;
  }
  if (ci->method_name != RESTMETHOD_DELETE) {
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
  json_str_res = json_api_delete_snippet(ci->app, id);
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

static enum MHD_Result
mhd_api_get_snippet(struct MHD_Connection *connection, struct ConnInfo *ci) {
  struct MHD_Response *response = NULL;
  int ret = MHD_NO;
  sqlite_int64 id = 0;
  int rc = 0;
  const char *edit_str = NULL;
  char edit = 0;
  bstring json_str_res = NULL;

  edit_str =
      MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "edit");
  if (edit_str != NULL && biseqcstrcaseless(&s_true, edit_str)) {
    edit = 1;
  }
  if (ci->method_name != RESTMETHOD_GET) {
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
  json_str_res = json_api_get_snippet(ci->app, id, !edit);
  LOG_DEBUG("json_str_res is %s", bdata(json_str_res));
  if (json_str_res == NULL) {
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
  return ret;
error:
  ret = MHD_NO;
  goto exit;
}

void mhd_log(void *cls, const char *fm, va_list ap) {
  int ret;
  bstring b;
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

static int mhd_handler(
    struct YNoteApp *app,
    struct MHD_Connection *connection,
    const char *url,
    const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls) {
  int ret = MHD_NO;
  struct MHD_Response *response = NULL;
  sqlite_int64 id = 0;
  int rc = 0;
  const char *edit_str = NULL;
  char edit = 0;
  bstring json_str_res = NULL;
  struct ConnInfo *ci = NULL;
  int new_con_cls = 0;

  if (*con_cls == NULL) {
    enum HTTPServerRestCallName call_name;
    enum HTTPServerMethodName method_name;

    if (!strcmp(url, "/api/get_snippet")) {
      call_name = RESTAPI_GET_SNIPPET;
    } else if (!strcmp(url, "/api/create_snippet")) {
      call_name = RESTAPI_CREATE_SNIPPET;
    } else if (!strcmp(url, "/api/find_snippets")) {
      call_name = RESTAPI_FIND_SNIPPETS;
    } else if (!strcmp(url, "/api/delete_snippet")) {
      call_name = RESTAPI_DELETE_SNIPPET;
    } else if (!strcmp(url, "/api/upload")) {
      call_name = RESTAPI_UPLOAD;
    } else {
      call_name = RESTAPI_UNKNOWN;
    }

    if (!strcmp(method, "GET")) {
      method_name = RESTMETHOD_GET;
    } else if (!strcmp(method, "POST")) {
      method_name = RESTMETHOD_POST;
    } else if (!strcmp(method, "DELETE")) {
      method_name = RESTMETHOD_DELETE;
    } else if (!strcmp(method, "PUT")) {
      method_name = RESTMETHOD_PUT;
    } else {
      method_name = RESTMETHOD_OTHER;
    }

    enum ConnInfoType cit = 0;
    if (method_name == RESTMETHOD_POST) {
      if (call_name == RESTAPI_UPLOAD) {
        cit = CIT_POST_FORM;
      } else {
        cit = CIT_POST_RAW;
      }
    } else {
      cit = CIT_OTHER;
    }
    ci = ConnInfo_create(cit, method_name, call_name, app);
    CHECK(ci != NULL, "Couldn't create con_cls");
    new_con_cls = 1;
    *con_cls = ci;
  }

  ci = *con_cls;
  ci->invocations++;

  switch (ci->api_call_name) {
  case RESTAPI_GET_SNIPPET:
    ret = mhd_api_get_snippet(connection, ci);
    goto exit;
  case RESTAPI_CREATE_SNIPPET:
    ret = mhd_api_create_snippet(connection, ci, upload_data, upload_data_size);
    goto exit;
  case RESTAPI_FIND_SNIPPETS:
    ret = mhd_api_find_snippets(connection, ci);
    goto exit;
  case RESTAPI_DELETE_SNIPPET:
    ret = mhd_api_delete_snippet(connection, ci);
    goto exit;
  case RESTAPI_UPLOAD:
    ret = mhd_api_upload(connection, ci, upload_data, upload_data_size);
    goto exit;
  default:
    MHD_RESPONSE_WITH_TAGBSTRING(
        connection, MHD_HTTP_OK, response, status_ok, ret);
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
  int err = 0;
  struct evhttp *http = NULL;
  struct evhttp_bound_socket *handle = NULL;
  struct YNoteApp *app = NULL;
  struct event *intterm_event = NULL;

  if (argc != 3) {
    goto usage;
  }

  app = ynote_app_create(argc, argv);
  CHECK(app != NULL, "Couldn't create app");
  CHECK(
      (http = evhttp_new(app->evbase)) != NULL,
      "Couldn't initialize http handle");

  evhttp_set_default_content_type(http, "text/html");

  CHECK(
      (handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", app->port)) !=
          NULL,
      "Couldn't bind to a socket");

  if (app->tg_bot_enabled) {
    CHECK(http_client_init(app) == 0, "Couldn't initialize http client");

    http_client_get_updates_req(app);
  }

  evhttp_set_cb(
      http,
      "/api/create_snippet",
      (void (*)(struct evhttp_request *, void *))ev_json_api_create_snippet,
      app);

  evhttp_set_cb(
      http,
      "/api/find_snippets",
      (void (*)(struct evhttp_request *, void *))json_api_find_snippets,
      app);

  evhttp_set_cb(
      http,
      "/api/get_snippet",
      (void (*)(struct evhttp_request *, void *))ev_json_api_get_snippet,
      app);

  evhttp_set_cb(
      http,
      "/api/delete_snippet",
      (void (*)(struct evhttp_request *, void *))ev_json_api_delete_snippet,
      app);

  evhttp_set_cb(
      http,
      "/api/upload",
      (void (*)(struct evhttp_request *, void *))api_upload_file,
      app);

  evhttp_set_gencb(
      http, (void (*)(struct evhttp_request *, void *))json_api_cb, app);

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
  LOG_INFO("mhd port %d", app->mhd_port);

  daemon = MHD_start_daemon(
      MHD_USE_EPOLL_INTERNAL_THREAD | MHD_USE_ERROR_LOG,
      app->mhd_port,
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

  LOG_INFO("Server started, port %d, mhd_port %d", app->port, app->mhd_port);

  event_base_dispatch(app->evbase);
  // event_base_loop(app->evbase, EVLOOP_ONCE);
  //

exit:
  if (app != NULL) {
    ynote_app_destroy(app);
  }
  curl_global_cleanup();
  return rc;
error:
  rc = 1;
  goto exit;
usage:
  printf(USAGE, argv[0]);
  goto error;
}
