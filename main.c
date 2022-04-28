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
#include <md4c-html.h>
#include <md4c.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>

#ifndef BUF_LEN
#define BUF_LEN 4096
#endif

#define USAGE "Usage: %s db_path\n"

static struct tagbstring s_true = bsStatic("true");

static const char *const getUpdatesUrl =
    "https://api.telegram.org/bot%s/getUpdates?timeout=%d&offset=%d";

static const char *const sendMessagelUrl =
    "https://api.telegram.org/bot%s/sendMessage?chat_id=%d&text=%s";

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
          resp, "{\"status\": \"error\", \"msg\": \"%s\"}", bad_request_msg),  \
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
  uint timeout;
  uint updates_offset;
  struct UsersInfo users_info;
  void *db_handle;
  CURLM *curl_multi;
  bstring tg_token;
  struct event *http_client_timer_event;
  int http_clients_running;
  bstring dbpath;
};

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
  PARSE_INT(strtoll, bdata(str_id), id, err);
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
      json_tmp != NULL && json_tmp->type == json_string && !strcmp(json_tmp->u.string.ptr, "ok"),
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
          app->timeout,
          app->updates_offset + 1);
    } else if (req_type == TG_SEND_MSG) {
      req_info->url =
          bformat(sendMessagelUrl, bdata(app->tg_token), app->timeout, data);
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
  int timeout = 60;
  FILE *conf = NULL;
  json_value *json_conf = NULL;
  json_value *json_tmp = NULL;
  struct stat filestat;
  bstring tmp_str = NULL;

  CHECK(path != NULL, "Null path");
  CHECK(app != NULL, "Null app");

  CHECK(stat(bdatae(path, ""), &filestat) == 0, "Couldn't get filestat");

  CHECK(S_ISREG(filestat.st_mode), "Config is not a file");
  CHECK(filestat.st_size < 4 * 1024 * 1024L, "Conf file is too big");

  CHECK((conf = fopen(bdata(path), "r")) != NULL, "Couldn't open config");

  tmp_str = bread((bNread)fread, conf);
  CHECK(tmp_str != NULL, "Couldn't read conf");

  json_conf = json_parse(bdata(tmp_str), blength(tmp_str));
  CHECK(json_conf != NULL, "Couldn't parse conf");

  CHECK(json_conf->type == json_object, "Incorrect json");

  JSON_GET_ITEM(json_conf, json_tmp, "tg_token");
  CHECK(json_tmp != NULL && json_tmp->type == json_string, "Incorrect json");

  app->tg_token = bfromcstr(json_tmp->u.string.ptr);
  CHECK(app->tg_token != NULL, "Failed to read tg_token");
  CHECK(blength(app->tg_token) > 0, "Empty config");

  JSON_GET_ITEM(json_conf, json_tmp, "client_timeout");
  if (json_tmp != NULL && json_tmp->type == json_integer &&
      json_tmp->u.integer > 0) {
    timeout = json_tmp->u.integer;
  };

  app->timeout = timeout;

  JSON_GET_ITEM(json_conf, json_tmp, "dbpath");
  CHECK(
      json_tmp != NULL && json_tmp->type == json_string,
      "Incorrect json, dbpath expected");
  app->dbpath = bfromcstr(json_tmp->u.string.ptr);
  CHECK(app->dbpath != NULL, "Coudln't create string");

  rc = 0;

  app->users_info.u.id = 332994181;
  app->users_info.u.allowed = 1;
  // fallthrough
exit:
  if (conf != NULL) {
    fclose(conf);
  }
  if (json_conf != NULL) {
    json_value_free(json_conf);
  }
  if (tmp_str != NULL) {
    bdestroy(tmp_str);
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

static void
json_api_get_snippet(struct evhttp_request *req, const struct YNoteApp *app) {
  char *reason = "OK";
  int ret_code = 200;
  int err = 0;
  struct evbuffer *resp = NULL;
  char edit = 0;
  const char *id_str = NULL;
  const char *edit_str = NULL;
  sqlite_int64 id = 0;
  struct evkeyvalq queries;
  char *bad_request_msg = NULL;
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
    bad_request_msg = "id required";
    goto bad_request;
  }
  PARSE_INT(strtoll, id_str, id, rc);
  if (rc == 1) {
    bad_request_msg = "{\"status\": \"malformed id\"}";
    goto bad_request;
  }
  edit_str = evhttp_find_header(&queries, "edit");
  if (edit_str != NULL && biseqcstrcaseless(&s_true, edit_str)) {
    edit = 1;
  }
  LOG_DEBUG("json_api_got_snippet got %lld", id);
  json_str_res = dbw_get_snippet(app->db_handle, id, &err);
  if (err == DBW_ERR_NOT_FOUND) {
    bad_request_msg = "{\"status\": \"snippet not found\"}";
    goto bad_request;
  }
  CHECK(
      json_str_res != NULL && blength(json_str_res) > 0 && err == DBW_OK,
      "Couldn't get snippets");

  if (!edit) {
    CHECK(render_json(&json_str_res) == 0, "Couldn't render json");
  }

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
  struct bstrList *taglist = NULL;
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
      taglist = bstrListCreate();
    } else {
      struct tagbstring tagstr = {0};
      btfromcstr(tagstr, tmp_cstr);
      LOG_DEBUG("%s, %s", tmp_cstr, bdata(&tagstr));
      taglist = bsplit(&tagstr, ',');
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
    bstrListDestroy(taglist);
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

static void json_api_delete_snippet(
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
  snippet_id = dbw_edit_snippet(
      app->db_handle, snippet_id, NULL, NULL, NULL, NULL, 1, &err);
  CHECK(
      evbuffer_add_printf(
          resp, "{\"status\": \"ok\", \"id\": %lld}", snippet_id) > 0,
      "Couldn't append to response buffer");
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
static void json_api_create_snippet(
    struct evhttp_request *req, const struct YNoteApp *app) {
  int rc = 200;
  int err = 0;
  char *reason = "OK";
  char *cbuf = NULL;
  char *bad_request_msg = NULL;
  struct evbuffer *ibuf = NULL;
  struct evbuffer *resp = NULL;
  bstring json_str = NULL;
  struct bstrList *tags = NULL;
  struct tagbstring *tags_array = NULL;
  json_value *json = NULL;
  sqlite_int64 snippet_id = 0;
  struct evkeyvalq queries = {0};
  char edit = 0;
  bstring tmp_str = NULL;
  char *tmp_cstr = NULL;

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

  json = json_parse(bdata(json_str), blength(json_str));

  if (json == NULL) {
    bad_request_msg = "JSON Malformed";
    goto bad_request;
  }
  if ((json->type) != json_object) {
    bad_request_msg = "Dict required";
    goto bad_request;
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
#define CHECK_J(tbstr, edit)                                       \
  do {                                                             \
    if (!(edit)) {                                                 \
      if ((j##tbstr) == NULL || (j##tbstr)->type != json_string) { \
        bad_request_msg = #tbstr " required and must be string";   \
        goto bad_request;                                          \
      }                                                            \
    } else {                                                       \
      if ((j##tbstr) != NULL && (j##tbstr)->type != json_string) { \
        bad_request_msg = #tbstr " must be string";                \
        goto bad_request;                                          \
      }                                                            \
    }                                                              \
    if ((j##tbstr) != NULL) {                                      \
      btfromcstr(tbstr, (j##tbstr)->u.string.ptr);                 \
    }                                                              \
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

    tags = calloc(1, sizeof(struct bstrList));
    CHECK_MEM(tags);

    /* Manual bstrList handling to eliminate unnecessary mallocs */
    tags->entry = calloc(jtags->u.array.length, sizeof(bstring));
    CHECK_MEM(tags->entry);
    tags_array = calloc(jtags->u.array.length, sizeof(struct tagbstring));
    CHECK_MEM(tags_array);

    for (unsigned int i = 0; i < jtags->u.array.length; i++) {
      if (jtags->u.array.values[i]->type != json_string) {
        bad_request_msg = "tags must be an array of strings";
        goto bad_request;
      }
      blk2tbstr(
          tags_array[i],
          jtags->u.array.values[i]->u.string.ptr,
          jtags->u.array.values[i]->u.string.length);

      tags->entry[i] = &tags_array[i];
    }
    tags->qty = jtags->u.array.length;
    tags->mlen = -1;
  }

  if (edit) {
    snippet_id = dbw_edit_snippet(
        app->db_handle, snippet_id, &title, &content, &type, tags, 0, &err);
  } else {
    snippet_id =
        dbw_new_snippet(app->db_handle, &title, &content, &type, tags, &err);
  }
  if (err == DBW_ERR_NOT_FOUND) {
    bad_request_msg = "wrong type";
    goto bad_request;
  } else if (err == DBW_ERR_ALREADY_EXISTS) {
    bad_request_msg = "already exists error. possibly snippet with this "
                      "title alredy exists";
    goto bad_request;

  } else if (err != DBW_OK) {
    goto error;
  }

  evhttp_add_header(
      evhttp_request_get_output_headers(req),
      "Content-Type",
      "application/json");

  CHECK(
      evbuffer_add_printf(
          resp, "{\"status\": \"ok\", \"id\": %lld}", snippet_id) > 0,
      "Couldn't append to response buffer");

exit:
  if (tags != NULL) {
    if (tags->entry != NULL) {
      free(tags->entry);
    }
    free(tags);
  }
  if (tags_array != NULL) {
    free(tags_array);
  }
  if (cbuf != NULL) {
    free(cbuf);
  }
  if (json != NULL) {
    json_value_free(json);
  }
  if (tmp_str != NULL) {
    bdestroy(tmp_str);
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

struct YNoteApp *ynote_app_create(bstring conf_path) {
  struct YNoteApp *ret = NULL;
  int err = 0;

  CHECK(bdata(conf_path) != NULL, "Null conf_path");

  CHECK_MEM(ret = calloc(1, sizeof(struct YNoteApp)));

  CHECK(read_config(ret, conf_path) == 0, "Couldn't read config");

  CHECK(
      (ret->evbase = event_base_new()) != NULL,
      "Couldn't initialize event base");
  CHECK(
      (ret->http_client_timer_event =
           evtimer_new(ret->evbase, http_client_timer_cb, ret)) != NULL,
      "Couldn't initialize timer");
  ret->db_handle = dbw_connect(DBW_SQLITE3, ret->dbpath, &err);
  CHECK(err == 0, "Couldn't connect to database");
  return ret;

error:
  if (ret != NULL) {
    ynote_app_destroy(ret);
  }
  return NULL;
}

int main(int argc, char *argv[]) {
  int rc = 0;
  rc = 0;
  int err = 0;
  int port = 8080;
  struct evhttp *http = NULL;
  struct evhttp_bound_socket *handle = NULL;
  struct YNoteApp *app = NULL;
  struct event *intterm_event = NULL;
  struct tagbstring conf_path = bsStatic("./ynote.json");
  DBWHandler *db = NULL;

  if (argc != 2 && argc != 3 && argc != 4) {
    goto usage;
  }

  if (argc == 3) {
    PARSE_INT(strtol, argv[2], port, rc);
    CHECK(rc == 0, "Couldn't parse port");
  }

  if (argc == 4) {
    btfromcstr(conf_path, argv[3]);
  }

  app = ynote_app_create(&conf_path);
  CHECK(app != NULL, "Couldn't create app");
  CHECK(
      (http = evhttp_new(app->evbase)) != NULL,
      "Couldn't initialize http handle");

  evhttp_set_default_content_type(http, "text/html");

  CHECK(
      (handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", port)) != NULL,
      "Couldn't bind to a socket");

  CHECK(http_client_init(app) == 0, "Couldn't initialize http client");

  http_client_get_updates_req(app);

  evhttp_set_cb(
      http,
      "/api/create_snippet",
      (void (*)(struct evhttp_request *, void *))json_api_create_snippet,
      app);

  evhttp_set_cb(
      http,
      "/api/find_snippets",
      (void (*)(struct evhttp_request *, void *))json_api_find_snippets,
      app);

  evhttp_set_cb(
      http,
      "/api/get_snippet",
      (void (*)(struct evhttp_request *, void *))json_api_get_snippet,
      app);

  evhttp_set_cb(
      http,
      "/api/delete_snippet",
      (void (*)(struct evhttp_request *, void *))json_api_delete_snippet,
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

  LOG_INFO("Server started");
  event_base_dispatch(app->evbase);
  // event_base_loop(app->evbase, EVLOOP_ONCE);

exit:
  ynote_app_destroy(app);
  curl_global_cleanup();
  return rc;
error:
  rc = 1;
  goto exit;
usage:
  printf(USAGE, argv[0]);
  goto error;
}
