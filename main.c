#include <bstrlib.h>
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

#ifndef BUF_LEN
#define BUF_LEN 4096
#endif

#define USAGE "Usage: %s db_path\n"

static struct tagbstring __true = bsStatic("true");

#define INTERNAL_ERROR_HANDLE                            \
    error:                                               \
    rc = 500;                                            \
    reason = "Internal Server Error";                    \
    if (resp != NULL) {                                  \
        evbuffer_drain(resp, evbuffer_get_length(resp)); \
        if (evbuffer_add_printf(resp, "500") <= 0) {     \
            evbuffer_free(resp);                         \
            resp = NULL;                                 \
        };                                               \
    }                                                    \
    goto exit

#define BAD_REQ_HANDLE                                             \
    bad_request:                                                   \
    rc = 403;                                                      \
    reason = "Bad Request";                                        \
    bad_request_msg =                                              \
        bad_request_msg == NULL ? "Bad request" : bad_request_msg; \
    CHECK(                                                         \
        evbuffer_add_printf(                                       \
            resp,                                                  \
            "{\"status\": \"error\", \"msg\": \"%s\"}",            \
            bad_request_msg),                                      \
        "Couldn't append to response buffer");                     \
    goto exit

#define PARSE_INT(func, num_str, num, rc)                \
    do {                                                 \
        errno = 0;                                       \
        char *end;                                       \
        (num) = (func)((num_str), &end, 10);             \
        if ((num_str) == end) {                          \
            (rc) = 1;                                    \
            break;                                       \
        }                                                \
        const char range_error = errno == ERANGE;        \
        if (range_error) {                               \
            LOG_ERR("Malformed string -- range error."); \
            rc = 2;                                      \
            errno = 0;                                   \
            break;                                       \
        }                                                \
                                                         \
    } while (0)

#define JSON_GET_ITEM(json, obj, index)                            \
    do {                                                           \
                                                                   \
        if ((json) == NULL) {                                      \
            obj = NULL;                                            \
            break;                                                 \
        }                                                          \
        if (json->type != json_object) {                           \
            obj = NULL;                                            \
            break;                                                 \
        }                                                          \
                                                                   \
        for (unsigned int i = 0; i < json->u.object.length; ++i) { \
            if (!strcmp(json->u.object.values[i].name, index)) {   \
                obj = (json->u).object.values[i].value;            \
                break;                                             \
            }                                                      \
        }                                                          \
    } while (0)

struct WNContext {
    struct event_base *base;
    void *db_handle;
};

// Sigint sigterm handler
static void sigint_term_handler(int sig, short events, void *arg) {
    struct WNContext *wctx = arg;
    CHECK(wctx != NULL, "Null contenxt");
    CHECK(wctx->base != NULL, "Null base");
    CHECK(wctx->db_handle != NULL, "Null db_handle");

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
    event_base_loopexit(wctx->base, NULL);
    CHECK(
        dbw_close(wctx->db_handle) == DBW_OK,
        "Couldn't close database connetcion");
error:
    return;
}

static void
json_api_cb(struct evhttp_request *req, const struct WNContext *wctx) {
    char *reason = "OK";
    int rc = 200;
    struct evbuffer *resp = NULL;

    (void)wctx;

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
        CHECK(
            json_tmp != NULL && json_tmp->type == json_string,
            "Incorrect json");

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
            (new_json_str = bfromcstralloc(json_measure_ex(json, jso), "")) !=
                NULL,
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
json_api_get_snippet(struct evhttp_request *req, const struct WNContext *wctx) {
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
            evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req)),
            &queries) == 0,
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
    if (edit_str != NULL && biseqcstrcaseless(&__true, edit_str)) {
        edit = 1;
    }
    LOG_DEBUG("json_api_got_snippet got %lld", id);
    json_str_res = dbw_get_snippet(wctx->db_handle, id, &err);
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

static void json_api_find_snippets(
    struct evhttp_request *req, const struct WNContext *wctx) {
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
            evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req)),
            &queries) == 0,
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
        dbw_find_snippets(wctx->db_handle, NULL, &snippet_type, taglist, &err);

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
    struct evhttp_request *req, const struct WNContext *wctx) {
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
            evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req)),
            &queries) == 0,
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
        wctx->db_handle, snippet_id, NULL, NULL, NULL, NULL, 1, &err);
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
    struct evhttp_request *req, const struct WNContext *wctx) {
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
            evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req)),
            &queries) == 0,
        "Couldn't parse query str");

    tmp_cstr = (char *)evhttp_find_header(&queries, "edit");
    if (tmp_cstr != NULL) {
        LOG_DEBUG("tmp_cstr %s", tmp_cstr);
        if (biseqcstrcaseless(&__true, tmp_cstr)) {
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
#define CHECK_J(tbstr, edit)                                             \
    do {                                                                 \
        if (!(edit)) {                                                   \
            if ((j##tbstr) == NULL || (j##tbstr)->type != json_string) { \
                bad_request_msg = #tbstr " required and must be string"; \
                goto bad_request;                                        \
            }                                                            \
        } else {                                                         \
            if ((j##tbstr) != NULL && (j##tbstr)->type != json_string) { \
                bad_request_msg = #tbstr " must be string";              \
                goto bad_request;                                        \
            }                                                            \
        }                                                                \
        if ((j##tbstr) != NULL) {                                        \
            btfromcstr(tbstr, (j##tbstr)->u.string.ptr);                 \
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
            wctx->db_handle,
            snippet_id,
            &title,
            &content,
            &type,
            tags,
            0,
            &err);
    } else {
        snippet_id = dbw_new_snippet(
            wctx->db_handle, &title, &content, &type, tags, &err);
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

int main(int argc, char *argv[]) {
    int rc = 0;
    rc = 0;
    int err = 0;
    int port = 8080;
    struct event_base *base = NULL;
    struct evhttp *http = NULL;
    struct evhttp_bound_socket *handle = NULL;
    struct tagbstring dbpath = {0};
    struct WNContext *wctx = NULL;
    struct event *intterm_event = NULL;
    DBWHandler *db = NULL;

    if (argc != 2 && argc != 3) {
        goto usage;
    }

    if (argc == 3) {
        PARSE_INT(strtol, argv[2], port, rc);
        CHECK(rc == 0, "Couldn't parse port");
    }

    btfromcstr(dbpath, argv[1]);

    CHECK((base = event_base_new()) != NULL, "Couldn't initialize event base");
    CHECK((http = evhttp_new(base)) != NULL, "Couldn't initialize http handle");

    CHECK_MEM(wctx = calloc(1, sizeof(struct WNContext)));

    evhttp_set_default_content_type(http, "text/html");

    CHECK(
        (handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", port)) !=
            NULL,
        "Couldn't bind to a socket");

    db = dbw_connect(DBW_SQLITE3, &dbpath, &err);
    CHECK(err == 0, "Couldn't connect to database");

    wctx->db_handle = db;
    wctx->base = base;

    evhttp_set_cb(
        http,
        "/api/create_snippet",
        (void (*)(struct evhttp_request *, void *))json_api_create_snippet,
        wctx);

    evhttp_set_cb(
        http,
        "/api/find_snippets",
        (void (*)(struct evhttp_request *, void *))json_api_find_snippets,
        wctx);

    evhttp_set_cb(
        http,
        "/api/get_snippet",
        (void (*)(struct evhttp_request *, void *))json_api_get_snippet,
        wctx);

    evhttp_set_cb(
        http,
        "/api/delete_snippet",
        (void (*)(struct evhttp_request *, void *))json_api_delete_snippet,
        wctx);

    evhttp_set_gencb(
        http, (void (*)(struct evhttp_request *, void *))json_api_cb, wctx);

    CHECK(
        (intterm_event =
             evsignal_new(base, SIGTERM, sigint_term_handler, wctx)) != NULL,
        "Couldn't create sigterm handler");
    CHECK(
        event_add(intterm_event, NULL) == 0,
        "Couldn't add sigterm handler to event loop");

    CHECK(
        (intterm_event =
             evsignal_new(base, SIGINT, sigint_term_handler, wctx)) != NULL,
        "Couldn't create sigint handler");
    CHECK(
        event_add(intterm_event, NULL) == 0,
        "Couldn't add sigint handler to event loop");

    LOG_INFO("Server started");
    event_base_dispatch(base);

exit:
    return rc;
error:
    rc = 1;
    goto exit;
usage:
    printf(USAGE, argv[0]);
    goto error;
}
