#include <bstrlib.h>
#include <dbg.h>
#include <dbw.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <json.h>
#include <stdlib.h>

#ifndef BUF_LEN
#define BUF_LEN 4096
#endif

#define JSON_GET_ITEM(json, obj, index)                            \
    do {                                                           \
                                                                   \
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
    void *db_handle;
};

static void
json_api_cb(struct evhttp_request *req, const struct WNContext *wctx) {
    int rc = 200;
    int ec = 0;
    char *reason = "OK";
    char *cbuf = NULL;
    char *bad_request_msg = NULL;
    struct evbuffer *ibuf = NULL;
    struct evbuffer *resp = NULL;
    bstring json_str = NULL;
    struct bstrList *tags = NULL;
    struct tagbstring *tags_array = NULL;

    tags = calloc(1, sizeof(struct bstrList));
    CHECK_MEM(tags);

    cbuf = malloc(BUF_LEN);
    CHECK_MEM(cbuf);

    resp = evbuffer_new();
    CHECK_MEM(resp);

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

    json_value *json = json_parse(bdata(json_str), blength(json_str));

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
    if (jtitle == NULL || jtitle->type != json_string) {
        bad_request_msg = "title required and must be string";
        goto bad_request;
    }

    JSON_GET_ITEM(json, jcontent, "content");
    if (jcontent == NULL || jcontent->type != json_string) {
        bad_request_msg = "content required and must be string";
        goto bad_request;
    }

    JSON_GET_ITEM(json, jtype, "type");
    if (jtype == NULL || jtype->type != json_string) {
        bad_request_msg = "type required and must be string";
        goto bad_request;
    }

    json_value *jtags = NULL;
    JSON_GET_ITEM(json, jtags, "tags");
    if (jtags != NULL && jtags->type == json_array) {

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

    btfromcstr(title, jtitle->u.string.ptr);
    btfromcstr(content, jcontent->u.string.ptr);
    btfromcstr(type, jtype->u.string.ptr);

    ec = dbw_new_snippet(wctx->db_handle, &title, &content, &type, tags);
    if (ec == DBW_ERR_NOT_FOUND) {
        bad_request_msg = "wrong type";
        goto bad_request;
    } else if (ec != DBW_OK) {
        goto error;
    }

    evhttp_add_header(
        evhttp_request_get_output_headers(req),
        "Content-Type",
        "application/json");

    CHECK(
        evbuffer_add_printf(resp, "OK"), "Couldn't append to response buffer");

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

bad_request:
    rc = 403;
    reason = "Bad Request";
    bad_request_msg = bad_request_msg == NULL ? "Bad request" : bad_request_msg;
    CHECK(
        evbuffer_add_printf(resp, "%s", bad_request_msg),
        "Couldn't append to response buffer");
    goto exit;
}

int main() {
    int rc = 0;
    rc = 0;
    int err = 0;
    struct event_base *base = NULL;
    struct evhttp *http = NULL;
    struct evhttp_bound_socket *handle = NULL;
    struct tagbstring dbpath = bsStatic("test.db");
    struct WNContext *wctx = NULL;
    DBWHandler *db = NULL;

    CHECK((base = event_base_new()) != NULL, "Couldn't initialize event base");
    CHECK((http = evhttp_new(base)) != NULL, "Couldn't initialize http handle");

    CHECK_MEM(wctx = calloc(1, sizeof(struct WNContext)));

    evhttp_set_default_content_type(http, "text/html");

    handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", atoi("8080"));

    db = dbw_connect(DBW_SQLITE3, &dbpath, &err);
    CHECK(err == 0, "Couldn't connect to database");

    wctx->db_handle = db;

    evhttp_set_gencb(
        http, (void (*)(struct evhttp_request *, void *))json_api_cb, wctx);

    event_base_dispatch(base);
exit:
    return rc;
error:
    rc = 1;
    goto exit;
}
