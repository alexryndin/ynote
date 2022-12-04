#ifndef _YNOTE_H_
#define _YNOTE_H_

#include <dbw.h>
#include <httpaux.h>
#include <ldbw.h>

#define MHD_RESPONSE_WITH_BSTRING(connection, status, response, s, ret)      \
  do {                                                                       \
    MHD_RESPONSE_WITH_BSTRING_CT(                                            \
        (connection), (status), (response), (s), (ret), "application/json"); \
  } while (0)

#define MHD_RESPONSE_WITH_BSTRING_CT(connection, status, response, s, ret, ct) \
  do {                                                                         \
    (response) = MHD_create_response_from_buffer_with_free_callback_cls(       \
        blength((s)),                                                          \
        bdata((s)),                                                            \
        (MHD_ContentReaderFreeCallback)bdestroy_silent,                        \
        (s));                                                                  \
    MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, (ct));     \
    (ret) = MHD_queue_response((connection), (status), (response));            \
    MHD_destroy_response((response));                                          \
    goto exit;                                                                 \
                                                                               \
  } while (0)

#define MHD_RESPONSE_REDIRECT_TB(connection, status, s, ret)            \
  do {                                                                  \
    (response) =                                                        \
        MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT); \
    CHECK(response != NULL, "NULL resp");                               \
    MHD_add_response_header(response, "Location", bdata(s));            \
    (ret) = MHD_queue_response((connection), (status), (response));     \
    MHD_destroy_response((response));                                   \
    goto exit;                                                          \
  } while (0)

#define MHD_RESPONSE_REDIRECT_B(connection, status, s, ret)             \
  do {                                                                  \
    (response) =                                                        \
        MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT); \
    CHECK(response != NULL, "NULL resp");                               \
    MHD_add_response_header(response, "Location", bdata(s));            \
    bdestroy(s);                                                        \
    (ret) = MHD_queue_response((connection), (status), (response));     \
    MHD_destroy_response((response));                                   \
    goto exit;                                                          \
  } while (0)

#define MHD_RESPONSE_WITH_TAGBSTRING(connection, status, response, s, ret) \
  do {                                                                     \
    (response) = MHD_create_response_from_buffer(                          \
        blength(&(s)), bdata(&(s)), MHD_RESPMEM_PERSISTENT);               \
    MHD_add_response_header(                                               \
        response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");       \
    (ret) = MHD_queue_response((connection), (status), (response));        \
    MHD_destroy_response((response));                                      \
    goto exit;                                                             \
                                                                           \
  } while (0)

struct YNoteApp;

struct LuaCtx {
  struct LDBWCtx* ldbwctx;
  struct ConnInfo* ci;
  struct MHD_Connection *conn;
};

DBWHandler *ynote_get_db_handle(struct LuaCtx *luactx);

struct ConnInfo *ynote_get_conn_info (struct LuaCtx* lc);
struct LDBWCtx *ynote_get_ldbwctx (struct LuaCtx* lc);
int ynote_get_port(struct LuaCtx *lc);

#endif
