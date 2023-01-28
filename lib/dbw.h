#ifndef _DBW_H_
#define _DBW_H_

#include <bbstrlib.h>
#include <bstrlib.h>
#include <json.h>
#include <md4c.h>
#include <rvec.h>
#include <sqlite3.h>

#define SNIPPETS_TABLE        "snippets"
#define SNIPPETS_VIEW_TABLE        "snippets_view"
#define SNIPPET_TYPES_TABLE   "snippet_types"
#define TAGS_TABLE            "tags"
#define SNIPPET_TO_TAGS_TABLE "snippet_to_tags"
#define FILES_TABLE           "files"
#define FILES_TO_TAGS_TABLE   "files_to_tags"

static struct tagbstring s_true = bsStatic("true");

static const struct tagbstring status_ok = bsStatic("{\"status\": \"ok\"}");

static const struct tagbstring status_method_not_allowed =
    bsStatic("{\"status\": \"error\", \"msg\": \"method not allowed\"}");

static const struct tagbstring status_wrong_path =
    bsStatic("{\"status\": \"error\", \"msg\": \"wrong path\"}");

static const struct tagbstring status_couldnt_open =
    bsStatic("{\"status\": \"error\", \"msg\": \"couldn't open file\"}");

static const struct tagbstring status_couldnt_stat =
    bsStatic("{\"status\": \"error\", \"msg\": \"couldn't stat file\"}");

static const struct tagbstring status_wrong_file_type =
    bsStatic("{\"status\": \"error\", \"msg\": \"wrong file type\"}");

static const struct tagbstring status_server_error =
    bsStatic("{\"status\": \"error\", \"msg\": \"server error\"}");

static const struct tagbstring status_bad_request =
    bsStatic("{\"status\": \"error\", \"msg\": \"bad request\"}");

static const struct tagbstring status_id_required =
    bsStatic("{\"status\": \"error\", \"msg\": \"id required\"}");

static const struct tagbstring status_not_found =
    bsStatic("{\"status\": \"error\", \"msg\": \"not found\"}");

static const struct tagbstring status_not_implemented =
    bsStatic("{\"status\": \"error\", \"msg\": \"not implemented\"}");

static const struct tagbstring status_snippet_not_found =
    bsStatic("{\"status\": \"error\", \"msg\": \"snippet not found\"}");

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

typedef enum DBWType {
  DBW_INTEGER,
  DBW_UNKN,

} DBWType;

typedef enum DBWResType {
  DBW_TUPLES = 0,
  DBW_TYPES,
} DBWResType;

typedef enum DBWError {
  DBW_OK = 0,
  DBW_ERR = -1,
  DBW_ERR_NOT_FOUND = -2,
  DBW_ERR_UNKN_DB = -3,
  DBW_ERR_ALREADY_EXISTS = -4,
} DBWDBError;

typedef struct DBWResult {
  int res_type;
  rvec_t(bstring) head_vec;
  union {
    rvec_t(bstring) res_vec;
    rvec_t(int) types_vec;
  };
} DBWResult;

typedef enum DBWDBType {
  DBW_POSTGRESQL,
  DBW_SQLITE3,
} DBWDBType;

typedef struct DBWHandler {
  int DBWDBType;
  void *conn;
} DBWHandler;

DBWHandler *dbw_connect(DBWDBType DBWDBType, const bstring url, int *err);
DBWResult *dbw_get_table_types(DBWHandler *h, const bstring table, int *err);
DBWResult *dbw_query(DBWHandler *h, const bstring query, int *err);
int dbw_close(DBWHandler *h);
int dbw_print(DBWResult *res);
int DBWResult_destroy(DBWResult *res);
sqlite_int64 dbw_new_snippet(
    DBWHandler *h,
    const bstring title,
    const bstring snippet,
    const bstring type,
    const bstrListEmb *tags,
    sqlite_int64 dir,
    int *err);

bstring dbw_find_snippets(
    DBWHandler *h,
    const bstring title,
    const bstring type,
    const bstrListEmb *tags,
    int *ret_err);

bstring dbw_get_snippet(DBWHandler *h, sqlite_int64 id, enum DBWError *err);

sqlite_int64 dbw_edit_snippet(
    DBWHandler *h,
    const sqlite_int64 id,
    const bstring title,
    const bstring snippet,
    const bstring type,
    const bstrListEmb *tags,
    char deleted,
    int *err);

bstring dbw_register_file(
    DBWHandler *h,
    const bstring path,
    const bstring filename,
    const bstring location,
    const bstring type,
    const bstrListEmb *tags,
    int *err);

bstring json_api_create_snippet(
    struct DBWHandler *db_handle,
    bstring json_req,
    sqlite_int64 snippet_id,
    int edit,
    int *ec);

bstring json_api_find_snippets(
    struct DBWHandler *db_handle,
    bstring title,
    bstring type,
    bstring tags,
    int *ec);

bstring json_api_get_snippet(
    struct DBWHandler *db_handle, sqlite_int64 id, int render, int *ec);
sqlite_int64 dbw_path_descend(DBWHandler *h, bstring path, enum DBWError *err);

bstring
dbw_snippet_path_ascend(DBWHandler *h, sqlite_int64 id, enum DBWError *err);

#endif
