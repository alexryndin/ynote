#include <bstrlib.h>
#include <bbstrlib.h>
#include <json.h>
#include <md4c.h>
#include <rvec.h>
#include <sqlite3.h>

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

sqlite_int64 dbw_register_file(
    DBWHandler *h,
    const bstring filename,
    const bstring location,
    const bstring type,
    const bstrListEmb *tags,
    int *err);
