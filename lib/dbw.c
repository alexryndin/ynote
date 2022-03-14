#include "dbw.h"
#include "dbg.h"
#include "json-builder.h"
#include "json.h"
#include <bstrlib.h>
#include <rvec.h>
#include <sqlite3.h>
#include <stdlib.h>

#define SNIPPETS_TABLE        "snippets"
#define TAGS_TABLE            "tags"
#define SNIPPET_TO_TAGS_TABLE "snippet_to_tags"

const struct tagbstring _insert_snippet_sql =
    bsStatic("INSERT INTO " SNIPPETS_TABLE
             " (title, content, type) VALUES (?, ?, ?) RETURNING id");

const struct tagbstring _insert_snippet_to_tags_sql = bsStatic(
    "INSERT OR IGNORE INTO " SNIPPET_TO_TAGS_TABLE
    " (snippet_id, tag_id) SELECT ?, id FROM " TAGS_TABLE " WHERE name IN (");

// statics and helpers
static struct tagbstring __integer = bsStatic("integer");

// forward declarations
static DBWResult *DBWResult_create(int t);

// ******************************
// * SQLite
// ******************************

static json_value *sqlite3_find_snippets(
    DBWHandler *h,
    const bstring title,
    const bstring type,
    const struct bstrList *tags,
    int *ret_err) {
    int err = 0;
    int rc = SQLITE_OK;
    sqlite3_int64 type_id = 0;
    sqlite3_int64 snippet_id = 0;
    sqlite3_stmt *stmt = NULL;
    json_value *json_ret = NULL;
    json_value *json_array_titles_ret = NULL;
    json_value *json_array_contents_ret = NULL;
    json_value *json_str = NULL;
    json_value *json_obj = NULL;
    bstring q = NULL;

    json_ret = json_object_new(0);
    CHECK_MEM(json_ret);
    json_array_titles_ret = json_array_new(0);
    CHECK_MEM(json_array_titles_ret);
    json_array_contents_ret = json_array_new(0);
    CHECK_MEM(json_array_contents_ret);
    json_obj = json_object_new(0);
    CHECK_MEM(json_obj);

    CHECK(
        json_object_push(json_ret, "result", json_obj) != NULL,
        "Couldn't create json");

    CHECK(
        json_object_push(json_obj, "title", json_array_titles_ret) != NULL,
        "Couldn't create json");

    CHECK(
        json_object_push(json_obj, "content", json_array_contents_ret) != NULL,
        "Couldn't create json");

    q = bfromcstr("SELECT title, content FROM " SNIPPETS_TABLE " WHERE 1=1;");
    CHECK(q != NULL, "Couldn't create query string");

    CHECK(
        sqlite3_prepare_v2(h->conn, bdata(q), blength(q) + 1, &stmt, NULL) ==
            SQLITE_OK,
        "Couldn't prepare statement: %s",
        sqlite3_errmsg(h->conn));

    LOG_DEBUG("query: %s", bdata(q));

    while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
        switch (err) {
        case SQLITE_ROW:
            json_str =
                json_string_new((json_char *)sqlite3_column_text(stmt, 0));
            CHECK_MEM(json_str);
            CHECK(
                json_array_push(json_array_titles_ret, json_str) != NULL,
                "Couldn't create json");
            json_str =
                json_string_new((json_char *)sqlite3_column_text(stmt, 1));
            CHECK_MEM(json_str);
            CHECK(
                json_array_push(json_array_contents_ret, json_str) != NULL,
                "Couldn't create json");
            break;
        default:
            LOG_ERR("Couldn't get row from table: %s", sqlite3_errmsg(h->conn));
            goto error;
        }
    }
    char *buf = malloc(json_measure(json_ret));
    json_serialize(buf, json_ret);
    LOG_DEBUG("generated json %s", buf);
    free(buf);

    bdestroy(q);
    q = NULL;

    if (ret_err != NULL) {
        *ret_err = DBW_OK;
    }

    /* fallthrough */
exit:
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    if (q != NULL) {
        bdestroy(q);
    }
    return json_ret;
error:
    if (json_ret != NULL) {
        json_builder_free(json_ret);
        json_ret = NULL;
    }
    if (ret_err != NULL) {
        *ret_err = DBW_ERR;
    }
    goto exit;
}

static int sqlite3_new_snippet(
    DBWHandler *h,
    const bstring title,
    const bstring snippet,
    const bstring type,
    const struct bstrList *tags) {
    int err = 0;
    int rc = SQLITE_OK;
    sqlite3_int64 type_id = 0;
    sqlite3_int64 snippet_id = 0;
    sqlite3_stmt *stmt = NULL;

    bstring q = NULL;
    bstring question_marks = NULL;

    // Step 1: get corresponding snippet type
    const struct tagbstring check_type_sql =
        bsStatic("select id from snippet_types where name = ?;");

    CHECK(
        sqlite3_prepare_v2(
            h->conn,
            bdata(&check_type_sql),
            blength(&check_type_sql) + 1,
            &stmt,
            NULL) == SQLITE_OK,
        "Couldn't prepare statement: %s",
        sqlite3_errmsg(h->conn));

    CHECK(
        sqlite3_bind_text(stmt, 1, bdata(type), -1, NULL) == SQLITE_OK,
        "Couldn't bind parameter to statement");

    CHECKRC(
        sqlite3_step(stmt) == SQLITE_ROW,
        DBW_ERR_NOT_FOUND,
        "Couldn't get snippet type %s",
        bdata(type));

    type_id = sqlite3_column_int64(stmt, 0);
    CHECK(sqlite3_finalize(stmt) == SQLITE_OK, "Couldn't finalize statement");

    // Step 2: ensure all tags are present in tags table
    if (tags->qty > 0) {
        q = bfromcstr("INSERT OR IGNORE INTO " TAGS_TABLE " (name) VALUES ");
        CHECK(q != NULL, "Couldn't create query string");

        question_marks = bfromcstr("(?),");
        CHECK(question_marks != NULL, "Couldn't create query string");

        // As many question marks as many tags we have
        CHECK(
            bpattern(question_marks, 4 * tags->qty - 1) == BSTR_OK,
            "Couldnt create query string");
        CHECK(
            bconcat(q, question_marks) == BSTR_OK,
            "Couldn't create query string");
        bdestroy(question_marks);
        question_marks = NULL;

        CHECK(
            sqlite3_prepare_v2(
                h->conn, bdata(q), blength(q) + 1, &stmt, NULL) == SQLITE_OK,
            "Couldn't prepare statement: %s",
            sqlite3_errmsg(h->conn));

        LOG_DEBUG("Statement is %s", bdata(q));

        for (unsigned int i = 0; i < tags->qty; i++) {
            CHECK(
                sqlite3_bind_text(
                    stmt, 1 + i, bdata(tags->entry[i]), -1, NULL) == SQLITE_OK,
                "Couldn't bind parameter (tag %s) to statement: %s",
                bdata(tags->entry[i]),
                sqlite3_errmsg(h->conn));
        }

        CHECK(sqlite3_step(stmt) == SQLITE_DONE, "Couldn't insert tags");

        CHECK(
            sqlite3_finalize(stmt) == SQLITE_OK, "Couldn't finalize statement");
        bdestroy(q);
        q = NULL;
    }

    // Step 3: insert snippet
    CHECK(
        sqlite3_prepare_v2(
            h->conn,
            bdata(&_insert_snippet_sql),
            blength(&_insert_snippet_sql) + 1,
            &stmt,
            NULL) == SQLITE_OK,
        "Couldn't prepare statement: %s",
        sqlite3_errmsg(h->conn));

    CHECK(
        sqlite3_bind_text(stmt, 1, bdata(title), -1, NULL) == SQLITE_OK,
        "Couldn't bind parameter to statement");

    CHECK(
        sqlite3_bind_text(stmt, 2, bdata(snippet), -1, NULL) == SQLITE_OK,
        "Couldn't bind parameter to statement");

    CHECK(
        sqlite3_bind_int64(stmt, 3, type_id) == SQLITE_OK,
        "Couldn't bind parameter to statement");

    err = sqlite3_step(stmt);
    if (err != SQLITE_ROW) {
        LOG_ERR("Couldn't insert snippet, %s", sqlite3_errmsg(h->conn));
        if (err == SQLITE_CONSTRAINT) {
            rc = DBW_ERR_ALREADY_EXISTS;
        }
        goto error;
    }

    snippet_id = sqlite3_column_int64(stmt, 0);
    CHECK(sqlite3_finalize(stmt) == SQLITE_OK, "Couldn't finalize statement");

    // Step 4: bind snippet to tags
    q = bstrcpy(&_insert_snippet_to_tags_sql);
    CHECK(q != NULL, "Couldn't create query string");

    question_marks = bfromcstr("?,");
    // As many question marks as many tags we have
    CHECK(question_marks != NULL, "Couldn't create query string");
    CHECK(
        bpattern(question_marks, 2 * tags->qty - 1) == BSTR_OK,
        "Couldn't create query string");
    CHECK(
        bconcat(q, question_marks) == BSTR_OK, "Couldn't create query string");
    bdestroy(question_marks);
    question_marks = NULL;
    CHECK(bconchar(q, ')') == BSTR_OK, "Couldn't create query string");

    CHECK(
        sqlite3_prepare_v2(h->conn, bdata(q), blength(q) + 1, &stmt, NULL) ==
            SQLITE_OK,
        "Couldn't prepare statement: %s",
        sqlite3_errmsg(h->conn));

    CHECK(
        sqlite3_bind_int64(stmt, 1, snippet_id) == SQLITE_OK,
        "Couldn't bind parameter to statement");

    LOG_DEBUG("query: %s", bdata(q));

    for (unsigned int i = 0; i < tags->qty; i++) {
        CHECK(
            sqlite3_bind_text(stmt, 2 + i, bdata(tags->entry[i]), -1, NULL) ==
                SQLITE_OK,
            "Couldn't bind parameter (tag %s) to statement: %s",
            bdata(tags->entry[i]),
            sqlite3_errmsg(h->conn));
    }
    err = sqlite3_step(stmt);
    if (err != SQLITE_DONE) {
        LOG_ERR("Couldn't bind snippet to tags, %s", sqlite3_errmsg(h->conn));
        goto error;
    }

    bdestroy(q);
    q = NULL;

exit:
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    if (q != NULL) {
        bdestroy(q);
    }
    if (question_marks != NULL) {
        bdestroy(question_marks);
    }
    return rc;
error:
    if (rc == DBW_OK) {
        rc = DBW_ERR;
    }
    goto exit;
}

static DBWHandler *sqlite3_connect(const bstring filename, int *err) {
    DBWHandler *h = NULL;
    sqlite3 *db = NULL;
    char *err_str = NULL;
    int rc = 0;
    int is_loading_enabled = 0;
    int is_fkey_enabled = 0;

    h = calloc(1, sizeof(DBWHandler));
    CHECK_MEM(h);
    CHECK(filename != NULL && bdata(filename) != NULL, "Null filename");

    rc = sqlite3_open(bdata(filename), &db);
    CHECK(rc == 0, "Couldn't open sqlite database: %s", sqlite3_errmsg(db));

    rc =
        sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_FKEY, 1, &is_fkey_enabled);
    CHECK(
        rc == 0,
        "Couldn't enable foreign keys in sqlite: %s",
        sqlite3_errmsg(db));
    CHECK(is_fkey_enabled == 1, "Couldn't enable foreign keys in sqlite");
    /* rc = sqlite3_db_config(
     *   db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 1, &is_loading_enabled);
     *  CHECK(rc == 0, "Couldn't allow sqlite to load extensions: %s",
     *       sqlite3_errmsg(db));
     * CHECK(is_loading_enabled == 1, "Couldn't allow sqlite to load
     * extensions");
     *
     * rc = sqlite3_load_extension(db, "./extension-functions", NULL, &err_str);
     * CHECK(rc == 0, "Couldn't load extensions: %s", err_str);
     */

    h->conn = db;
    h->DBWDBType = DBW_SQLITE3;
    return h;
error:
    if (h != NULL) {
        free(h);
    }
    if (db != NULL) {
        sqlite3_close(db);
    }
    if (err != NULL) {
        *err = DBW_ERR;
    }
    if (err_str != NULL) {
        sqlite3_free(err_str);
    }
    return NULL;
}

static int dbw_sqlite3_close(DBWHandler *h) {
    int rc = 0;
    rc = sqlite3_close(h->conn);
    CHECK(
        rc == SQLITE_OK,
        "Coudldn't close sqlite connetion: %s",
        sqlite3_errstr(rc));
    // fallthrough
error:
    if (h != NULL) {
        free(h);
    }
    if (rc != 0) {
        return DBW_ERR;
    }
    return 0;
}

static int
sqllite3_get_types_cb(DBWResult *res, int n, char **cls, char **cns) {
    bstring f = NULL;
    int err = 0;
    CHECK(n > 2, "Callback failed");

    struct tagbstring ct;
    struct tagbstring _type;
    f = bfromcstr(cls[1]);
    rv_push(res->head_vec, f, &err);
    f = NULL;
    CHECK(err == 0, "SQLite: callback failed");
    btfromcstr(ct, cls[2] == NULL ? "" : cls[2]);
    if (_type = (struct tagbstring)bsStatic("INTEGER"), !bstrcmp(&ct, &_type)) {
        rv_push(res->types_vec, DBW_INTEGER, NULL);
    } else {
        rv_push(res->types_vec, DBW_UNKN, NULL);
    }
    CHECK(err == 0, "SQLite: callback failed");

    return 0;

error:
    if (f != NULL) {
        bdestroy(f);
    }
    return -1;
}

// Warning -- this funciton is SQL injections vulnarable
static DBWResult *
sqlite3_get_table_types(DBWHandler *h, const bstring table, int *err) {
    bstring query = NULL;
    int rc = 0;
    char *zErrMsg = NULL;
    DBWResult *ret = NULL;

    CHECK(h != NULL, "Null handler");
    CHECK(table != NULL && bdata(table) != NULL, "Null table");

    ret = DBWResult_create(DBW_TYPES);
    CHECK_MEM(ret);

    query = bformat("PRAGMA TABLE_INFO(%s)", bdata(table));
    CHECK(query != NULL, "Couldn't prepare query");

    rc = sqlite3_exec(
        h->conn,
        bdata(query),
        (int (*)(void *, int, char **, char **))sqllite3_get_types_cb,
        ret,
        &zErrMsg);
    CHECK(rc == 0, "SQLite: couldn't execute query: %s", zErrMsg);

    if (query != NULL) {
        bdestroy(query);
    }
    return ret;
error:
    if (ret != NULL) {
        DBWResult_destroy(ret);
    }
    if (err != NULL) {
        *err = DBW_ERR;
    }
    return NULL;
}

static int sqllite3_query_cb(DBWResult *res, int n, char **cls, char **cns) {
    bstring f = NULL;
    int err = 0;

    // We assume that first callback invocation fills up header
    if (rv_len(res->head_vec) == 0) {
        for (int i = 0; i < n; i++) {
            f = bfromcstr(cns[i]);
            rv_push(res->head_vec, f, &err);
            f = NULL;
            CHECK(err == 0, "SQLite: callback failed");
        }
    }
    for (int i = 0; i < n; i++) {
        f = bfromcstr(cls[i] == NULL ? "" : cls[i]);
        rv_push(res->res_vec, f, &err);
        f = NULL;
        CHECK(err == 0, "SQLite: callback failed");
    }

    return 0;

error:
    if (f != NULL) {
        bdestroy(f);
    }
    return -1;
}

static DBWResult *sqlite3_query(DBWHandler *h, const bstring query, int *err) {
    int rc = 0;
    DBWResult *ret = NULL;
    char *zErrMsg = NULL;

    CHECK(h != NULL, "Null handler");
    CHECK(h->conn != NULL, "Null db connection");
    CHECK(query != NULL && bdata(query) != NULL, "Null query");

    ret = DBWResult_create(DBW_TUPLES);
    CHECK_MEM(ret);

    rc = sqlite3_exec(
        h->conn,
        bdata(query),
        (int (*)(void *, int, char **, char **))sqllite3_query_cb,
        ret,
        &zErrMsg);
    CHECK(rc == 0, "SQLite: couldn't execute query: %s", zErrMsg);

    return ret;
error:
    if (ret != NULL) {
        DBWResult_destroy(ret);
    }
    if (zErrMsg != NULL) {
        sqlite3_free(zErrMsg);
    }
    return NULL;
}

// ******************************
// * Generic interface
// ******************************

int dbw_print(DBWResult *res) {
    CHECK(res != NULL, "Null result.");
    size_t n_fields = rv_len(res->head_vec);
    size_t n_tuples = rv_len(res->res_vec);

    if (n_fields < 1 || rv_len(res->res_vec) < 1) {
        return 0;
    }
    for (size_t j = 0; j < n_fields; j++) {
        bstring f = rv_pop(res->head_vec, NULL);
        printf("%-15.15s ", bdata(f));
    }
    printf("\n");
    for (; rv_len(res->res_vec) > 0;) {
        for (size_t j = 0; j < n_fields; j++) {
            bstring f = rv_pop(res->res_vec, NULL);
            printf("%-15.15s ", bdata(f));
        }
        printf("\n");
    }
    res->res_vec.n = n_tuples;
    res->head_vec.n = n_fields;
error:
    return -1;
}

int DBWResult_destroy(DBWResult *res) {
    CHECK(res != NULL, "Null result");
    while (rv_len(res->head_vec) > 0) {
        // thanks to type magic, we are sure that head_vec contains bstrings...
        bdestroy(rv_pop(res->head_vec, NULL));
    }
    rv_destroy(res->head_vec);
    if (res->res_type == DBW_TYPES) {
        rv_destroy(res->types_vec);
    } else {
        while (rv_len(res->res_vec) > 0) {
            // ... as well as res_ves
            bdestroy(rv_pop(res->res_vec, NULL));
        }
        rv_destroy(res->res_vec);
    }

    free(res);

    return 0;
error:
    return -1;
}

static DBWResult *DBWResult_create(int t) {
    DBWResult *ret = calloc(1, sizeof(DBWResult));
    CHECK_MEM(ret);
    rv_init(ret->head_vec);
    if (t == DBW_TYPES) {
        rv_init(ret->types_vec);
    } else {
        rv_init(ret->res_vec);
    }
    ret->res_type = t;

    return ret;
error:
    if (ret != NULL) {
        free(ret);
    }
    return NULL;
}

DBWHandler *dbw_connect(int DBWDBType, const bstring url, int *err) {
    if (DBWDBType == DBW_SQLITE3)
        return sqlite3_connect(url, err);
    if (err != NULL) {
        *err = DBW_ERR_UNKN_DB;
    }
error:
    return NULL;
}

DBWResult *dbw_get_table_types(DBWHandler *h, const bstring table, int *err) {
    CHECK(h != NULL, "Null handler.");
    if (h->DBWDBType == DBW_SQLITE3)
        return sqlite3_get_table_types(h, table, err);
    if (err != NULL) {
        *err = DBW_ERR_UNKN_DB;
    }

error:
    return NULL;
}

DBWResult *dbw_query(DBWHandler *h, const bstring query, int *err) {
    CHECK(h != NULL, "Null handler.");
    if (h->DBWDBType == DBW_SQLITE3)
        return sqlite3_query(h, query, err);
    if (err != NULL) {
        *err = DBW_ERR_UNKN_DB;
    }

error:
    return NULL;
}

int dbw_new_snippet(
    DBWHandler *h,
    const bstring title,
    const bstring snippet,
    const bstring type,
    const struct bstrList *tags) {

    CHECK(title != NULL && bdata(title) != NULL, "Null title");
    CHECK(snippet != NULL && bdata(snippet) != NULL, "Null snippet");
    CHECK(type != NULL && bdata(type) != NULL, "Null type");
    CHECK(tags != NULL, "Null tags");
    CHECK(tags->qty > 0 && tags->qty < 100, "Too many tags");

    for (unsigned int i = 0; i < tags->qty; i++) {
        LOG_DEBUG("Got tag %s", bdata(tags->entry[i]));
    }
    CHECK(
        bdata(title)[blength(title)] == '\0', "String must be nul terminated");
    CHECK(
        bdata(snippet)[blength(snippet)] == '\0',
        "String must be nul terminated");
    CHECK(bdata(type)[blength(type)] == '\0', "String must be nul terminated");

    if (h->DBWDBType == DBW_SQLITE3)
        return sqlite3_new_snippet(h, title, snippet, type, tags);

    return DBW_ERR_UNKN_DB;
error:
    return DBW_ERR;
}

json_value *dbw_find_snippets(
    DBWHandler *h,
    const bstring title,
    const bstring type,
    const struct bstrList *tags,
    int *err) {

    if (h->DBWDBType == DBW_SQLITE3)
        return sqlite3_find_snippets(h, title, type, tags, err);
    else {
        if (err != NULL) {
            *err = DBW_ERR_UNKN_DB;
        }
        return NULL;
    }

error:
    if (err != NULL) {
        *err = DBW_ERR;
    }
    return NULL;
}

int dbw_close(DBWHandler *h) {
    CHECK(h != NULL, "Null handler.");
    if (h->DBWDBType == DBW_SQLITE3)
        return dbw_sqlite3_close(h);
error:
    return DBW_ERR_UNKN_DB;
}