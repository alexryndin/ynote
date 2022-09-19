#include "dbw.h"
#include "dbg.h"
#include "json-builder.h"
#include "json.h"
#include <bstrlib.h>
#include <rvec.h>
#include <sqlite3.h>
#include <stdlib.h>

#define STR_APPEND_PATTERN(str, pattern, num)                              \
  do {                                                                     \
    bstring question_marks = bfromcstr((pattern));                         \
    if (question_marks == NULL) {                                          \
      LOG_ERR("Couldn't create query string");                             \
      goto error;                                                          \
    }                                                                      \
    /* As many question marks as many tags we have */                      \
    if (bpattern(question_marks, (sizeof(pattern) - 1) * (num)-1) !=       \
        BSTR_OK) {                                                         \
      LOG_ERR("Couldnt create query string");                              \
      bdestroy(question_marks);                                            \
      goto error;                                                          \
    }                                                                      \
    if (bconcat((str), question_marks) != BSTR_OK) {                       \
      LOG_ERR("Couldn't create query string");                             \
      bdestroy(question_marks);                                            \
      goto error;                                                          \
    }                                                                      \
    CHECK(bdestroy(question_marks) == BSTR_OK, "Couldn't destroy string"); \
  } while (0)

#define CHECK_JSON_OBJ_PUSH(json, field_name, obj)             \
  do {                                                         \
    CHECK(                                                     \
        json_object_push((json), (field_name), (obj)) != NULL, \
        "Couldn't create json");                               \
  } while (0)

#define CHECK_JSON_ARRAY_STR_FIELD_PUSH(str, stmt, field_num, array)        \
  do {                                                                      \
    CHECK_MEM(                                                              \
        (str) = json_string_new(                                            \
            (json_char *)sqlite3_column_text((stmt), (field_num))));        \
    CHECK(json_array_push((array), (str)) != NULL, "Couldn't create json"); \
  } while (0)

#define SNIPPETS_TABLE        "snippets"
#define SNIPPET_TYPES_TABLE   "snippet_types"
#define TAGS_TABLE            "tags"
#define SNIPPET_TO_TAGS_TABLE "snippet_to_tags"
#define FILES_TABLE           "files"
#define FILES_TO_TAGS_TABLE   "files_to_tags"

static const struct tagbstring _insert_snippet_sql =
    bsStatic("INSERT INTO " SNIPPETS_TABLE
             " (title, content, type) VALUES (?, ?, ?) RETURNING id");

static const struct tagbstring _insert_file_sql = bsStatic(
    "INSERT INTO " FILES_TABLE " (name, location) VALUES (?, ?) RETURNING id");

static const struct tagbstring _update_snippet_sql =
    bsStatic("UPDATE " SNIPPETS_TABLE " SET deleted =  ");

static const struct tagbstring _insert_t_to_tags_sql =
    bsStatic("INSERT OR IGNORE INTO %s (snippet_id, tag_id) SELECT ?, id "
             "FROM " TAGS_TABLE " WHERE name IN (");

static const struct tagbstring _insert_snippet_to_tags_sql = bsStatic(
    "INSERT OR IGNORE INTO " SNIPPET_TO_TAGS_TABLE
    " (snippet_id, tag_id) SELECT ?, id FROM " TAGS_TABLE " WHERE name IN (");

static const struct tagbstring _insert_files_to_tags_sql = bsStatic(
    "INSERT OR IGNORE INTO " FILES_TO_TAGS_TABLE
    " (file_id, tag_id) SELECT ?, id FROM " TAGS_TABLE " WHERE name IN (");

static const struct tagbstring _select_snippets_sql = bsStatic(
    "SELECT json_object('status', 'ok', 'result', json(result)) from ("
    "  SELECT json_object("
    "    'id', json_group_array(id),"
    "    'title', json_group_array(title),"
    "    'content', json_group_array(content),"
    "    'type', json_group_array(type),"
    "    'created', json_group_array(created),"
    "    'updated', json_group_array(updated),"
    "    'tags', json_group_array(json(tags))"
    "  ) AS result"
    "  FROM ("
    "    SELECT " SNIPPETS_TABLE ".id as id,"
    "           title,"
    "           CASE"
    "             WHEN length(content) < 51"
    "             THEN content"
    "             ELSE substr(content, 1, 50) || '...'"
    "           END as content,"
    "           snippet_types.name as type,"
    "           datetime(created, 'localtime') as created,"
    "           datetime(updated, 'localtime') as updated,"
    "           json_group_array(tags.name) as tags FROM " SNIPPETS_TABLE
    "             LEFT JOIN " SNIPPET_TYPES_TABLE " ON " SNIPPETS_TABLE
    ".type = " SNIPPET_TYPES_TABLE ".id"
    "             LEFT JOIN " SNIPPET_TO_TAGS_TABLE " ON " SNIPPETS_TABLE
    ".id = " SNIPPET_TO_TAGS_TABLE ".snippet_id"
    "             LEFT JOIN " TAGS_TABLE " ON " SNIPPET_TO_TAGS_TABLE
    ".tag_id = " TAGS_TABLE ".id"
    "    WHERE deleted=FALSE %s GROUP BY " SNIPPETS_TABLE ".id %s"
    "  ))");

static const struct tagbstring _get_snippet_sql = bsStatic(
    "SELECT json_object('status', 'ok', 'result', json(result))"
    "FROM ("
    "  SELECT"
    "    json_object("
    "      'id', id,"
    "      'title', title,"
    "      'content', content ,"
    "      'type', type,"
    "      'created', created,"
    "      'updated', updated,"
    "      'tags', json(tags)"
    "    ) AS result"
    "  FROM ("
    "    SELECT * FROM ("
    "      SELECT snippets.id as id,"
    "             title,"
    "             content,"
    "             snippet_types.name AS type,"
    "             datetime(created, 'localtime') AS created,"
    "             datetime(updated, 'localtime') AS updated,"
    "             json_group_array(tags.name) AS tags FROM " SNIPPETS_TABLE
    "               LEFT JOIN " SNIPPET_TYPES_TABLE " ON " SNIPPETS_TABLE
    "  .type = " SNIPPET_TYPES_TABLE ".id"
    "               LEFT JOIN " SNIPPET_TO_TAGS_TABLE " ON " SNIPPETS_TABLE
    "  .id = " SNIPPET_TO_TAGS_TABLE ".snippet_id"
    "               LEFT JOIN " TAGS_TABLE " ON " SNIPPET_TO_TAGS_TABLE
    "  .tag_id = " TAGS_TABLE ".id"
    "      WHERE " SNIPPETS_TABLE ".id=?"
    "    )"
    "    WHERE title IS NOT NULL "
    "  )"
    ")");

// statics and helpers
static struct tagbstring __integer = bsStatic("integer");

// forward declarations
static DBWResult *DBWResult_create(int t);

// ******************************
// * SQLite
// ******************************
//
static bstring
sqlite3_get_snippet(DBWHandler *h, sqlite_int64 id, int *ret_err) {
  int err = 0;
  sqlite3_stmt *stmt = NULL;
  const unsigned char *tmp_text_res = NULL;
  bstring ret = NULL;
  bstring q = NULL;

  q = bstrcpy((bstring)&_get_snippet_sql);
  CHECK(q != NULL, "Couldn't create query string");

  CHECK(
      sqlite3_prepare_v2(h->conn, bdata(q), blength(q) + 1, &stmt, NULL) ==
          SQLITE_OK,
      "Couldn't prepare statement: %s",
      sqlite3_errmsg(h->conn));

  LOG_DEBUG("query: %s", bdata(q));

  CHECK(
      sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK,
      "Couldn't bind parameter to statement");

  err = sqlite3_step(stmt);
  LOG_DEBUG("%s", sqlite3_errstr(err));
  switch (err) {
  case SQLITE_DONE:
    if (ret_err != NULL) {
      *ret_err = DBW_ERR_NOT_FOUND;
      goto error;
    }
    break;
  case SQLITE_ROW:
    tmp_text_res = sqlite3_column_text(stmt, 0);
    CHECK(
        tmp_text_res != NULL,
        "Couldn't fetch result set from db: %s",
        sqlite3_errmsg(h->conn));

    ret = bfromcstr((char *)tmp_text_res);
    CHECK(ret != NULL, "Couldn't gerenare result string");
    break;
  default:
    LOG_ERR("Couldn't get row from table: %s", sqlite3_errmsg(h->conn));
    goto error;
  }

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
  return ret;
error:
  if (ret_err != NULL && *ret_err == DBW_OK) {
    *ret_err = DBW_ERR;
  }
  if (ret != NULL) {
    bdestroy(ret);
  }
  goto exit;
}

static bstring sqlite3_find_snippets(
    DBWHandler *h,
    const bstring title,
    const bstring type,
    const bstrListEmb *tags,
    int *ret_err) {
  int err = 0;
  const int tags_padding = 5;
  sqlite3_stmt *stmt = NULL;
  const unsigned char *tmp_text_res = NULL;
  bstring ret = NULL;
  bstring q = NULL;
  bstring where_clause = NULL;
  bstring having_clause = NULL;

  where_clause = bfromcstr("");
  CHECK(where_clause != NULL, "Couldn't create query string");
  having_clause = bfromcstr("");
  CHECK(having_clause != NULL, "Couldn't create query string");

  if (tags != NULL) {
    if (rv_len(*tags) > 0) {
      bcatcstr(
          where_clause,
          "AND " SNIPPETS_TABLE
          ".id in (SELECT s.id as tags FROM " SNIPPETS_TABLE
          " AS s LEFT JOIN " SNIPPET_TO_TAGS_TABLE
          " as st ON s.id = st.snippet_id "
          "LEFT JOIN " TAGS_TABLE
          " AS t ON t.id = st.tag_id WHERE t.name in (");
      STR_APPEND_PATTERN(where_clause, "?,", rv_len(*tags));
      CHECK(
          bcatcstr(where_clause, "))") == BSTR_OK,
          "Couldn't create query string");
      CHECK(
          bcatcstr(
              having_clause,
              " HAVING COUNT(" SNIPPET_TO_TAGS_TABLE
              ".tag_id) >= ?") == BSTR_OK,
          "Couldn't create query string");
    } else {
      CHECK(
          bcatcstr(
              having_clause,
              " HAVING COUNT(" SNIPPET_TO_TAGS_TABLE ".tag_id) = 0") == BSTR_OK,
          "Couldn't create query string");
    }
  }

  if (bdata(type) != NULL) {
    CHECK(
        bcatcstr(
            where_clause,
            "AND " SNIPPETS_TABLE
            ".type in (select id from " SNIPPET_TYPES_TABLE " WHERE name = "
            "?)") == BSTR_OK,
        "Couldn't create query string");
  }

  q = bformat(
      bdata(&_select_snippets_sql), bdata(where_clause), bdata(having_clause));
  CHECK(q != NULL, "Couldn't create query string");
  bdestroy(where_clause);
  where_clause = NULL;
  bdestroy(having_clause);
  having_clause = NULL;

  LOG_DEBUG("query: %s", bdata(q));
  CHECK(
      sqlite3_prepare_v2(h->conn, bdata(q), blength(q) + 1, &stmt, NULL) ==
          SQLITE_OK,
      "Couldn't prepare statement: %s",
      sqlite3_errmsg(h->conn));

  int binding_field = 0;
  if (tags != NULL && rv_len(*tags) > 0) {
    for (binding_field = 0; binding_field < rv_len(*tags); binding_field++) {
      LOG_DEBUG(
          "Binding field %d(%s)",
          binding_field + 1,
          bdata(rv_get(*tags, binding_field, NULL)));
      CHECK(
          sqlite3_bind_text(
              stmt,
              binding_field + 1,
              bdata(rv_get(*tags, binding_field, NULL)),
              -1,
              NULL) == SQLITE_OK,
          "Couldn't bind parameter (tag %s) to statement: %s",
          bdata(rv_get(*tags, binding_field, NULL)),
          sqlite3_errmsg(h->conn));
    }
    LOG_DEBUG("Binding field %d(%zu)", binding_field + 1, rv_len(*tags));
  }
  LOG_DEBUG("Binding filed %d(%s)", binding_field + 1, bdata(type));
  if (bdata(type) != NULL) {
    CHECK(
        sqlite3_bind_text(stmt, ++binding_field, bdata(type), -1, NULL) ==
            SQLITE_OK,
        "Couldn't bind parameter (type %s) to statement: %s",
        bdata(type),
        sqlite3_errmsg(h->conn));
  }
  // We need to bind variables in order they appear in the query
  // so we cannot bind tags->qty in the loop above
  if (tags != NULL && rv_len(*tags) > 0) {
    CHECK(
        sqlite3_bind_int64(stmt, ++binding_field, rv_len(*tags)) == SQLITE_OK,
        "Couldn't bind parameter to statement");
  }

  while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
    switch (err) {
    case SQLITE_ROW:
      tmp_text_res = sqlite3_column_text(stmt, 0);
      CHECK(
          tmp_text_res != NULL,
          "Couldn't fetch result set from db: %s",
          sqlite3_errmsg(h->conn));

      ret = bfromcstr((char *)tmp_text_res);
      CHECK(ret != NULL, "Couldn't gerenare result string");
      break;
    default:
      LOG_ERR("Couldn't get row from table: %s", sqlite3_errmsg(h->conn));
      goto error;
    }
  }

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
  if (having_clause != NULL) {
    bdestroy(having_clause);
  }
  if (where_clause != NULL) {
    bdestroy(where_clause);
  }
  return ret;
error:
  if (ret_err != NULL) {
    *ret_err = DBW_ERR;
  }
  if (ret != NULL) {
    bdestroy(ret);
  }
  goto exit;
}

// Bind id to tags
// table name must not be provided by user
static enum DBWError sqlite3_bind_tags(
    DBWHandler *h,
    const bstring table,
    sqlite3_int64 entity_id,
    const bstrListEmb *tags) {
  int ret = DBW_OK;
  int err = 0;
  bstring q = NULL;
  bstring question_marks = NULL;
  sqlite3_stmt *stmt = NULL;

  CHECK(tags != NULL, "Null tags");

  q = bformat(bdata((bstring)&_insert_snippet_to_tags_sql), bdata(table));
  CHECK(q != NULL, "Couldn't create query string");

  question_marks = bfromcstr("?,");
  // As many question marks as many tags we have
  CHECK(question_marks != NULL, "Couldn't create query string");
  CHECK(
      bpattern(question_marks, 2 * rv_len(*tags) - 1) == BSTR_OK,
      "Couldn't create query string");
  CHECK(bconcat(q, question_marks) == BSTR_OK, "Couldn't create query string");
  bdestroy(question_marks);
  question_marks = NULL;
  CHECK(bconchar(q, ')') == BSTR_OK, "Couldn't create query string");

  CHECK(
      sqlite3_prepare_v2(h->conn, bdata(q), blength(q) + 1, &stmt, NULL) ==
          SQLITE_OK,
      "Couldn't prepare statement: %s",
      sqlite3_errmsg(h->conn));

  CHECK(
      sqlite3_bind_int64(stmt, 1, entity_id) == SQLITE_OK,
      "Couldn't bind parameter to statement");

  LOG_DEBUG("query: %s", bdata(q));

  for (int i = 0; i < rv_len(*tags); i++) {
    CHECK(
        sqlite3_bind_text(
            stmt, 2 + i, bdata(rv_get(*tags, i, NULL)), -1, NULL) == SQLITE_OK,
        "Couldn't bind parameter (tag %s) to statement: %s",
        bdata(rv_get(*tags, i, NULL)),
        sqlite3_errmsg(h->conn));
  }
  err = sqlite3_step(stmt);
  if (err != SQLITE_DONE) {
    LOG_ERR("Couldn't bind snippet to tags, %s", sqlite3_errmsg(h->conn));
    goto error;
  }
  if (sqlite3_finalize(stmt) != SQLITE_OK) {
    LOG_ERR("Couldn't finalize statement");
    stmt = NULL;
    goto error;
  } else {
    stmt = NULL;
  };
exit:
  if (q != NULL) {
    bdestroy(q);
  }
  if (question_marks != NULL) {
    bdestroy(question_marks);
  }
  if (stmt != NULL) {
    sqlite3_finalize(stmt);
  }
error:
  ret = DBW_ERR;
  goto exit;
}

// Unlink unnecessary tags
static enum DBWError sqlite3_unbind_tags(
    DBWHandler *h,
    const bstring table,
    sqlite3_int64 entity_id,
    const bstrListEmb *tags) {
  int ret = DBW_OK;
  int err = 0;
  bstring q = NULL;
  sqlite3_stmt *stmt = NULL;

  CHECK(tags != NULL, "Null tags");

  if (rv_len(*tags) > 0) {
    CHECK(
        (q = bformat(
             "DELETE FROM %s WHERE snippet_id = ? AND tag_id NOT IN (SELECT id "
             "FROM " TAGS_TABLE " WHERE name IN (")) != NULL,
        "Couldn't create query string");
    STR_APPEND_PATTERN(q, "?,", rv_len(*tags));
    CHECK(bcatcstr(q, "))") == BSTR_OK, "Couldn't create query string");
  } else {
    q = bfromcstr("DELETE FROM " SNIPPET_TO_TAGS_TABLE " WHERE snippet_id = ?");
    CHECK(q != NULL, "Couldn't create query string");
  }
  LOG_DEBUG("query = %s, id = %lld", bdata(q), entity_id);

  CHECK(
      sqlite3_prepare_v2(h->conn, bdata(q), blength(q) + 1, &stmt, NULL) ==
          SQLITE_OK,
      "Couldn't prepare statement: %s",
      sqlite3_errmsg(h->conn));
  CHECK(
      sqlite3_bind_int64(stmt, 1, entity_id) == SQLITE_OK,
      "Couldn't bind parameter to statement");
  for (int i = 0; i < rv_len(*tags); i++) {
    CHECK(
        sqlite3_bind_text(
            stmt, 2 + i, bdata(rv_get(*tags, i, NULL)), -1, NULL) == SQLITE_OK,
        "Couldn't bind parameter (tag %s) to statement: %s",
        bdata(rv_get(*tags, i, NULL)),
        sqlite3_errmsg(h->conn));
  }
  err = sqlite3_step(stmt);
  if (err != SQLITE_DONE) {
    LOG_ERR("Couldn't bind snippet to tags, %s", sqlite3_errmsg(h->conn));
    goto error;
  }
  if (sqlite3_finalize(stmt) != SQLITE_OK) {
    LOG_ERR("Couldn't finalize statement");
    stmt = NULL;
    goto error;
  } else {
    stmt = NULL;
  };
exit:
  if (q != NULL) {
    bdestroy(q);
  }
  if (stmt != NULL) {
    sqlite3_finalize(stmt);
  }
  return ret;
error:
  ret = DBW_ERR;
  goto exit;
}
// Ensure all tags are present in tags table
static enum DBWError sqlite3_ensure_tags(
    DBWHandler *h, const bstring table, const bstrListEmb *tags) {
  int ret = DBW_OK;
  bstring q = NULL;
  sqlite3_stmt *stmt = NULL;
  bstring question_marks = NULL;

  CHECK(bdata(table), "Table name is required");

  if (tags && rv_len(*tags) > 0) {
    q = bfromcstr("INSERT OR IGNORE INTO " TAGS_TABLE " (name) VALUES ");
    CHECK(q != NULL, "Couldn't create query string");

    question_marks = bfromcstr("(?),");
    CHECK(question_marks != NULL, "Couldn't create query string");

    // As many question marks as many tags we have
    CHECK(
        bpattern(question_marks, 4 * rv_len(*tags) - 1) == BSTR_OK,
        "Couldnt create query string");
    CHECK(
        bconcat(q, question_marks) == BSTR_OK, "Couldn't create query string");
    bdestroy(question_marks);
    question_marks = NULL;

    CHECK(
        sqlite3_prepare_v2(h->conn, bdata(q), blength(q) + 1, &stmt, NULL) ==
            SQLITE_OK,
        "Couldn't prepare statement: %s",
        sqlite3_errmsg(h->conn));

    LOG_DEBUG("Statement is %s", bdata(q));

    for (int i = 0; i < rv_len(*tags); i++) {
      CHECK(
          sqlite3_bind_text(
              stmt, 1 + i, bdata(rv_get(*tags, i, NULL)), -1, NULL) ==
              SQLITE_OK,
          "Couldn't bind parameter (tag %s) to statement: %s",
          bdata(rv_get(*tags, i, NULL)),
          sqlite3_errmsg(h->conn));
    }

    CHECK(sqlite3_step(stmt) == SQLITE_DONE, "Couldn't insert tags");

    CHECK(sqlite3_finalize(stmt) == SQLITE_OK, "Couldn't finalize statement");
    bdestroy(q);
    q = NULL;
  }
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
  return ret;
error:
  ret = DBW_ERR;
  goto exit;
}

static sqlite3_int64 sqlite3_edit_snippet(
    DBWHandler *h,
    const sqlite3_int64 snippet_id,
    const bstring title,
    const bstring snippet,
    const bstring type,
    const bstrListEmb *tags,
    char deleted,
    int *ret_err) {
  int err = 0;
  sqlite3_int64 ret = 0;
  int rc = 0;
  sqlite3_int64 type_id = 0;
  sqlite3_stmt *stmt = NULL;

  bstring q = NULL;

  // Step 1: get corresponding snippet type
  if (type != NULL) {
    const struct tagbstring check_type_sql =
        bsStatic("SELECT id FROM snippet_types WHERE name = ?;");

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
    stmt = NULL;
  }

  // Step 2: ensure all tags are present in tags table
  if (tags != NULL && rv_len(*tags) > 0) {
    struct tagbstring tags_table_name = bsStatic(TAGS_TABLE);
    CHECK(
        sqlite3_ensure_tags(h, &tags_table_name, tags) == DBW_OK,
        "Couldn't insert tags");
  }

  // Step 3: update snippet
  if (bdata(title) != NULL || bdata(snippet) != NULL || bdata(type) != NULL ||
      deleted) {
    q = bstrcpy((bstring)&_update_snippet_sql);
    CHECK(q != NULL, "Couldn't create query string");
    char *_deleted = deleted ? "TRUE," : "FALSE,";
    CHECK(bcatcstr(q, _deleted) == BSTR_OK, "Couldn't create query string");
    if (bdata(title) != NULL) {
      CHECK(
          bcatcstr(q, "title = ?1,") == BSTR_OK,
          "Couldn't create query string");
    }
    if (bdata(snippet) != NULL) {
      CHECK(
          bcatcstr(q, "content = ?2,") == BSTR_OK,
          "Couldn't create query string");
    }
    if (bdata(type) != NULL) {
      CHECK(
          bcatcstr(q, "type = ?3,") == BSTR_OK, "Couldn't create query string");
    }

    // remove trailig ,
    bdata(q)[--q->slen] = '\0';

    CHECK(
        bcatcstr(q, " WHERE id = ?4;") == BSTR_OK,
        "Couldn't create query string");

    LOG_DEBUG("query %s", bdata(q));

    CHECK(
        sqlite3_prepare_v2(h->conn, bdata(q), blength(q) + 1, &stmt, NULL) ==
            SQLITE_OK,
        "Couldn't prepare statement: %s",
        sqlite3_errmsg(h->conn));

    LOG_DEBUG("title is %s", bdata(title));
    if (bdata(title) != NULL) {
      CHECK(
          sqlite3_bind_text(stmt, 1, bdata(title), -1, NULL) == SQLITE_OK,
          "Couldn't bind parameter to statement");
    }

    if (bdata(snippet) != NULL) {
      CHECK(
          sqlite3_bind_text(stmt, 2, bdata(snippet), -1, NULL) == SQLITE_OK,
          "Couldn't bind parameter to statement");
    }

    if (bdata(type) != NULL) {
      CHECK(
          sqlite3_bind_int64(stmt, 3, type_id) == SQLITE_OK,
          "Couldn't bind parameter to statement");
    }
    LOG_DEBUG("snippet id is %lld", snippet_id);
    CHECK(
        sqlite3_bind_int64(stmt, 4, snippet_id) == SQLITE_OK,
        "Couldn't bind parameter to statement");

    err = sqlite3_step(stmt);
    if (err != SQLITE_DONE) {
      LOG_ERR("Couldn't update snippet, %s", sqlite3_errmsg(h->conn));
      if (err == SQLITE_CONSTRAINT) {
        rc = DBW_ERR_ALREADY_EXISTS;
      }
      goto error;
    }

    CHECK(sqlite3_finalize(stmt) == SQLITE_OK, "Couldn't finalize statement");
    CHECK(bdestroy(q) == BSTR_OK, "Coudln't destroy string");
    q = NULL;
    stmt = NULL;
  }

  if (tags != NULL && rv_len(*tags) > 0) {
    // Step 4: bind snippet to tags
    struct tagbstring tablename = bsStatic(SNIPPETS_TABLE);
    CHECK(
        sqlite3_bind_tags(h, &tablename, snippet_id, tags) == DBW_OK,
        "Couldn't bind snippet to tags");
    // Step 5: unlink unnecessary tags
    CHECK(
        sqlite3_unbind_tags(h, &tablename, snippet_id, tags) == DBW_OK,
        "Couldn't bind snippet to tags");
  }
  if (ret_err != NULL) {
    *ret_err = DBW_OK;
  }

  ret = snippet_id;

exit:
  if (stmt != NULL) {
    sqlite3_finalize(stmt);
  }
  if (q != NULL) {
    bdestroy(q);
  }
  return ret;
error:
  if (ret_err != NULL && *ret_err == DBW_OK) {
    *ret_err = rc == DBW_OK ? DBW_ERR : rc;
  }
  goto exit;
}

static sqlite3_int64 sqlite3_new_snippet(
    DBWHandler *h,
    const bstring title,
    const bstring snippet,
    const bstring type,
    const bstrListEmb *tags,
    int *ret_err) {
  int err = 0;
  sqlite3_int64 ret = 0;
  int rc = 0;
  sqlite3_int64 type_id = 0;
  sqlite3_int64 snippet_id = 0;
  sqlite3_stmt *stmt = NULL;

  bstring q = NULL;
  bstring question_marks = NULL;

  // Step 1: get corresponding snippet type
  const struct tagbstring check_type_sql =
      bsStatic("SELECT id FROM snippet_types WHERE name = ?;");

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
  if (tags && rv_len(*tags) > 0) {
    struct tagbstring tags_table_name = bsStatic(TAGS_TABLE);
    CHECK(
        sqlite3_ensure_tags(h, &tags_table_name, tags) == DBW_OK,
        "Couldn't insert tags");
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
  stmt = NULL;

  // Step 4: bind snippet to tags
  if (rv_len(*tags) > 0) {
    struct tagbstring tablename = bsStatic(SNIPPETS_TABLE);
    CHECK(
        sqlite3_bind_tags(h, &tablename, snippet_id, tags) == DBW_OK,
        "Couldn't bind snippet to tags");
  }

  if (ret_err != NULL) {
    *ret_err = DBW_OK;
  }

  ret = snippet_id;

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
  return ret;
error:
  if (ret_err != NULL && *ret_err == DBW_OK) {
    *ret_err = rc == DBW_OK ? DBW_ERR : rc;
  }
  goto exit;
}

static sqlite3_int64 sqlite3_register_file(
    DBWHandler *h,
    const bstring filename,
    const bstring location,
    const bstrListEmb *tags,
    int *ret_err) {
  int err = 0;
  sqlite3_int64 ret = 0;
  int rc = 0;
  sqlite3_int64 type_id = 0;
  sqlite3_int64 file_id = 0;
  sqlite3_stmt *stmt = NULL;

  bstring q = NULL;
  bstring question_marks = NULL;

  // Step 1: ensure all tags are present in tags table
  if (tags && rv_len(*tags) > 0) {
    struct tagbstring tags_table_name = bsStatic(TAGS_TABLE);
    CHECK(
        sqlite3_ensure_tags(h, &tags_table_name, tags) == DBW_OK,
        "Couldn't insert tags");
  }
  // Step 2: insert file
  CHECK(
      sqlite3_prepare_v2(
          h->conn,
          bdata(&_insert_file_sql),
          blength(&_insert_file_sql) + 1,
          &stmt,
          NULL) == SQLITE_OK,
      "Couldn't prepare statement: %s",
      sqlite3_errmsg(h->conn));

  CHECK(
      sqlite3_bind_text(stmt, 1, bdata(filename), -1, NULL) == SQLITE_OK,
      "Couldn't bind parameter to statement");

  CHECK(
      sqlite3_bind_text(stmt, 2, bdata(location), -1, NULL) == SQLITE_OK,
      "Couldn't bind parameter to statement");

  err = sqlite3_step(stmt);
  if (err != SQLITE_ROW) {
    LOG_ERR("Couldn't insert snippet, %s", sqlite3_errmsg(h->conn));
    if (err == SQLITE_CONSTRAINT) {
      rc = DBW_ERR_ALREADY_EXISTS;
    }
    goto error;
  }

  file_id = sqlite3_column_int64(stmt, 0);
  CHECK(sqlite3_finalize(stmt) == SQLITE_OK, "Couldn't finalize statement");
  stmt = NULL;
  // Step 3: bind file to tags
  if (tags && rv_len(*tags) > 0) {
    struct tagbstring tablename = bsStatic(FILES_TABLE);
    CHECK(
        sqlite3_bind_tags(h, &tablename, file_id, tags) == DBW_OK,
        "Couldn't bind snippet to tags");
  }

  if (ret_err != NULL) {
    *ret_err = DBW_OK;
  }

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
  return ret;
error:
  if (ret_err != NULL && *ret_err == DBW_OK) {
    *ret_err = rc == DBW_OK ? DBW_ERR : rc;
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

  rc = sqlite3_open_v2(bdata(filename), &db, SQLITE_OPEN_READWRITE, NULL);
  CHECK(rc == 0, "Couldn't open sqlite database: %s", sqlite3_errmsg(db));

  rc = sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_FKEY, 1, &is_fkey_enabled);
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
   * rc = sqlite3_load_extension(db, "./extension-functions", NULL,
   * &err_str); CHECK(rc == 0, "Couldn't load extensions: %s", err_str);
   */

  h->conn = db;
  if (err != NULL) {
    *err = DBW_OK;
  }
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
  if (err != NULL) {
    *err = DBW_OK;
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

  if (err != NULL) {
    *err = DBW_OK;
  }
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
    // thanks to type magic, we are sure that head_vec contains
    // bstrings...
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

DBWHandler *dbw_connect(DBWDBType DBWDBType, const bstring url, int *err) {
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

sqlite_int64 dbw_new_snippet(
    DBWHandler *h,
    const bstring title,
    const bstring snippet,
    const bstring type,
    const bstrListEmb *tags,
    int *err) {

  CHECK(title != NULL && bdata(title) != NULL, "Null title");
  CHECK(snippet != NULL && bdata(snippet) != NULL, "Null snippet");
  CHECK(type != NULL && bdata(type) != NULL, "Null type");
  CHECK(tags != NULL, "Null tags");
  CHECK(rv_len(*tags) >= 0 && rv_len(*tags) < 100, "Too many tags: %zu", rv_len(*tags));

  for (int i = 0; i < rv_len(*tags); i++) {
    LOG_DEBUG("Got tag %s", bdata(rv_get(*tags, i, NULL)));
  }
  CHECK(bdata(title)[blength(title)] == '\0', "String must be nul terminated");
  CHECK(
      bdata(snippet)[blength(snippet)] == '\0',
      "String must be nul terminated");
  CHECK(bdata(type)[blength(type)] == '\0', "String must be nul terminated");

  if (h->DBWDBType == DBW_SQLITE3)
    return sqlite3_new_snippet(h, title, snippet, type, tags, err);

  return DBW_ERR_UNKN_DB;
error:
  if (err != NULL) {
    *err = DBW_ERR;
  }
  return -1;
}

sqlite_int64 dbw_edit_snippet(
    DBWHandler *h,
    const sqlite_int64 id,
    const bstring title,
    const bstring snippet,
    const bstring type,
    const bstrListEmb *tags,
    char deleted,
    int *err) {

  if (tags != NULL) {
    CHECK(rv_len(*tags) >= 0 && rv_len(*tags) < 100, "Too many tags");
  }

  if (bdata(title) != NULL) {
    CHECK(
        bdata(title)[blength(title)] == '\0', "String must be nul terminated");
  }
  if (bdata(snippet) != NULL) {
    CHECK(
        bdata(snippet)[blength(snippet)] == '\0',
        "String must be nul terminated");
  }
  if (bdata(type) != NULL) {
    CHECK(bdata(type)[blength(type)] == '\0', "String must be nul terminated");
  }

  // CHECK(tags != NULL, "Null tags");

  if (h->DBWDBType == DBW_SQLITE3)
    return sqlite3_edit_snippet(
        h, id, title, snippet, type, tags, deleted, err);

  return DBW_ERR_UNKN_DB;
error:
  if (err != NULL) {
    *err = DBW_ERR;
  }
  return -1;
}

bstring dbw_get_snippet(DBWHandler *h, sqlite_int64 id, int *err) {

  if (h->DBWDBType == DBW_SQLITE3)
    return sqlite3_get_snippet(h, id, err);
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

bstring dbw_find_snippets(
    DBWHandler *h,
    const bstring title,
    const bstring type,
    const bstrListEmb *tags,
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

sqlite_int64 dbw_register_file(
    DBWHandler *h,
    const bstring filename,
    const bstring location,
    const bstring type,
    const bstrListEmb *tags,
    int *err) {
  if (h->DBWDBType == DBW_SQLITE3)
    return sqlite3_register_file(h, filename, location, tags, err);
  else {
    if (err != NULL) {
      *err = DBW_ERR_UNKN_DB;
    }
    return -1;
  }

error:
  if (err != NULL) {
    *err = DBW_ERR;
  }
  return -1;
}

int dbw_close(DBWHandler *h) {
  CHECK(h != NULL, "Null handler.");
  if (h->DBWDBType == DBW_SQLITE3)
    return dbw_sqlite3_close(h);
error:
  return DBW_ERR_UNKN_DB;
}
