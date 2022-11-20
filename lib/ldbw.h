#ifndef _LDBW_H_
#define _LDBW_H_

#include <httpaux.h>
#include <lua.h>

struct LDBWCtx {
  struct sqlite3_stmt *stmt;
};

struct LDBWCtx *LDBWCtx_create();
void LDBWCtx_destroy(struct LDBWCtx *ldbwctx);

void register_ldbwlib(lua_State *lua);

#endif
