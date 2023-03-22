#ifndef _HTTPAUX_H_
#define _HTTPAUX_H_

#include <bstrlib.h>
#include <curl/curl.h>
#include <lua.h>
#include <microhttpd.h>
#include <rvec.h>
#include <stdint.h>

#define strstartswith(haystack, needle) \
  (!strncmp((haystack), (needle), strlen(needle)))

struct UploadFile {
  bstring filename;
  bstring mime;
  bstring field_name;
  bstring name;
  bstring path;
  int fd;
};

struct PostField {
  bstring key;
  bstring value;
};

typedef rvec_t(struct UploadFile) UploadFilesVec;
typedef rvec_t(struct PostFields) PostFieldsVec;

enum ConnInfoType {
  CIT_POST_RAW,
  CIT_POST_UPLOAD_FORM,
  CIT_POST_FIELDS,
  CIT_POST_FILE_FORM,
  CIT_POST_SNIPPET_FORM,
  CIT_OTHER,
};

enum HTTPServerCallName {
  RESTAPI_UNKNOWN = 0,
  RESTAPI_CREATE_SNIPPET = 1,
  RESTAPI_GET_SNIPPET,
  RESTAPI_DELETE_SNIPPET,
  RESTAPI_FIND_SNIPPETS,
  RESTAPI_UPLOAD,
  RESTAPI_UNSORTED,
  RESTAPI_NGINX_UPLOAD,
  RESTAPI_STATIC,
  RESTAPI_STATIC_UPLOADED,
  RESTAPI_COMMAND,
  RESTAPI_GET_FILE,
  HTTP_PATH_GET_SNIPPET,
  HTTP_PATH_INDEX,
  HTTP_PATH_LUA,
};

enum HTTPAcceptType {
  HTTP_ACCEPT_APPLICATION_JSON = 0,
  HTTP_ACCEPT_TEXT_HTML = 1,
  HTTP_ACCEPT_OTHER = 2,
};

enum HTTPContentType {
  HTTP_CONTENT_OTHER = 0,
  HTTP_CONTENT_MULTIPART_FORM_DATA = 1,
  HTTP_CONTENT_FORM_URLENCODED = 2,
  HTTP_CONTENT_APPLICATION_JSON = 3,
  HTTP_CONTENT_TEXT_PLAIN = 4,
};

enum HTTPServerMethodName {
  HTTP_METHOD_OTHER = 0,
  HTTP_METHOD_POST,
  HTTP_METHOD_GET,
  HTTP_METHOD_PUT,
  HTTP_METHOD_DELETE,
};

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

struct ConnInfo {
  struct YNoteApp *app;
  const char *url;
  uint64_t invocations;
  const char * method_str;
  enum ConnInfoType type;
  enum HTTPServerCallName api_call_name;
  enum HTTPServerMethodName method_name;
  enum HTTPAcceptType at;
  enum HTTPContentType ct;
  void *userp;
  struct MHD_PostProcessor *pp;
  struct tagbstring error;
};

void ConnInfo_destroy(struct ConnInfo *ci);
struct ConnInfo *ConnInfo_create(
    enum ConnInfoType ct,
    enum HTTPServerMethodName method_name,
    const char *method_str,
    enum HTTPServerCallName call_name,
    struct MHD_Connection *connection,
    const char *url,
    struct YNoteApp *app);

void register_httpauxlib(lua_State *lua);

#endif
