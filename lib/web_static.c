#include <bstrlib.h>

const struct  tagbstring web_static_main_header = bsStatic("\
<!DOCTYPE html>\
<html lang=\"en\" dir=\"ltr\">\
  <head>\
    <meta charset=\"utf-8\">\
    <title>ynote</title>\
    <link rel=\"stylesheet\" href=\"/static/css/nb.css\">\
  </head>\
  <body>\
");

const struct  tagbstring web_static_snippet_header = bsStatic("\
<!DOCTYPE html>\
<html lang=\"en\" dir=\"ltr\">\
  <head>\
    <meta charset=\"utf-8\">\
    <title>ynote</title>\
    <link rel=\"stylesheet\" href=\"/static/css/nb.css\">\
  </head>\
  <body>\
");

const struct  tagbstring web_static_main_footer = bsStatic("\
</body>\
</html>\
");
