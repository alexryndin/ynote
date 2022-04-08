#!/bin/bash

set -e

PORT=${1:-8080}

echo $PORT

(./main test.db $PORT ) &

catch() {
    echo "error:
response $response
expected $compare"
    kill %1
    exit 1
}

trap 'catch' ERR

response=$(curl -fs "localhost:$PORT/api/find_snippets?tags=" | jq -c 'del(.result.created, .result.updated)')
compare='{"status":"ok","result":{"id":[3],"title":["Halo!"],"content":["test very long string that contains very much of a..."],"type":["plain"],"tags":[[null]]}}'
[[ "$response" == "$compare" ]] || false

response=$(curl -fs "localhost:$PORT/api/find_snippets" | jq -c 'del(.result.created, .result.updated)')
compare='{"status":"ok","result":{"id":[1,2,3,4],"title":["Hello","Привет","Halo!","Маркdown!"],"content":["world","Мир","test very long string that contains very much of a...","# Title 1\n## Сабтайтл 2\nНекоторый текст\n```\nint ma..."],"type":["bash","bash","plain","markdown"],"tags":[["kafka","c"],["c"],[null],["test"]]}}'
[[ "$response" == "$compare" ]] || false


response=$(curl -fs "localhost:$PORT/api/find_snippets?tags=c" | jq -c 'del(.result.created, .result.updated)')
compare='{"status":"ok","result":{"id":[1,2],"title":["Hello","Привет"],"content":["world","Мир"],"type":["bash","bash"],"tags":[["kafka","c"],["c"]]}}'
[[ "$response" == "$compare" ]] || false

response=$(curl -fs "localhost:$PORT/api/find_snippets?tags=kafka&type=bash" | jq -c 'del(.result.created, .result.updated)')
compare='{"status":"ok","result":{"id":[1],"title":["Hello"],"content":["world"],"type":["bash"],"tags":[["kafka","c"]]}}'
[[ "$response" == "$compare" ]] || false

response=$(curl -fs "localhost:$PORT/api/get_snippet?id=4" | jq -c 'del(.result.created, .result.updated)')
compare='{"status":"ok","result":{"id":4,"title":"Маркdown!","content":"<h1>Title 1</h1>\n<h2>Сабтайтл 2</h2>\n<p>Некоторый текст</p>\n<pre><code>int main(void){\n    printf(&quot;hello world&quot;);\n    return 0;\n}\n</code></pre>\n<h2>Subtitle 2</h2>\n<p>Некоторый text.</p>\n","type":"markdown","tags":["test"]}}'
[[ "$response" == "$compare" ]] || false

response=$(curl -fs "localhost:$PORT/api/get_snippet?id=4&edit=true" | jq -c 'del(.result.created, .result.updated)')
compare='{"status":"ok","result":{"id":4,"title":"Маркdown!","content":"# Title 1\n## Сабтайтл 2\nНекоторый текст\n```\nint main(void){\n    printf(\"hello world\");\n    return 0;\n}\n```\n## Subtitle 2\nНекоторый text.\n","type":"markdown","tags":["test"]}}'
[[ "$response" == "$compare" ]] || false

kill %1
echo tests passed
