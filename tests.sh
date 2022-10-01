#!/bin/bash

set -E

PORT=${1:-8080}

echo $PORT

catch() {
    echo "error:
response $response
expected $compare"
    kill %1
    exit 1
}

trap 'catch' ERR


run_test_on_port() {
    PORT=${1:-8080}

    test=$2

    echo $PORT

    cmd="curl -fs http://${test[host]}:${test[port]}${test[api]}${test[query]}"

    echo "Running $cmd -X ${test[method]:-"GET"}"
    echo "Body ${test[body]}"

    if [[ -z "${test[body]}" ]]; then
        response=$(curl -fs -X "${test[method]:-GET}" http://${test[host]}:${test[port]}${test[api]}${test[query]} | jq -c 'del(.result.created, .result.updated)')
    else
        response=$(echo "${test[body]}" | curl -s "http://${test[host]}:${test[port]}${test[api]}${test[query]}" --data-binary @- | jq -c 'del(.result.created, .result.updated)')
    fi

    if [[ "$response" != "${test[compare]}" ]]; then
        echo "error:
response $response
expected ${test[compare]}"
        kill %1
        exit 1
    fi
}




run_tests() {
    PORT=${1:-8080}
    declare -A test

    test['host']='localhost'
    test['port']=$PORT

    test['api']='/api/find_snippets'
    test['query']='?tags='
    test['compare']='{"status":"ok","result":{"id":[3],"title":["Halo!"],"content":["test very long string that contains very much of a..."],"type":["plain"],"tags":[[null]]}}'
    run_test_on_port $PORT test

    test['api']='/api/find_snippets'
    test['query']=''
    test['compare']='{"status":"ok","result":{"id":[1,2,3,4],"title":["Hello","Привет","Halo!","Маркdown!"],"content":["world","Мир","test very long string that contains very much of a...","# Title 1\n## Сабтайтл 2\nНекоторый текст\n```\nint ma..."],"type":["bash","bash","plain","markdown"],"tags":[["kafka","c"],["c"],[null],["test"]]}}'
    run_test_on_port $PORT test

    test['api']='/api/find_snippets'
    test['query']='?tags=c'
    test['compare']='{"status":"ok","result":{"id":[1,2],"title":["Hello","Привет"],"content":["world","Мир"],"type":["bash","bash"],"tags":[["kafka","c"],["c"]]}}'
    run_test_on_port $PORT test

    test['api']='/api/find_snippets'
    test['query']='?tags=kafka&type=bash'
    test['compare']='{"status":"ok","result":{"id":[1],"title":["Hello"],"content":["world"],"type":["bash"],"tags":[["kafka","c"]]}}'
    run_test_on_port $PORT test

    test['api']='/api/find_snippets'
    test['query']='?tags=kafka&type=bash'
    test['compare']='{"status":"ok","result":{"id":[1],"title":["Hello"],"content":["world"],"type":["bash"],"tags":[["kafka","c"]]}}'
    run_test_on_port $PORT test

    test['api']="/api/get_snippet"
    test['query']='?id=4'
    test['compare']='{"status":"ok","result":{"id":4,"title":"Маркdown!","content":"<h1>Title 1</h1>\n<h2>Сабтайтл 2</h2>\n<p>Некоторый текст</p>\n<pre><code>int main(void){\n    printf(&quot;hello world&quot;);\n    return 0;\n}\n</code></pre>\n<h2>Subtitle 2</h2>\n<p>Некоторый text.</p>\n","type":"markdown","tags":["test"]}}'
    run_test_on_port $PORT test

    test['api']="/api/get_snippet"
    test['query']='?id=4&edit=true'
    test['compare']='{"status":"ok","result":{"id":4,"title":"Маркdown!","content":"# Title 1\n## Сабтайтл 2\nНекоторый текст\n```\nint main(void){\n    printf(\"hello world\");\n    return 0;\n}\n```\n## Subtitle 2\nНекоторый text.\n","type":"markdown","tags":["test"]}}'
    run_test_on_port $PORT test

    test['query']=''
    test['body']='{"title":"Your title","content":"Your code here","type":"plain","tags":[]}'
    test['api']="/api/create_snippet"
    test['compare']='{"status":"ok","id":5}'
    run_test_on_port $PORT test

    test['body']=''
    test['api']="/api/get_snippet"
    test['query']='?id=5'
    test['compare']='{"status":"ok","result":{"id":5,"title":"Your title","content":"Your code here","type":"plain","tags":[null]}}'
    run_test_on_port $PORT test

    test['body']='{"title":"Your title 2","content":"Your code here too","type":"plain","tags":[]}'
    test['api']='/api/create_snippet'
    test['query']='?edit=true&id=6'
    test['compare']='{"status":"ok","id":6}'
    run_test_on_port $PORT test

    test['api']="/api/delete_snippet"
    test['body']=''
    test['query']='?id=5'
    test['method']='DELETE'
    test['compare']='{"status":"ok","id":5}'
    run_test_on_port $PORT test

    test['method']=''
    test['api']="/api/get_snippet"
    test['query']='?id=10'
    test['compare']='{"status":"error","msg":"snippet not found"}'
    run_test_on_port $PORT test
}


rm test.db
./init_db.sh test.db
($VALGRIND ./main -c test.lua ) &

# TODO: better server starter
sleep 1
run_tests 8080
kill %1
rm test.db
./init_db.sh test.db
($VALGRIND ./main -c test.lua ) &
sleep 1
run_tests 8083

rm -rf uploads || true
mkdir -p uploads/tmp
echo test > uploads/tmp/1
curl -s -F "test.name=hello" -F "test.path=uploads/tmp/1" "localhost:$PORT/api/upload"

kill %2
echo tests passed
