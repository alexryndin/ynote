#!/bin/bash

set -e

(./main test.db) &

catch() {
    echo "error: response $response expected $compare"
    kill %1
    exit 1
}

trap 'catch' ERR

response=$(curl -fs 'localhost:8080/api/find_snippets?tags=' | jq -c 'del(.result.created, .result.updated)')
compare='{"status":"ok","result":{"id":[3],"title":["Halo!"],"content":["test very long string that contains very much of a..."],"type":["plain"],"tags":[[null]]}}'
[[ "$response" == "$compare" ]] || false

response=$(curl -fs 'localhost:8080/api/find_snippets' | jq -c 'del(.result.created, .result.updated)')
compare='{"status":"ok","result":{"id":[1,2,3],"title":["Hello","Привет","Halo!"],"content":["world","Мир","test very long string that contains very much of a..."],"type":["bash","bash","plain"],"tags":[["kafka","c"],["c"],[null]]}}'
[[ "$response" == "$compare" ]] || false


response=$(curl -fs 'localhost:8080/api/find_snippets?tags=c' | jq -c 'del(.result.created, .result.updated)')
compare='{"status":"ok","result":{"id":[1,2],"title":["Hello","Привет"],"content":["world","Мир"],"type":["bash","bash"],"tags":[["kafka","c"],["c"]]}}'
[[ "$response" == "$compare" ]] || false

response=$(curl -fs 'localhost:8080/api/find_snippets?tags=kafka&type=bash' | jq -c 'del(.result.created, .result.updated)')
compare='{"status":"ok","result":{"id":[1],"title":["Hello"],"content":["world"],"type":["bash"],"tags":[["kafka","c"]]}}'
[[ "$response" == "$compare" ]] || false


kill %1
echo tests passed
