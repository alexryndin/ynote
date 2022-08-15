"use strict";

const types = [
    "plain",
    "code",
    "bash",
    "markdown",
];

const tags_sep = ',';

function msg_info(str) {
    $("#message-block").innerHTML = str;
    $("#message-block").className = "bar info";
    $("#message-block").style.display = '';
}

function msg_err(str) {
    $("#message-block").innerHTML = str;
    $("#message-block").className = "bar error";
    $("#message-block").style.display = '';
}

function delete_snippet(id) {
    if (typeof id !== 'number' || id === 0) {
        throw new Error("id must be a number");
    }

    let url = new URL('/api/delete_snippet', window.location.origin);
    let params = { 'id': id };
    url.search = new URLSearchParams(params).toString()
    msg_info("Sending request...");
    fetch(url)
        .then((response) => {
            return response.json();
        })
        .then((json) => {
            console.log(json);
            location.reload();
        });

}

function ask_delete_snippet(evt) {
    const id = evt.currentTarget._snippet_id;
    let result = window.confirm(`Delete snippet ${id}?`);
    console.log(result);
    if (result) {
        delete_snippet(id);
    }
}

async function fetch_snippet_data(id, edit) {
    let url = new URL('/api/get_snippet', window.location.origin);
    let params = { 'id': id };
    if (edit) {
        params['edit'] = true;
    }
    url.search = new URLSearchParams(params).toString()
    let response = await fetch(url);
    if (!response.ok) {
        let json = await response.json();
        msg_err(`Got ${response.statusText}: ${json.msg ? json.msg : ""}`);
        throw new Error(`${response.status} is unacceptable for me!`);
    }
    return response.json();
}

async function create_snippet_send(title, content, type, tags, edit, id) {
    if (!(
        typeof title === 'string' &&
        typeof content === 'string' &&
        typeof type === 'string' &&
        typeof tags === 'string'
    )) {
        throw new Error('String is expected');
    }
    if (edit) {
        if (typeof id !== 'number' || id === 0) {
            throw new Error("id required when editing snippet");
        }
    }
    console.log(title);
    console.log(content);
    console.log(type);
    const tags_list = tags.split(tags_sep)
        .map(x => x.trim())
        .filter(x => x !== "")
        ;
    console.log(
        tags_list
    );
    const data = {
        "title": title,
        "content": content,
        "type": type,
        "tags": tags_list,
    }
    let url = new URL('/api/create_snippet', window.location.origin);
    if (edit) {
        let params = { 'id': id, 'edit': true };
        url.search = new URLSearchParams(params).toString()
    }
    msg_info("Sending request...");
    console.log(JSON.stringify(data));
    let response = await fetch(url, {
        method: "POST",
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!response.ok) {
        let json = await response.json();
        msg_err(`Got ${response.statusText}: ${json.msg ? json.msg : ""}`);
        throw new Error(`${response.status} is unacceptable for me!`);
    }
    response.json().then((json) => {
        if (json["status"] === "error") {
            msg_err(json["msg"]);
            return;
        }
        console.log("Request complete! response:", json);
        const snippet_url = new URL('/snippet.html', window.location.origin);
        const params = { id: json["id"] };
        console.log(json["id"]);
        snippet_url.search = new URLSearchParams(params).toString()
        window.location.replace(snippet_url.toString());
    })
        .catch((err) => {
            msg_err(err);
        })
        ;
}

async function create_snippet() {
    const urlSearchParams = new URLSearchParams(window.location.search);
    let edit;
    let id;

    let edit_str = urlSearchParams.get('edit');
    if (typeof edit_str === 'string' && edit_str.toLowerCase() === 'true') {
        edit = true
        id = Number(urlSearchParams.get('id'));
        if (typeof id !== 'number' || id === 0) {
            throw new Error("id required when editing snippet");
        }
    } else {
        edit = false
    }
    $("#send-button").addEventListener("click", function() {
        const title = $("#title").textContent;
        const content = $("#content").innerText;
        const type = $("#type-list").value;
        const tags = $("#tags").value;
        try {
            create_snippet_send(title, content, type, tags, edit, id);
        } catch (error) {
            msg_err(error)
        }

    });
    for (const type of types) {
        const option = document.createElement('option');
        option.value = type;
        option.appendChild(document.createTextNode(type));
        $("#type-list").append(option);
    }
    if (edit) {
        console.log(id);
        const json = await fetch_snippet_data(id, edit);
        console.log(json);
        $("#title").textContent = json["result"]["title"];
        $("#content").innerText = json["result"]["content"];
        $("#type-list").value = json["result"]["type"];
        $("#tags").value = json["result"]["tags"].join(`${tags_sep} `);
        console.log(json);
    }
}

function index() {
    let url = new URL('/api/find_snippets', window.location.origin);
    url.search = window.location.search;
    console.log(url.search);
    fetch(url)
        .then((response) => {
            return response.json();
        })
        .then((json) => {
            console.log(json);
            document.querySelectorAll('#snippets-table > thead > tr > th').forEach(x => x.addEventListener("click", Sortable.sort))
            const tbl = $("#snippets-table");
            tbl.className = 'sortable';
            const tbdy = document.createElement('tbody');
            tbl.appendChild(tbdy);
            const result = json["result"];
            for (let i = 0; i < json["result"]["title"].length; i++) {
                const tr = tbdy.insertRow();
                for (let column of ["id", "title", "content", "type", "created", "updated", "tags"]) {
                    const td = tr.insertCell();
                    console.log(column);
                    if (column == "title") {
                        const a = document.createElement('a');
                        a.title = result[column][i];
                        const url = new URL('/snippet.html', window.location.origin);
                        const params = { 'id': result["id"][i] };
                        url.search = new URLSearchParams(params).toString()
                        a.href = url.toString();
                        a.appendChild(document.createTextNode(result[column][i]));
                        td.appendChild(a);

                    } else if (column == "tags") {
                        td.appendChild(document.createTextNode(`${result[column][i].join(', ')}`));
                    } else {
                        td.appendChild(document.createTextNode(`${result[column][i]}`));
                    }
                }
                const td = tr.insertCell();
                const edit_link = document.createElement('a');
                edit_link.title = "edit";
                const url = new URL('/create_snippet.html', window.location.origin);
                const params = {
                    'id': result["id"][i],
                    'edit': 'true',
                };
                url.search = new URLSearchParams(params).toString()
                edit_link.href = url.toString();
                edit_link.appendChild(document.createTextNode('[edit]'));
                // document.body.appendChild(edit_link);
                td.appendChild(edit_link);

                const delete_columnt = tr.insertCell();
                const delete_link = document.createElement('a');
                delete_link._snippet_id = result["id"][i];
                delete_link.addEventListener("click", ask_delete_snippet);

                edit_link.title = "edit";
                const delete_url = new URL('/delete_snippet.html', window.location.origin);
                const delete_params = {
                    'id': result["id"][i],
                };
                delete_url.search = new URLSearchParams(delete_params).toString()
                delete_link.appendChild(document.createTextNode('[x]'));
                // document.body.appendChild(edit_link);
                delete_columnt.appendChild(delete_link);
            }
            $("#snippets")?.appendChild(tbl);
        })
}

async function snippet() {
    const urlParams = new URLSearchParams(window.location.search);
    const id = urlParams.get('id');
    if (typeof id !== 'string') {
        throw new Error('id expected');
    }

    $("#snippet-id").value = id;
    $("#snippet-id").style.display = 'none';

    const json = await fetch_snippet_data(id, false);

    const h = $('#title');
    h.innerHTML = json["result"]["title"];
    const type = document.createElement('p');
    type.innerHTML = `Type: ${json["result"]["type"]}`;
    $("#snippet")?.appendChild(type);
    const tags = document.createElement('p');
    var sep = `${tags_sep} `;
    tags.innerHTML = `Tags: ${json["result"]["tags"].join(sep)}`;
    $("#snippet")?.appendChild(tags);
    let content;
    switch (json["result"]["type"]) {
        case 'plain':
            content = document.createElement('p');
            break;
        case 'bash':
        case 'c':
            content = document.createElement('code');
            content.className = "container-fluid";
            break;
        case 'markdown':
            content = document.createElement('div');
            content.className = "container-fluid";
            break;
        default:
            content = document.createElement('code');
            content.className = "container-fluid";
            break;
    }
    if (json["result"]["type"] === 'markdown') {
        content.innerHTML = json["result"]["content"];

    } else {
        content.innerText = json["result"]["content"];
    }
    let pre = document.createElement('pre');
    pre.appendChild(content);
    $("#snippet")?.appendChild(pre);
    console.log(json);
}

function main() {
    $("#message-block").style.display = 'none';
    console.log("sasay");
}


main()
