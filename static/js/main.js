"use strict";

function main() {
    let url = new URL('/api/find_snippets', window.location.origin);
    fetch(url)
        .then((response) => {
            return response.json();
        })
        .then((json) => {
            console.log(json);
            const tbl = document.createElement('table');
            const tbdy = document.createElement('tbody');
            tbl.appendChild(tbdy);
            for (let i = 0; i < json["result"]["title"].length; i++) {
                const tr = tbdy.insertRow();
                const td_title = tr.insertCell();
                td_title.appendChild(document.createTextNode(`${json["result"]["title"][i]}`));
                const td_content = tr.insertCell();
                td_content.appendChild(document.createTextNode(`${json["result"]["content"][i]}`));
            }
            $("#snippets")?.appendChild(tbl);
        })
}

main()
