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
                for (let column of ["title", "content", "id", "created", "updated"]) {
                    const td = tr.insertCell();
                    td.appendChild(document.createTextNode(`${json["result"][column][i]}`));
                }
            }
            $("#snippets")?.appendChild(tbl);
        })
}

main()
