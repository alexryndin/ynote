#!/bin/sh

db_name=~/.ynote.db

if [ ! -z $1 ]; then
    db_name=$1
fi

if [ ! -f "${db_name}" ]; then
    sqlite3 "${db_name}" < init_db.sql
else
    echo "Already exists"
fi
