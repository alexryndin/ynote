#!/bin/sh

if [ -z $1 ]; then
    echo "db name required"
fi

db_name=$1

if [ ! -f db_name ]; then
    sqlite3 "${db_name}" < init_db.sql
else
    echo "Already exists"
fi
