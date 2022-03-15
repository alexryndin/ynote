#!/bin/sh

if [ ! -f "test.db" ]; then
    sqlite3 test.db < init_db.sql
else
    echo "Already exists"
fi
