#!/bin/python3

import requests
import json


class Test:

    def __init__(self, api, query, body, compare, method='GET', host='localhost', port=8080, status=200):
        self.api = api
        self.query = query
        self.body = body
        self.host = host
        self.port = port
        self.compare = json.loads(compare) if type(compare) == str else compare
        self.status = status
        self.method = method

    def run(self):
        r = requests.get(
            f'http://{self.host}:{self.port}{self.api}', self.query or None)

        if (r.status_code != self.status):
            raise Exception(
                f"Expected code {self.status}, got {r.status_code}")

        if 'result' in r.json():
            r.json()['result'].pop('created')
            r.json()['result'].pop('updated')


Test('/api/find_snippets',
     {'tags': None},
     '',
     """{"status":"ok","result":{"id":[3],"title":["Halo!"],"content":["test very long string that contains very much of a..."],"type":["plain"],"tags":[[null]]}}"""
     ).run()
