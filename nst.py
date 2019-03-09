#!/usr/bin/env python

import json
import logging
import sys

import halflife

loglevel = logging.WARNING
if '--verbose' in sys.argv[1:]:
    loglevel = logging.INFO
    sys.argv.remove('--verbose')
logging.basicConfig(level=loglevel, format='%(module)s:%(message)s')
with open('halflife.conf') as conffile:
    conf = json.loads(conffile.read())
if len(sys.argv) == 2:
    with open(sys.argv[1]) as jfile:
        posts = json.loads(jfile.read())
else:
    posts = json.loads(sys.stdin.read())
h = halflife.Halflife(conf['metasmoke-key'])
for post in posts:
    try:
        h.check(post)
    except KeyboardInterrupt:
        break
