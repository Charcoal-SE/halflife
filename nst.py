#!/usr/bin/env python

import json
import logging
import sys

import halflife


#logging.basicConfig(level=logging.INFO, format='%(module)s:%(message)s')
logging.basicConfig(level=logging.WARN, format='%(module)s:%(message)s')
with open('halflife.conf') as conffile:
    conf = json.loads(conffile.read())
with open(sys.argv[1]) as jfile:
    posts = json.loads(jfile.read())
h = halflife.Halflife(conf['metasmoke-key'])
for post in posts:
    try:
        h.check(post)
    except KeyboardInterrupt:
        break
