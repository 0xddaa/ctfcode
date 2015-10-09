#!/usr/bin/env python

import requests

post = requests.post
get = requests.get

def login(uri, user, passwd):
    r = get(uri)
    start = r.text.find("authenticity_token") + 56
    end = start + r.text[start:].find("\"")
    csrf = r.text[start:end]
    post_data = {"user[username]": user, "user[password]": passwd, "authenticity_token": csrf}
    r = post(uri, data = post_data, cookies = r.cookies)
    return r.cookies

def submit_flag(uri, cookies, flag, fail_pattern = "Your flag is wrong! :("):
    r = get("http://140.113.194.85:81/problems/1", cookies = cookies)
    start = r.text.find("authenticity_token") + 56
    end = start + r.text[start:].find("\"")
    csrf = r.text[start:end]
    post_data = {"authenticity_token": csrf, \
        "problem_id": "1", \
        "flag": flag}
    r = requests.post("http://140.113.194.85:81/submit", data = post_data, cookies = cookies)
    return fail_pattern not in r.text

cookies = login("http://140.113.194.85:81/users/sign_in", "meheap", "12345678")
submit_flag("http://140.113.194.85:81/submit", cookies, flag):
