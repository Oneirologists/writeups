#!/usr/bin/env python3

import requests, base64, hashpumpy

host = "http://crypto.chal.csaw.io:5003"

def new(author, note):
    payload={'author': author, 'note': note}
    print("makig new note with payload={}".format(payload))
    r = requests.post('{}/new'.format(host), data=payload)
    return r.text

def parse_resp(resp):
    return resp.split(' ')[2].split(':')[0].strip(), resp.split(' ')[2].split(':')[1].strip()

def view(id, integrity):
    payload={'id': id, 'integrity': integrity}
    print("viewing note with payload={}".format(payload))
    r = requests.post('{}/view'.format(host), data=payload)
    return r.text
author = 'aa'
note = 'lol&admin=True&access_sensitive=True'
my_id, my_int = parse_resp(new(author, note))
print(view(my_id, my_int))

i = 2
while True:
    new_int, new_data = hashpumpy.hashpump(my_int, 'admin=False&access_sensitive=False&author={}&note={}&entrynum=783'.format(author, note), '&entrynum=7', i)
    new_data = new_data.decode('unicode-escape').encode('unicode-escape')
    new_id = base64.b64encode(new_data).decode()
    print("new_int={}".format(new_int))
    print("new_data={}".format(new_data))
    print("new_id={}".format(new_id))
    resp = view(new_id, new_int)
    if '>:(' in resp: i += 1
    else:
        print(i, resp)
        break
# i = 13, flag{h4ck_th3_h4sh}