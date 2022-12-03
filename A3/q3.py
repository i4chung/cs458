import requests
import base64
import nacl

import nacl
import nacl.secret
import nacl.utils
import nacl.pwhash
from nacl.public import Box

api_token = '27c3a67e288a7e1a8eeb5401769cc073c9cb5ec1f26114579a47843ff635c8c6'
shared_pass = b'able measure'
salt = '4c51a6cc42af91aa8c6ce6c8f573ceb3'
operation_limit = 2
mem_limit = 67108864

# Part 1. send encrypted message

key = nacl.pwhash.argon2id.kdf(
    size=32, 
    password=shared_pass, 
    salt=bytes.fromhex(salt), 
    opslimit=operation_limit, 
    memlimit=mem_limit
  )
secret_box = nacl.secret.SecretBox(key)

url = 'https://hash-browns.cs.uwaterloo.ca/api/psp/send'
headers={
  'Content-type': 'application/json', 
  'Accept': 'application/json'
}
data={
  "api_token": api_token,
  "recipient": "Batman",
  "msg": base64.b64encode(secret_box.encrypt(b"I am Batman"))
}
r = requests.post(url, headers=headers, json=data)
print(r.json())

# Part 2. receive message
url = 'https://hash-browns.cs.uwaterloo.ca/api/psp/inbox'
data={"api_token": api_token}
r = requests.post(url, headers=headers, json=data)
msg = base64.b64decode(r.json()[0]['msg'])
print(secret_box.decrypt(msg))