import requests
import base64
import nacl

import nacl
import nacl.secret
import nacl.utils
from nacl.public import Box

api_token = '27c3a67e288a7e1a8eeb5401769cc073c9cb5ec1f26114579a47843ff635c8c6'
shared_key = '7534ef735767bab80bdb0688eaa9eadd5136ffa031300abf1c385ddcee187f2f'

# Part 1. send encrypted message

secret_box = nacl.secret.SecretBox(bytes.fromhex(shared_key))

url = 'https://hash-browns.cs.uwaterloo.ca/api/psk/send'
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
url = 'https://hash-browns.cs.uwaterloo.ca/api/psk/inbox'
data={"api_token": api_token}
r = requests.post(url, headers=headers, json=data)
msg = base64.b64decode(r.json()[0]['msg'])
print(secret_box.decrypt(msg))