import requests
import base64
import nacl

import nacl.hash
import nacl.bindings
import nacl.utils
import nacl.pwhash
import nacl.public
from nacl.signing import SigningKey

import binascii

api_token = '27c3a67e288a7e1a8eeb5401769cc073c9cb5ec1f26114579a47843ff635c8c6'

# Part 1. verify a public key
# Generate a new random signing key

url = 'https://hash-browns.cs.uwaterloo.ca/api/pke/get-key'
headers={
  'Content-type': 'application/json', 
  'Accept': 'application/json'
}
data={
  "api_token": api_token,
  "user": "Batman"
}
r = requests.post(url, headers=headers, json=data)
print(r.json())
bat_pk = base64.b64decode(r.json()['pubkey'])

# Part 2. send message
my_sk = nacl.public.PrivateKey.generate()
my_pk = my_sk.public_key

url = 'https://hash-browns.cs.uwaterloo.ca/api/pke/set-key'

# 1 set public key
data={
  "api_token": api_token,
  "pubkey": base64.b64encode(my_pk.encode())
}
r = requests.post(url, headers=headers, json=data)
print(r.json())

# 2 send message
url = 'https://hash-browns.cs.uwaterloo.ca/api/pke/send'
nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
box = nacl.bindings.crypto_box(
  b"IS THIS WORKING?", 
  nonce, 
  bat_pk, 
  bytes(my_sk)
)
data={
  "api_token": api_token,
  "recipient": "Batman",
  "msg": base64.b64encode(nonce + box)
}
r = requests.post(url, headers=headers, json=data)
print(r.json())


# Part 3. receive message
url = 'https://hash-browns.cs.uwaterloo.ca/api/pke/inbox'

data={"api_token": api_token}
r = requests.post(url, headers=headers, json=data)

box = nacl.public.Box(
  my_sk, 
  nacl.public.PublicKey(bat_pk)
)
msg = box.decrypt(base64.b64decode(r.json()[0]['msg']))
print(msg)
