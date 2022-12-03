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
headers={
  'Content-type': 'application/json', 
  'Accept': 'application/json'
}

# Part 1. upload a signed prekey
# Generate a new random signing key
signing_key = SigningKey.generate()

url = 'https://hash-browns.cs.uwaterloo.ca/api/prekey/set-identity-key'
data={
  "api_token": api_token,
  "pubkey": base64.b64encode(signing_key.verify_key.encode())
}
r = requests.post(url, headers=headers, json=data)
print(r.json())

# signed prekey
my_sk = nacl.public.PrivateKey.generate()
my_pk = my_sk.public_key

url = 'https://hash-browns.cs.uwaterloo.ca/api/prekey/set-signed-prekey'
data={
  "api_token": api_token,
  "pubkey": base64.b64encode(signing_key.sign(my_pk.encode()))
}
r = requests.post(url, headers=headers, json=data)
print(r.json())

# Part 2. send encrypted message
# get batman's public key

url = 'https://hash-browns.cs.uwaterloo.ca/api/prekey/get-identity-key'
data={
  "api_token": api_token,
  "user": "Batman"
}
r = requests.post(url, headers=headers, json=data)
print(r.json())

bat_vk = base64.b64decode(r.json()['pubkey'])

# get batman's signed prekey
url = 'https://hash-browns.cs.uwaterloo.ca/api/prekey/get-signed-prekey'
r = requests.post(url, headers=headers, json=data)
print(r.json())

bat_pk = nacl.bindings.crypto_sign_open(
  base64.b64decode(r.json()['pubkey']), 
  bat_vk
)

# send message
url = 'https://hash-browns.cs.uwaterloo.ca/api/prekey/send'

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
url = 'https://hash-browns.cs.uwaterloo.ca/api/prekey/inbox'

data={"api_token": api_token}
r = requests.post(url, headers=headers, json=data)

print(r.json())

box = nacl.public.Box(
  my_sk, 
  nacl.public.PublicKey(bat_pk)
)
msg = box.decrypt(base64.b64decode(r.json()[0]['msg']))
print(msg)
