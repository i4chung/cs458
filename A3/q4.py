import requests
import base64
import nacl

import nacl
import nacl.secret
import nacl.utils
import nacl.pwhash
from nacl.signing import SigningKey

import binascii

api_token = '27c3a67e288a7e1a8eeb5401769cc073c9cb5ec1f26114579a47843ff635c8c6'

# Part 1. upload a public verification key
# Generate a new random signing key
signing_key = SigningKey.generate()
print(binascii.hexlify(signing_key.verify_key.encode()))

url = 'https://hash-browns.cs.uwaterloo.ca/api/signed/set-key'
headers={
  'Content-type': 'application/json', 
  'Accept': 'application/json'
}
data={
  "api_token": api_token,
  "pubkey": base64.b64encode(signing_key.verify_key.encode())
}
r = requests.post(url, headers=headers, json=data)
print(r.json())

# Part 2. send message
headers={
  'Content-type': 'application/json', 
  'Accept': 'application/json'
}
url = 'https://hash-browns.cs.uwaterloo.ca/api/signed/send'
data={
  "api_token": api_token,
  "recipient": "Batman",
  "msg": base64.b64encode(signing_key.sign(b"IS THIS WORKING?"))
}
r = requests.post(url, headers=headers, json=data)
print(r.json())