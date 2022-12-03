import requests
import base64

api_token = '27c3a67e288a7e1a8eeb5401769cc073c9cb5ec1f26114579a47843ff635c8c6'

# Part 1. send message
url = 'https://hash-browns.cs.uwaterloo.ca/api/plain/send'
headers={
  'Content-type': 'application/json', 
  'Accept': 'application/json'
}
data={
  "api_token": api_token,
  "recipient": "Batman",
  "msg": base64.b64encode("Hello Batman!".encode('ascii'))
}
r = requests.post(url, headers=headers, json=data)
print(r.json())

# Part 2. receive message
url = 'https://hash-browns.cs.uwaterloo.ca/api/plain/inbox'
data={"api_token": api_token}
r = requests.post(url, headers=headers, json=data)
msg = base64.b64decode(r.json()[0]['msg'])
print(msg)