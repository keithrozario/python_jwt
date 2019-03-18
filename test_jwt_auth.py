import requests
import json
import time

import jwt_helper
import jwt


url = "http://localhost:5000"
login_data = {"psid": "123456"}

login_uri = f"{url}/login"
protected_uri = f"{url}/protectedResource"
refresh_uri = f"{url}/token"

# No token
response = requests.get(protected_uri )
print("Status Code for No Token: {}".format(response.status_code))

# Get token
response = requests.post(login_uri , data = login_data)
token_wrapper = json.loads(response.content)
access_token = token_wrapper['access_token']
refresh_token = token_wrapper['refresh_token']

# print out tokens
print(f"Access Token: {jwt_helper.decode(access_token, token_type='access')}")
print(f"Refresh Token: {jwt_helper.decode(refresh_token, token_type='refresh')}")

# Try Token
headers = {'Authorization': f'Bearer {access_token}'}
response = requests.get(protected_uri, headers=headers)
print("Status Code for Valid token: {}".format(response.status_code))

# Invalid Header
bad_token = '.,.' + access_token[3:]
bad_header = {'Authorization': f'Bearer {bad_token}'}
response = requests.get(protected_uri, headers=bad_header)
print("Status Code for Invalid token: {}".format(response.status_code))

# Invalid Signature
bad_token = access_token[:-3] + 'xxx'
bad_header = {'Authorization': f'Bearer {bad_token}'}
response = requests.get(protected_uri, headers=bad_header)
print("Status Code for Invalidly Signed token: {}".format(response.status_code))

# Expired Signature
time.sleep(5 + 2)
response = requests.get(protected_uri, headers=headers)
print("Status Code for Expired token: {}".format(response.status_code))

# refresh token
headers = {'Authorization': f'Bearer {refresh_token}'}
response = requests.post(refresh_uri, headers=headers)
token_wrapper = json.loads(response.content)
access_token = token_wrapper['access_token']
refresh_token = token_wrapper['refresh_token']

print(f"Access Token: {jwt_helper.decode(access_token, token_type='access')}")
print(f"Refresh Token: {jwt_helper.decode(refresh_token, token_type='refresh')}")

# Try Token
headers = {'Authorization': f'Bearer {access_token}'}
response = requests.get(protected_uri, headers=headers)
print("Status Code for Refreshed token: {}".format(response.status_code))