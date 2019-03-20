import requests
import json
import time

from authorizer import jwt_helper
import jwt


url = "http://localhost:5000"
login_data = {"psid": "123456"}

login_uri = f"{url}/login"
protected_uri = f"{url}/protectedResource"
refresh_uri = f"{url}/token"

s = requests.Session()

# Access Protected URI without cookies
response = s.get(protected_uri)
print("Status Code for cookie-less access: {}".format(response.status_code))

# Get token
print("Getting tokens")
response = s.post(login_uri , data = login_data)
# Check cookies
print(f"Access Token: {response.cookies['accToken'][:5]}...{response.cookies['accToken'][-5:]}")
print(f"Refresh Token: {response.cookies['refToken'][:5]}...{response.cookies['refToken'][-5:]}")

# Access Protected URI with cookie
response = s.get(protected_uri)
print("Status Code for valid token: {}".format(response.status_code))
print(response.text)

# Wait for token to expire
print("Waiting for token to expire...")
time.sleep(10)
response = s.get(protected_uri)
print("Status Code for expired token: {}".format(response.status_code))

# Refresh tokens
print("Refreshing tokens")
response = s.post(refresh_uri)
print(f"Access Token: {response.cookies['accToken'][:5]}...{response.cookies['accToken'][-5:]}")
print(f"Refresh Token: {response.cookies['refToken'][:5]}...{response.cookies['refToken'][-5:]}")

# Access Protected URI with cookie
response = s.get(protected_uri)
print("Status Code for valid token: {}".format(response.status_code))
print(response.text)