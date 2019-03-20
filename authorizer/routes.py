import time
import uuid
import json

from flask import Flask, request, jsonify, Response, make_response
from authorizer import app

from authorizer import jwt_helper
import jwt.exceptions

response_headers = {
    "Cache-Control" : "no-cache, no-store, must-revalidate"
}

@app.route('/', methods=['POST'])
def index():
    return Response("index.html", status=200, headers=response_headers)

@app.route('/protectedResource')
@jwt_helper.authorizer
def protected_resource():
    return 'Protected_resource Woo Hoo!'

@app.route('/login', methods=['POST'])
def login():

    # check_login()
    subject = request.form['psid']
    refresh_token, access_token = jwt_helper.gen_tokens(subject)
    resp = jwt_helper.make_token_response(access_token, refresh_token)
    return resp

@app.route('/token', methods=['POST'])
@jwt_helper.authorizer_refresh
def refresh_token():
    """
    authorizer_refresh already checks validity of refresh token. 
    Here we perform additional checks and return the tokens
    """

    enc_token = jwt_helper.get_token_from_cookie(cookies=request.cookies, key='refToken')
    __, jwt_content = jwt_helper.decode(token=enc_token, token_type='refresh')

    # check_jti()
    subject = jwt_content['sub']
    refresh_token, access_token = jwt_helper.gen_tokens(subject)
    resp = jwt_helper.make_token_response(access_token, refresh_token)
    return resp