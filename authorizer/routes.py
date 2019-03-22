import time
import uuid
import json

from flask import Flask, request, jsonify, Response, make_response, render_template
from authorizer import app

from authorizer import jwt_helper
import jwt.exceptions

api_prefix = '/api/v1'

@app.route(f'{api_prefix}/login', methods=['POST'])
def login():
    
    try:
        username, password = request.form['username'], request.form['password']
    except KeyError:
        return Response("", 500)

    auth_result = jwt_helper.ldap_authenticate(username, password)
    if auth_result['status'] == 200:
        refresh_token, access_token = jwt_helper.gen_tokens(username)
        resp = jwt_helper.make_token_response(access_token, refresh_token)
    else:
        resp = Response("",auth_result['status'])

    return resp

@app.route(f'{api_prefix}/token', methods=['POST'])
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

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('auth/login.html')

@app.route('/protectedResource')
@jwt_helper.authorizer
def protected_resource():
    return 'Protected_resource Woo Hoo!'