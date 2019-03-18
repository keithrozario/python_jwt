import time
import uuid
import json

import jwt_helper
import jwt.exceptions

from flask import Flask, request, jsonify, Response

app = Flask(__name__)
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
    bearer_response = jwt_helper.gen_tokens(subject)
    return Response(json.dumps(bearer_response), status=200, headers=response_headers)

@app.route('/token', methods=['POST'])
@jwt_helper.authorizer_refresh
def refresh_token():

    enc_token = jwt_helper.get_token_from_headers(request.headers)
    jwt_headers, jwt_content = jwt_helper.decode(enc_token, token_type='refresh')

    # check_jti()
    subject = jwt_content['sub']
    bearer_response = jwt_helper.gen_tokens(subject)

    return Response(json.dumps(bearer_response), status=200, headers=response_headers)

if __name__ == '__main_':

    app.run(debug=True, port=5000)