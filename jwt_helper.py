import time
import uuid
import json

import jwt
from flask import request, redirect, url_for, Response
from functools import wraps


access_token_duration = 5
refresh_token_duration = 24 * 60 * 60
issuer = 'iss'
audience = 'aud'

def sign_token(token):
    """
    Signs token
    """
    rsa_private_key = get_rsa_private_key()
    if not rsa_private_key:
        return False
    
    headers = {'kid': '1'}    
    signed_token = jwt.encode(token, rsa_private_key, algorithm='RS256', headers=headers)
    return signed_token 

def gen_tokens(subject):
    """
    Provides the bare access and refresh tokens for a single subject
    """
    now = int(time.time())
    access_token = {
        'iss': issuer,
        'sub': subject,
        'iat': now,
        'exp': now + access_token_duration,
        'aud': audience
    }

    refresh_token = {
        'iss': issuer,
        'sub': subject,
        'scope': "Refresh",
        'iat': now,
        'exp': now + refresh_token_duration,
        'jti': uuid.uuid4().__str__(),
        'aud': issuer
    }

    response = {
        "token_type": "Bearer",
        "access_token": sign_token(access_token).decode('ascii'),
        "expires_in" : access_token_duration,
        "refresh_token": sign_token(refresh_token).decode('ascii')
    }

    return response

def get_rsa_public_key(jwt_headers=None):
    """ Gets the public key """
    with open('jwtRS256.key.pub', 'rb') as f:
        public_key = f.read()

    return public_key

def get_rsa_private_key():
    """ Gets the private key """
    with open ('jwtRS256.pem', 'rb') as f:
        private_key = f.read()
    
    return private_key

def get_token_from_headers(headers):
    """
    Extracts token from Authorization HTTP Header
    returns everything after 'Bearer ' in header value
    returns False if Authorization Header not found
    """
    try:
        authorization_header = headers['Authorization']
        enc_token = authorization_header[7:] 
    except KeyError:
        return False
    return enc_token

def decode(token, token_type='access'):
    """
    Decodes token either as Access or Refresh
    Refresh tokens have Issuer as Audience
    All decoding errors are raised to calling function to handle
    """
    public_key = get_rsa_public_key(None)
    jwt_headers = jwt.get_unverified_header(token)

    if token_type == 'access':
        aud = audience
    elif token_type == 'refresh':
        aud = issuer
    else:
        raise jwt.exceptions.InvalidAudienceError
    
    decoded_token = jwt.decode(token, 
                               public_key, 
                               algorithms='RS256',
                               issuer=issuer,
                               audience=aud)
    return jwt_headers, decoded_token

def authorizer(f):
    """
    Decorator for functions to validate / authenticate token
    If token is invalid, return error response
    else proceed to decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        error_response = Response("", status=400)
        expired_token_response = Response("",  status=401)

        enc_token = get_token_from_headers(request.headers)
        if not enc_token:
            return redirect(url_for('index'))

        try:
            jwt_headers, jwt_content = decode(enc_token, token_type='access')
        except (jwt.exceptions.InvalidSignatureError, 
                jwt.exceptions.InvalidAlgorithmError, 
                jwt.exceptions.InvalidIssuerError):
            return error_response
        except jwt.exceptions.InvalidAudienceError:
            return error_response
        except jwt.exceptions.ExpiredSignatureError:
            return expired_token_response
        except jwt.exceptions.DecodeError:
            return error_response
        except jwt.exceptions.InvalidTokenError:
            return error_response
        else:
            return f(*args, **kwargs)
    return decorated_function

def authorizer_refresh(f):
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        error_response = Response("", status=400)

        enc_token = get_token_from_headers(request.headers)
        if not enc_token:
            return redirect(url_for('index'))
        
        try:
            jwt_headers, jwt_content = decode(enc_token, token_type='refresh')
        except jwt.exceptions.InvalidTokenError:
            return error_response
        else:
            return f(*args, **kwargs)

    return decorated_function