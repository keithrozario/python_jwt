import os
import sys
import authorizer
import unittest
import tempfile
import time

from werkzeug.http import parse_cookie

protected_uri = "/protectedResource"
refresh_uri = "/token"

class AuthorizerTestCase(unittest.TestCase):

    def setUp(self):
        authorizer.app.testing = True
        self.app = authorizer.app.test_client()

    def tearDown(self):
        pass
    
    def login(self, username, password):
        return self.app.post('/login', data=dict(username=username, password=password))
    
    def getCookie(self, response, cookie_name):
        cookies = response.headers.getlist('Set-Cookie')
        for cookie in cookies:
            value = parse_cookie(cookie).get(cookie_name)
            if value:
                return value
        return None
    
    def test_login_wrong_parameters(self):
        resp = self.app.post('/login')
        assert resp.status_code == 500
        cookies = resp.headers.getlist('Set-Cookie')
        assert len(cookies) == 0

        resp = self.app.post('/login', data=dict(username='admin'))
        assert resp.status_code == 500
        cookies = resp.headers.getlist('Set-Cookie')
        assert len(cookies) == 0

        resp = self.app.post('/login', data=dict(password='admin'))
        assert resp.status_code == 500
        cookies = resp.headers.getlist('Set-Cookie')
        assert len(cookies) == 0
    
    def test_protected_resource_fail(self):
        """ attempt protected resource with no cookies set """
        resp = self.app.get(protected_uri)
        assert resp.status_code == 302
    
    def test_invalid_logins(self):
        """ test invalid passwords """
        resp = self.login('nothing', 'nothing')
        assert resp.status_code == 403
        cookies = resp.headers.getlist('Set-Cookie')
        assert len(cookies) == 0
        
        resp = self.login('admin', 'wrongadmingpassword')
        assert resp.status_code == 403
        cookies = resp.headers.getlist('Set-Cookie')
        assert len(cookies) == 0
        
        resp  = self.login('wrongadminuser', 'admin')
        assert resp.status_code == 403
        cookies = resp.headers.getlist('Set-Cookie')
        assert len(cookies) == 0
    
    def test_login_cookies(self):
        """ checks if login grants two cookies and length of cookies > 10"""
        resp = self.login('admin', 'admin')
        cookies = resp.headers.getlist('Set-Cookie')
        assert len(cookies) == 2
        for cookie in ['accToken', 'refToken']:
            token = self.getCookie(resp, cookie)
            assert len(token) > 10
    
    def test_protected_resource_pass(self):
        """checks if we can access the protected resource with token"""
        resp = self.login('admin', 'admin')
        resp = self.app.get(protected_uri)
        assert resp.status_code == 200

        # time out the access_token
        time.sleep(11)
        resp = self.app.get(protected_uri)
        assert resp.status_code == 401

        # refresh token
        resp = self.app.post(refresh_uri)
        cookies = resp.headers.getlist('Set-Cookie')
        assert len(cookies) == 2

        # try protected resource again
        resp = self.app.get(protected_uri)
        assert resp.status_code == 200

if __name__ == '__main__':
    unittest.main()