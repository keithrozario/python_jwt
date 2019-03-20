import os
import authorizer
import unittest
import tempfile
import time

from werkzeug.http import parse_cookie

protected_uri = "/protectedResource"
refresh_uri = "/token"

class FlaskrTestCase(unittest.TestCase):

    def setUp(self):
        authorizer.app.testing = True
        self.app = authorizer.app.test_client()

    def tearDown(self):
        pass
    
    def login(self, id):
        return self.app.post('/login', data=dict(psid=id))
    
    def getCookie(self, response, cookie_name):
        cookies = response.headers.getlist('Set-Cookie')
        for cookie in cookies:
            value = parse_cookie(cookie).get(cookie_name)
            if value:
                return value
        return None
    
    def test_protected_resource_fail(self):
        """ attempt protected resource with no cookies set """
        resp = self.app.get(protected_uri)
        assert resp.status_code == 302
    
    def test_login(self):
        """ checks if login grants two cookies and length of cookies > 10"""
        resp = self.login('12345')
        cookies = resp.headers.getlist('Set-Cookie')
        assert len(cookies) == 2
        for cookie in ['accToken', 'refToken']:
            token = self.getCookie(resp, cookie)
            assert len(token) > 10
    
    def test_protected_resource_pass(self):
        """checks if we can access the protected resource with token"""
        resp = self.login('12345')
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