from ftw.oidcauth.browser.oidc_tools import OIDCClientAuthentication
from ftw.oidcauth.errors import OIDCJwkEndpointError
from ftw.oidcauth.errors import OIDCSubMismatchError
from ftw.oidcauth.errors import OIDCTokenError
from ftw.oidcauth.errors import OIDCUserInfoError
from ftw.oidcauth.testing import FTW_OIDCAUTH_INTEGRATION_TESTING
from mock import Mock
from mock import patch
import unittest


class TestOIDCClientAuthentication(unittest.TestCase):

    layer = FTW_OIDCAUTH_INTEGRATION_TESTING

    def setUp(self):
        self.plugin = self.layer['plugin']
        self.request = self.layer['request']

    @patch('requests.post')
    def test_authorize_client_post_request(self, post_mock):
        post_mock.return_value = self._mock_response(200)
        code = '9999'
        state = ''
        oidc_auth = OIDCClientAuthentication(self.request, code, state)
        oidc_auth._authorize_client()

        post_mock.assert_called_once_with(
            u'https://auth.ch/openid/token',
            headers={'Authorization': u'Basic NDI6NDI='},
            data={
                'code': '9999',
                'grant_type': 'authorization_code',
                'redirect_uri': 'http://nohost/plone/oidc/callback'})

    @patch('requests.post')
    def test_authorize_client_post_request_error(self, post_mock):
        post_mock.return_value = self._mock_response(400)
        code = '9999'
        state = ''
        oidc_auth = OIDCClientAuthentication(self.request, code, state)

        with self.assertRaises(OIDCTokenError):
            oidc_auth._authorize_client()

    @patch('requests.get')
    def test_obtain_validated_token_get_request_error(self, get_mock):
        get_mock.return_value = self._mock_response(400)
        code = '9999'
        state = ''
        oidc_auth = OIDCClientAuthentication(self.request, code, state)

        token_data = {
            u'access_token': u'8800c60bd6f44a78a9c9a963b615170c',
            u'token_type': u'bearer',
            u'expires_in': 3600,
            u'refresh_token': u'30894d955fa7434bb848f12a55dcf8de',
            u'id_token': u'MdrZBzXHCBwvaDDL4sYaBzhjhnhE9Y2'}

        with self.assertRaises(OIDCJwkEndpointError):
            oidc_auth._obtain_validated_token(token_data)

    @patch('requests.get')
    def test_get_user_info_get_request(self, get_mock):
        get_mock.return_value = self._mock_response(200)
        code = '9999'
        state = ''
        oidc_auth = OIDCClientAuthentication(self.request, code, state)

        access_token = u'8800c60bd6f44a78a9c9a963b615170c'
        oidc_auth._get_user_info(access_token)

        get_mock.assert_called_once_with(
            u'https://auth.ch/openid/userinfo',
            headers={
                'Authorization': 'Bearer 8800c60bd6f44a78a9c9a963b615170c'})

    @patch('requests.get')
    def test_get_user_info_get_request_error(self, get_mock):
        get_mock.return_value = self._mock_response(400)
        code = '9999'
        state = ''
        oidc_auth = OIDCClientAuthentication(self.request, code, state)

        access_token = u'8800c60bd6f44a78a9c9a963b615170c'

        with self.assertRaises(OIDCUserInfoError):
            oidc_auth._get_user_info(access_token)

    def test_validate_sub_matching(self):
        code = '9999'
        state = ''
        oidc_auth = OIDCClientAuthentication(self.request, code, state)

        token = {'sub': '424242'}
        user_info = {'sub': '424242'}
        self.assertIsNone(
            oidc_auth._validate_sub_matching(token, user_info))

        token = {'sub': '424242'}
        user_info = {'sub': '525252'}
        with self.assertRaises(OIDCSubMismatchError):
            oidc_auth._validate_sub_matching(token, user_info)

    def _mock_response(self, status_code, json_data=None):
        mock_resp = Mock()
        mock_resp.status_code = status_code
        if json_data:
            def _json():
                return json_data
            mock_resp.json = _json
        return mock_resp
