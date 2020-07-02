from ftw.oidcauth.errors import OIDCBaseError
from ftw.oidcauth.tests import IntegrationTestCase
from mock import Mock
from mock import patch
from zope.publisher.interfaces import NotFound


class TestOIDCView(IntegrationTestCase):

    def setUp(self):
        self.plugin = self.layer['plugin']
        self.request = self.layer['request']
        self.portal = self.layer['portal']

    @patch('ftw.oidcauth.browser.oidc.OIDCClientAuthentication')
    def test_oidc_view_if_authentication_is_a_success(self, client_auth_mock):
        oidc_view = self.portal.unrestrictedTraverse('@@oidc')
        oidc_view.publishTraverse(self.request, 'callback')
        oidc_view()

        self.assertEqual(self.request.response.status, 302)
        self.assertIn(
            'OIDCClientAuthentication().get_redirect()',
            self.request.response.headers['location'])

    @patch('ftw.oidcauth.browser.oidc.OIDCClientAuthentication')
    def test_oidc_view_if_authentication_is_not_successful(self, client_auth_mock):
        client_auth_mock.return_value.authorize.side_effect=OIDCBaseError
        oidc_view = self.portal.unrestrictedTraverse('@@oidc')
        oidc_view.publishTraverse(self.request, 'callback')
        oidc_view()

        self.assertEqual(self.request.response.status, 400)

    @patch('ftw.oidcauth.browser.oidc.OIDCClientAuthentication')
    def test_oidc_view_with_invalid_name(self, client_auth_mock):
        oidc_view = self.portal.unrestrictedTraverse('@@oidc')

        with self.assertRaises(NotFound):
            oidc_view.publishTraverse(self.request, 'james-ppk')

    @patch('ftw.oidcauth.browser.oidc.OIDCClientAuthentication')
    def test_oidc_view_with_no_name(self, client_auth_mock):
        oidc_view = self.portal.unrestrictedTraverse('@@oidc')

        with self.assertRaises(NotFound):
            oidc_view.publishTraverse(self.request, None)
