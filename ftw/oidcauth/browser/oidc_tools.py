from DateTime import DateTime
from Products.PlonePAS.events import UserInitialLoginInEvent
from Products.PlonePAS.events import UserLoggedInEvent
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from base64 import b64encode
from ftw.oidcauth.errors import OIDCJwkEndpointError
from ftw.oidcauth.errors import OIDCPluginNotFoundError
from ftw.oidcauth.errors import OIDCSubMismatchError
from ftw.oidcauth.errors import OIDCTokenError
from ftw.oidcauth.errors import OIDCUserAutoProvisionError
from ftw.oidcauth.errors import OIDCUserIDPropertyError
from ftw.oidcauth.errors import OIDCUserInfoError
from ftw.oidcauth.helper import get_oidc_request_uri
from jwt.exceptions import InvalidTokenError
from plone import api
from zope import event
import json
import jwt
import logging
import requests

logger = logging.getLogger('ftw.oidcauth')


class OIDCClientAuthentication(object):
    """Tool to authenticate a user using the OIDC standard.
    """
    def __init__(self, request, code, state):
        self.has_been_authorized = False

        self.code = code
        self.state = state
        self.request = request
        self.oidc_plugin = self._get_oidc_plugin()

    def authorize(self):
        user_info = self._authorize_user()
        props = self._map_properties()
        oidc_user_handler = OIDCUserHandler(self._request, props)
        oidc_user_handler.login_user()
        if oidc_user_handler.is_user_logged_in:
            self.has_been_authorized = True

    def set_redirect(self):
        next_path = self._request.cookies.get('oidc_next')
        self._request.response.redirect('%s' % next_path)

    def _map_properties(self):
        
        props_mapping = self._oidc_plugin._properties_mapping
        props = {key: user_info.get(value)
                 for (key, value) in props_mapping.items()}
        if not props.get('userid') or not user_info.get(props_mapping.get('userid')):
            logger.info('The userid property is not set correctly.')
            raise OIDCUserIDPropertyError
        return props

    def _authorize_user(self):
        """OIDC main authorization code flow:

        1: Get authorization token to authorize on the client side using the
           authorization code received in response to the user authentication
           by the OIDC issuer.
        2: Obtain and validate the token for the user.
        3: Get the user info.
        4: Validate the sub from the validated token/user_info are a match.
        """
        client_auth_token = self._authorize_client()
        token = self._obtain_validated_token(client_auth_token)
        user_info = self._get_user_info(client_auth_token.get('access_token'))
        self._validate_sub_matching(token, user_info)

        return user_info

    def _authorize_client(self):
        """Client side validation of user request code.

        The return value is expected to contain a dictionary with:
            - access_token
            - token_type
            - refresh_token
            - expires_in
            - id_token
        """
        authstr = 'Basic ' + b64encode(
            ('{}:{}'.format(
                self._oidc_plugin._client_id,
                self._oidc_plugin._client_secret)).encode('utf-8')).decode('utf-8')
        headers = {'Authorization': authstr}
        data = {
            'grant_type': 'authorization_code',
            'code': self._code,
            'redirect_uri': get_oidc_request_uri(),
        }

        response = requests.post(
            self._oidc_plugin._token_endpoint,
            data=data,
            headers=headers)

        if response.status_code != 200:
            logger.warning(
                'An error occurred trying to authorize %s', self._code)
            raise OIDCTokenError
        else:
            return response.json()

    def _obtain_validated_token(self, token_data):
        """Obtain validated jwk.
        """
        response = requests.get(self._oidc_plugin._jwks_endpoint)
        if response.status_code != 200:
            logger.info('An error occurred obtaining jwks')
            raise OIDCJwkEndpointError
        jwks = response.json().get('keys')
        id_token = token_data['id_token']
        public_key = self._extract_token_key(jwks, id_token)

        try:
            return jwt.decode(
                id_token, key=public_key, algorithms=['RS256'],
                audience=self._oidc_plugin._client_id)
        except InvalidTokenError:
            logger.warning('An error occurred trying to decode %s', id_token)
            raise OIDCTokenError

    def _get_user_info(self, access_token):
        bearerstr = 'Bearer {}'.format(access_token)
        headers = {'Authorization': bearerstr}
        response = requests.get(
            self._oidc_plugin._user_endpoint, headers=headers)
        if response.status_code != 200:
            logger.warning(
                'An error occurred getting user info for %s.', access_token)
            raise OIDCUserInfoError
        return response.json()

    @staticmethod
    def _get_oidc_plugin():
        """Get the OIDC plugin.

        This method assumes there is only one OIDC plugin.
        """
        portal = api.portal.get()
        plugins = portal.acl_users.plugins
        authenticators = plugins.listPlugins(IChallengePlugin)
        oidc_plugin = None
        for id_, authenticator in authenticators:
            if authenticator.meta_type == "ftw.oidcauth plugin":
                oidc_plugin = authenticator

        return oidc_plugin

    @staticmethod
    def _validate_sub_matching(token, user_info):
        """Validates that sub in the validated token is equal to sub provided
           by the user information.
        """
        token_sub = ''
        if token:
            token_sub = token.get('sub')

        if token_sub != user_info.get('sub') or not token_sub:
            logger.warning(
                'Subject mismatch error: %s unequal %s',
                user_info.get('sub'), token.get('sub'))
            raise OIDCSubMismatchError

    @staticmethod
    def _extract_token_key(jwks, id_token):
        """Extract the matching jwk for an id_token.

        We should always assume that a JWKS will contain multiple keys.
        The kid is used to identify the right key.
        """
        public_keys = {}
        for jwk in jwks:
            kid = jwk.get('kid')
            if not kid:
                continue
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk))
        kid = jwt.get_unverified_header(id_token).get('kid')
        return public_keys.get(kid)


class OIDCUserHandler(object):
    def __init__(self, request, props):
        self.is_user_logged_in = False
        self.properties = props
        self.userid = self._properties.get('userid')
        self.request = request
        self.first_login = False
        self.mtool = api.portal.get_tool('portal_membership')

    def login_user(self):
        member = self._get_member()
        self._setup_session()
        self._update_login_times_and_other_member_properties(member)
        self._fire_login_event(member)
        self._expire_the_clipboard()
        self._create_member_area()
        self.is_user_logged_in = True

    def _get_member(self):
        member = self._mtool.getMemberById(self._userid)
        if member is None:
            plugin = self._get_oidc_plugin()
            if plugin is None:
                logger.warning(
                    'Missing OIDC PAS plugin. Cannot autoprovision user %s.' %
                    self._userid)
                raise OIDCPluginNotFoundError
            if not plugin.enable_auto_provisioning():
                logger.info(
                    'Auto provisioning\'s disabled. User %s wasn\'t created' %
                    self._userid)
                raise OIDCUserAutoProvisionError
            plugin.addUser(self._userid)
            member = self._mtool.getMemberById(self._userid)
        return member

    def _update_login_times_and_other_member_properties(self, member):
        default = DateTime('2000/01/01')
        login_time = member.getProperty('login_time', default)
        if login_time == default:
            self._first_login = True
            login_time = DateTime()
        member.setMemberProperties(dict(
            login_time=self._mtool.ZopeTime(),
            last_login_time=login_time,
            **self._properties
        ))

    def _setup_session(self):
        uf = api.portal.get_tool('acl_users')
        uf.updateCredentials(
            self._request, self._request.response, self._userid, '')

    def _fire_login_event(self, member):
        user = member.getUser()
        if self._first_login:
            event.notify(UserInitialLoginInEvent(user))
        else:
            event.notify(UserLoggedInEvent(user))

    def _expire_the_clipboard(self):
        if self._request.get('__cp', None) is not None:
            self._request.response.expireCookie('__cp', path='/')

    def _create_member_area(self):
        self._mtool.createMemberArea(member_id=self._userid)

    @staticmethod
    def _get_oidc_plugin():
        """Get the OIDC plugin.

        This method assumes there is only one OIDC plugin.
        """
        portal = api.portal.get()
        plugins = portal.acl_users.plugins
        authenticators = plugins.listPlugins(IChallengePlugin)
        oidc_plugin = None
        for _id, authenticator in authenticators:
            if authenticator.meta_type == "ftw.oidcauth plugin":
                oidc_plugin = authenticator

        return oidc_plugin
