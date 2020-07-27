from DateTime import DateTime
from Products.PlonePAS.events import UserInitialLoginInEvent
from Products.PlonePAS.events import UserLoggedInEvent
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from base64 import b64encode
from ftw.oidcauth.errors import OIDCAlgorithmError
from ftw.oidcauth.errors import OIDCJwkEndpointError
from ftw.oidcauth.errors import OIDCPluginNotFoundError
from ftw.oidcauth.errors import OIDCSubMismatchError
from ftw.oidcauth.errors import OIDCTokenError
from ftw.oidcauth.errors import OIDCUserAutoProvisionError
from ftw.oidcauth.errors import OIDCUserIDPropertyError
from ftw.oidcauth.errors import OIDCUserInfoError
from ftw.oidcauth.helper import get_oidc_request_url
from jwt.exceptions import DecodeError
from jwt.exceptions import InvalidTokenError
from plone import api
from plone.dexterity.utils import safe_unicode
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
        self.oidc_plugin = self.get_oidc_plugin()

    def authorize(self):
        user_info = self.authorize_user()
        props = self.map_properties(user_info)
        oidc_user_handler = OIDCUserHandler(self.request, props)
        oidc_user_handler.login_user()
        if oidc_user_handler.is_user_logged_in:
            self.has_been_authorized = True

    def get_redirect(self):
        return self.request.cookies.get('oidc_next')

    def map_properties(self, user_info):
        props_mapping = self.oidc_plugin.properties_mapping
        props = {key: user_info.get(value)
                 for (key, value) in props_mapping.items()}
        if not props.get('userid') or not user_info.get(props_mapping.get('userid')):
            logger.info('The userid property is not set correctly.')
            raise OIDCUserIDPropertyError
        return props

    def authorize_user(self):
        """OIDC main authorization code flow:

        1: Get authorization token to authorize on the client side using the
           authorization code received in response to the user authentication
           by the OIDC issuer.
        2: Obtain and validate the token for the user.
        3: Get the user info.
        4: Validate the sub from the validated token/user_info are a match.
        """
        client_auth_token = self.authorize_client()
        token = self.obtain_validated_token(client_auth_token)
        user_info = self.get_user_info(client_auth_token.get('access_token'))
        self.validate_sub_matching(token, user_info)

        return user_info

    def authorize_client(self):
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
                self.oidc_plugin.client_id,
                self.oidc_plugin.client_secret)).encode('utf-8')).decode('utf-8')
        headers = {'Authorization': authstr}
        data = {
            'grant_type': 'authorization_code',
            'code': self.code,
            'redirect_uri': get_oidc_request_url(),
        }

        response = requests.post(
            self.oidc_plugin.token_endpoint,
            data=data,
            headers=headers)

        if response.status_code != 200:
            logger.warning(
                'An error occurred trying to authorize %s', self.code)
            raise OIDCTokenError
        else:
            return response.json()

    def get_algorithm_and_extract_id_token(self, plugin, token_data):
        try:
            id_token = token_data['id_token']
            alg = jwt.get_unverified_header(id_token)['alg']
        except (DecodeError, KeyError):
            raise OIDCAlgorithmError
        if not alg:
            raise OIDCAlgorithmError
        if plugin.sign_algorithm != alg or alg not in ['HS256', 'RS256']:
            raise OIDCAlgorithmError
        return alg, id_token

    def decode_hs256(self, plugin, id_token):
        try:
            return jwt.decode(
                id_token, plugin.client_secret, algorithms=['HS256'],
                audience=self.oidc_plugin.client_id)
        except InvalidTokenError:
            logger.warning('An error occurred trying to decode %s', id_token)
            raise OIDCTokenError

    def decode_rs256(self, plugin, id_token):
        response = requests.get(self.oidc_plugin.jwks_endpoint)
        if response.status_code != 200:
            logger.info('An error occurred obtaining jwks')
            raise OIDCJwkEndpointError
        jwks = response.json().get('keys')
        public_key = self.extract_token_key(jwks, id_token)
        try:
            return jwt.decode(
                id_token, key=public_key, algorithms=['RS256'],
                audience=self.oidc_plugin.client_id)
        except InvalidTokenError:
            logger.warning('An error occurred trying to decode %s', id_token)
            raise OIDCTokenError

    def obtain_validated_token(self, token_data):
        """Obtain validated jwk.
        """
        plugin = self.get_oidc_plugin()
        alg, id_token = self.get_algorithm_and_extract_id_token(
            plugin, token_data)

        if alg == 'HS256':
            return self.decode_hs256(plugin, id_token)
        else:
            return self.decode_rs256(plugin, id_token)

    def get_user_info(self, access_token):
        bearerstr = 'Bearer {}'.format(access_token)
        headers = {'Authorization': bearerstr}
        response = requests.get(
            self.oidc_plugin.user_endpoint, headers=headers)
        if response.status_code != 200:
            logger.warning(
                'An error occurred getting user info for %s.', access_token)
            raise OIDCUserInfoError
        return response.json()

    @staticmethod
    def get_oidc_plugin():
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

    @staticmethod
    def validate_sub_matching(token, user_info):
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
    def extract_token_key(jwks, id_token):
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
        self.userid = safe_unicode(self.properties.get('userid'))
        self.request = request
        self.first_login = False
        self.mtool = api.portal.get_tool('portal_membership')

    def login_user(self):
        member = self.get_member()
        self.setup_session()
        self.update_login_times_and_other_member_properties(member)
        self.fire_login_event(member)
        self.expire_the_clipboard()
        self.create_member_area()
        self.is_user_logged_in = True

    def get_member(self):
        member = self.mtool.getMemberById(self.userid)
        if member is None:
            plugin = self.get_oidc_plugin()
            if plugin is None:
                logger.warning(
                    'Missing OIDC PAS plugin. Cannot autoprovision user %s.' %
                    self.userid)
                raise OIDCPluginNotFoundError
            if not plugin.auto_provisioning_enabled():
                logger.info(
                    'Auto provisioning\'s disabled. User %s wasn\'t created' %
                    self.userid)
                raise OIDCUserAutoProvisionError
            plugin.addUser(self.userid)
            member = self.mtool.getMemberById(self.userid)
        return member

    def update_login_times_and_other_member_properties(self, member):
        default = DateTime('2000/01/01')
        login_time = member.getProperty('login_time', default)
        if login_time == default:
            self.first_login = True
            login_time = DateTime()
        member.setMemberProperties(dict(
            login_time=self.mtool.ZopeTime(),
            last_login_time=login_time,
            **self.properties
        ))

    def setup_session(self):
        uf = api.portal.get_tool('acl_users')
        uf.updateCredentials(
            self.request, self.request.response, self.userid, '')

    def fire_login_event(self, member):
        user = member.getUser()
        if self.first_login:
            event.notify(UserInitialLoginInEvent(user))
        else:
            event.notify(UserLoggedInEvent(user))

    def expire_the_clipboard(self):
        if self.request.get('__cp', None) is not None:
            self.request.response.expireCookie('__cp', path='/')

    def create_member_area(self):
        self.mtool.createMemberArea(member_id=self.userid)

    @staticmethod
    def get_oidc_plugin():
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
