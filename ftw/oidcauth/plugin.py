from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.requestmethod import postonly
from App.class_init import default__class_init__ as InitializeClass
from BTrees.OIBTree import OITreeSet
from OFS.Cache import Cacheable
from Products.CMFCore.permissions import ManagePortal
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.interfaces.plugins import (
    IRolesPlugin,
    IUserEnumerationPlugin
)
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from Products.PluggableAuthService.permissions import ManageUsers
from Products.PluggableAuthService.utils import csrf_only
from ftw.oidcauth.helper import get_oidc_request_url
from zope.interface import implements
import ast
import json
import logging

logger = logging.getLogger('ftw.oidcauth')


manage_addOIDCPlugin = PageTemplateFile(
    "www/addPlugin",
    globals(),
    __name__="manage_addOIDCPlugin",
)


def addOIDCPlugin(self, id_, title='', REQUEST=None):
    """Add a OIDC Web SSO plugin to a Pluggable Authentication Service.
    """
    p = OIDCPlugin(id_, title)
    self._setObject(p.getId(), p)

    if REQUEST is not None:
        REQUEST["RESPONSE"].redirect(
            "%s/manage_workspace?manage_tabs_message=OIDC+Web+SSO+plugin+"
            "added." % self.absolute_url())


class OIDCPlugin(BasePlugin):
    """OIDC authentication plugin.
    """
    implements(
        IRolesPlugin,
        IUserEnumerationPlugin,
        IChallengePlugin
    )

    meta_type = "ftw.oidcauth plugin"
    security = ClassSecurityInfo()

    # ZMI tab for configuration page
    manage_options = (
        ({'label': 'Configuration',
          'action': 'manage_config'},
         {'label': 'Users',
          'action': 'manage_users'},
         ) + BasePlugin.manage_options + Cacheable.manage_options
    )

    security.declareProtected(ManagePortal, 'manage_config')
    manage_config = PageTemplateFile('www/config', globals(),
                                     __name__='manage_config')

    security.declareProtected(ManageUsers, 'manage_users')
    manage_users = PageTemplateFile('www/manage_users', globals(),
                                    __name__='manage_users')

    def __init__(self, id, title=None):
        self._setId(id)

        self.title = title
        self._roles = ()
        self.client_id = None
        self.client_secret = None
        self.scope = u'openid email profile'
        self.sign_algorithm = u'RS256'
        self.username_attribute = u'sub'
        self.authentication_endpoint = None
        self.token_endpoint = None
        self.user_endpoint = None
        self.jwks_endpoint = None
        self._auto_provisioning_enabled = True
        self.properties_mapping = json.dumps({
            "userid": "sub",
            "fullname": "name",
            "email": "email"
            })
        self.logins = OITreeSet()

    security.declarePrivate('challenge')

    # Initiate a challenge to the user to provide credentials.
    def challenge(self, request, response, **kw):
        request.response.setCookie('oidc_next', request['ACTUAL_URL'])
        uri = '{}?response_type=code&scope={}&client_id={}&redirect_uri={}'.format(
            self.authentication_endpoint,
            self.scope,
            self.client_id,
            get_oidc_request_url(quote_=True))
        response.redirect(uri, lock=True, status=302)
        return True

    def addUser(self, userid):
        if userid in self.logins:
            return

        self.logins.insert(userid)

    def removeUser(self, userid):
        if userid not in self.logins:
            return

        self.logins.remove(userid)

    def listUserInfo(self):
        """ -> ( {}, ...{} )

        o Return one mapping per user, with the following keys:

          - 'user_id'
          - 'login_name'
        """
        return [{'user_id': x, 'login_name': x} for x in self.logins]

    security.declareProtected(ManageUsers, 'manage_addUser')

    @csrf_only
    @postonly
    def manage_addUser(self, user_id,
                       RESPONSE=None,
                       REQUEST=None):
        """ Add a user via the ZMI.
        """
        self.addUser(user_id)

        message = 'User+added'

        if RESPONSE is not None:
            RESPONSE.redirect('{}/manage_users?manage_tabs_message={}'.format(
                            self.absolute_url(), message))

    security.declareProtected(ManageUsers, 'manage_removeUsers')

    @csrf_only
    @postonly
    def manage_removeUsers(self, user_ids,
                           RESPONSE=None,
                           REQUEST=None):
        """ Remove one or more users via the ZMI.
        """
        user_ids = filter(None, user_ids)

        if not user_ids:
            message = 'no+users+selected'

        else:
            for user_id in user_ids:
                self.removeUser(user_id)

            message = 'Users+removed'

        if RESPONSE is not None:
            RESPONSE.redirect('{}/manage_users?manage_tabs_message={}'.format(
                self.absolute_url(), message))

    # IUserEnumerationPlugin implementation
    def enumerateUsers(self, id=None, login=None, exact_match=False,
                       sort_by=None, max_results=None, **kw):

        key = id and id or login
        user_infos = []
        pluginid = self.getId()

        # We do not provide search for additional keywords
        if kw:
            return ()

        if not key:
            # Return all users
            for login in self.logins:
                user_infos.append({
                    "id": login,
                    "login": login,
                    "pluginid": pluginid,
                    })
        elif key in self.logins:
            # User does exists
            user_infos.append({
                "id": key,
                "login": key,
                "pluginid": pluginid,
                })
        else:
            # User does not exists
            return ()

        if max_results is not None and max_results >= 0:
            user_infos = user_infos[:max_results]

        return tuple(user_infos)

    # IRolesPlugin
    def getRolesForPrincipal(self, principal, request=None):
        # Return a list of roles for the given principal (a user or group).
        if principal.getId() in self.logins:
            return self._roles

        return ()

    security.declareProtected(ManagePortal, 'manage_updateConfig')

    @postonly
    def manage_updateConfig(self, REQUEST):
        """Update configuration of OIDC plugin.
        """
        response = REQUEST.response

        self.client_id = REQUEST.form.get('client-id')
        self.client_secret = REQUEST.form.get('client-secret')
        self.scope = REQUEST.form.get('scope')
        self.sign_algorithm = REQUEST.form.get('sign-algorithm')
        self.authentication_endpoint = REQUEST.form.get('authentication-endpoint')
        self.token_endpoint = REQUEST.form.get('token-endpoint')
        self.user_endpoint = REQUEST.form.get('user-endpoint')
        self.jwks_endpoint = REQUEST.form.get('jwks-endpoint')
        self._auto_provisioning_enabled = REQUEST.form.get('auto-provisioning-enabled')

        roles = REQUEST.form.get('roles')
        self._roles = tuple([role.strip() for role in roles.split(',') if role])

        # only update props if json is valid
        props = REQUEST.form.get('properties-mapping')
        props_data = self.get_valid_json(props)
        if not props_data:
            response.redirect('%s/manage_config?manage_tabs_message=%s' % (
                self.absolute_url(), 'Please make sure the json is valid!'))
            return
        self.properties_mapping = props_data

        response.redirect('%s/manage_config?manage_tabs_message=%s' %
                          (self.absolute_url(), 'Configuration+updated.'))

    def auto_provisioning_enabled(self):
        return True if self._auto_provisioning_enabled else False

    def roles(self):
        return ','.join(self._roles)

    @staticmethod
    def get_valid_json(props):
        try:
            data = ast.literal_eval(props)
        except ValueError as e:
            return False
        return data


InitializeClass(OIDCPlugin)
