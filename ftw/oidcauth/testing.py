from plone.app.testing import PloneSandboxLayer
from plone.app.testing import PLONE_FIXTURE
from plone.app.testing import IntegrationTesting, FunctionalTesting
from plone.app.testing import applyProfile
from plone.testing import z2
from zope.configuration import xmlconfig
from ftw.oidcauth.plugin import OIDCPlugin


class FtwOIDCauthLayer(PloneSandboxLayer):

    defaultBases = (PLONE_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        # Load ZCML
        import plone.restapi
        xmlconfig.file('configure.zcml',
                       plone.restapi,
                       context=configurationContext)
        import ftw.oidcauth
        xmlconfig.file('configure.zcml',
                       ftw.oidcauth,
                       context=configurationContext)
        z2.installProduct(app, 'plone.restapi')
        z2.installProduct(app, 'ftw.oidcauth')

    def setUpPloneSite(self, portal):
        # Setup PAS plugin
        uf = portal.acl_users
        plugin = OIDCPlugin('oidc')
        plugin_props = [
            ('_client_id', u'42'),
            ('_client_secret', u'42'),
            ('_scope', u'openid email profile'),
            ('_sign_algorithm', u'RS256'),
            ('_authentication_endpoint', u'https://auth.ch/openid/authorize'),
            ('_token_endpoint', u'https://auth.ch/openid/token'),
            ('_user_endpoint', u'https://auth.ch/openid/userinfo'),
            ('_jwks_endpoint', u'https://auth.ch/openid/jwks'),
            ('_enable_auto_provisioning', u'true'),
            ('_properties_mapping',
             u'{"fullname": "Existing User", "email": "i@existed.com"}'),
        ]
        for x, y in plugin_props:
            plugin._setPropValue(x, y)
        uf._setObject(plugin.getId(), plugin)
        plugin = uf['oidc']
        plugin.manage_activateInterfaces([
            'IRolesPlugin',
            'IUserEnumerationPlugin',
            'IChallengePlugin',
        ])
        self['plugin'] = plugin
        applyProfile(portal, 'plone.restapi:default')


FTW_OIDCAUTH_FIXTURE = FtwOIDCauthLayer()
FTW_OIDCAUTH_INTEGRATION_TESTING = IntegrationTesting(
    bases=(FTW_OIDCAUTH_FIXTURE,), name="ftw.oidcauth:Integration")
FTW_OIDCAUTH_FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(FTW_OIDCAUTH_FIXTURE,), name="ftw.oidcauth:Functional")
