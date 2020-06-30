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
        import ftw.oidcauth
        xmlconfig.file('configure.zcml',
                       ftw.oidcauth,
                       context=configurationContext)
        z2.installProduct(app, 'ftw.oidcauth')

    def setUpPloneSite(self, portal):
        # Setup PAS plugin
        uf = portal.acl_users
        plugin = OIDCPlugin('oidc')
        plugin_props = [
            ('client_id', u'42'),
            ('client_secret', u'42'),
            ('scope', u'openid email profile'),
            ('sign_algorithm', u'RS256'),
            ('authentication_endpoint', u'https://auth.ch/openid/authorize'),
            ('token_endpoint', u'https://auth.ch/openid/token'),
            ('user_endpoint', u'https://auth.ch/openid/userinfo'),
            ('jwks_endpoint', u'https://auth.ch/openid/jwks'),
            ('_auto_provisioning_enabled', u'true'),
            ('properties_mapping',
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


FTW_OIDCAUTH_FIXTURE = FtwOIDCauthLayer()
FTW_OIDCAUTH_INTEGRATION_TESTING = IntegrationTesting(
    bases=(FTW_OIDCAUTH_FIXTURE,), name="ftw.oidcauth:Integration")
FTW_OIDCAUTH_FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(FTW_OIDCAUTH_FIXTURE,), name="ftw.oidcauth:Functional")
