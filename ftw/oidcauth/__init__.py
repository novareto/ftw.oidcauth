from AccessControl.Permissions import manage_users
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
from ftw.oidcauth import plugin


def initialize(context):
    """Initializer called when used as a Zope 2 product."""
    registerMultiPlugin(plugin.OIDCPlugin.meta_type)
    context.registerClass(
        plugin.OIDCPlugin,
        permission=manage_users,
        constructors=(plugin.manage_addOIDCPlugin,
                      plugin.addOIDCPlugin),
        visibility=None,
    )
