from ftw.oidcauth.errors import OIDCBaseError
from ftw.oidcauth.errors import OIDCJwkEndpointError
from ftw.oidcauth.errors import OIDCPluginNotFoundError
from ftw.oidcauth.errors import OIDCSubMismatchError
from ftw.oidcauth.errors import OIDCTokenError
from ftw.oidcauth.errors import OIDCUserAutoProvisionError
from ftw.oidcauth.errors import OIDCUserIDPropertyError
from ftw.oidcauth.errors import OIDCUserInfoError
from unittest import TestCase


class TestErrorsInheritFromBase(TestCase):
    def test_errors_inherit_from_base(self):
        """It is important that all the errors raised inherit from the base
        error to make sure they are all catched by the call method.
        """
        self.assertIsInstance(OIDCTokenError(), OIDCBaseError)
        self.assertIsInstance(OIDCJwkEndpointError(), OIDCBaseError)
        self.assertIsInstance(OIDCUserInfoError(), OIDCBaseError)
        self.assertIsInstance(OIDCSubMismatchError(), OIDCBaseError)
        self.assertIsInstance(OIDCUserAutoProvisionError(), OIDCBaseError)
        self.assertIsInstance(OIDCPluginNotFoundError(), OIDCBaseError)
        self.assertIsInstance(OIDCUserIDPropertyError(), OIDCBaseError)
