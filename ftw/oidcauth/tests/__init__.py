from ftw.oidcauth.testing import FTW_OIDCAUTH_INTEGRATION_TESTING
from unittest import TestCase


class IntegrationTestCase(TestCase):

    layer = FTW_OIDCAUTH_INTEGRATION_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        self.request = self.layer['request']
