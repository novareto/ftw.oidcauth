from Products.CMFCore.utils import getToolByName
from Products.PlonePAS.plugins.ufactory import PloneUser
from ftw.oidcauth.browser.oidc_tools import OIDCUserHandler
from ftw.oidcauth.testing import FTW_OIDCAUTH_INTEGRATION_TESTING
from plone.app.testing import TEST_USER_ID
import unittest


class TestOIDCUserHandler(unittest.TestCase):

    layer = FTW_OIDCAUTH_INTEGRATION_TESTING

    def setUp(self):
        self.plugin = self.layer['plugin']
        self.request = self.layer['request']
        self.portal = self.layer['portal']

    def test_user_handler_api_creating_a_new_user(self):
        props = {'fullname': 'James Bond',
                 'email': 'james@007.com',
                 'userid': u'j\xe4ims007'}
        user_handler = OIDCUserHandler(self.request, props)
        self.assertFalse(user_handler.is_user_logged_in)
        user_handler.login_user()
        self.assertTrue(user_handler.is_user_logged_in)

        # check if user has been created
        acl_users = getToolByName(self.portal, 'acl_users')
        user = acl_users.getUserById(u'j\xe4ims007')
        self.assertIsInstance(user, PloneUser)

        # check if property was applied
        self.assertEqual(user.getProperty('fullname'), 'James Bond')

    def test_user_handler_api_with_existing_user(self):
        props = {'fullname': 'Existing User',
                 'email': 'james@existing.com',
                 'userid': TEST_USER_ID}
        user_handler = OIDCUserHandler(self.request, props)
        self.assertFalse(user_handler.is_user_logged_in)
        user_handler.login_user()
        self.assertTrue(user_handler.is_user_logged_in)

        # check if user has been created
        acl_users = getToolByName(self.portal, 'acl_users')
        user = acl_users.getUserById(TEST_USER_ID)
        self.assertIsInstance(user, PloneUser)

        # check if property was applied
        self.assertEqual(user.getProperty('fullname'), 'Existing User')

    def test_properties_set_according_to_plugin_mapping(self):
        props = {'fullname': 'James Bond',
                 'email': 'james@007.com',
                 'userid': TEST_USER_ID}
        user_handler = OIDCUserHandler(self.request, props)
        user_handler.login_user()
        acl_users = getToolByName(self.portal, 'acl_users')
        user = acl_users.getUserById(TEST_USER_ID)

        # check if property was applied
        self.assertEqual(user.getProperty('fullname'), 'James Bond')
        self.assertEqual(user.getProperty('email'), 'james@007.com')
