from Products.Five import BrowserView
from ftw.oidcauth.browser.oidc_tools import OIDCClientAuthentication
from ftw.oidcauth.errors import OIDCBaseError
from zExceptions import NotFound as zNotFound
from zope.interface import implements
from zope.publisher.interfaces import IPublishTraverse
from zope.publisher.interfaces import NotFound
import logging

logger = logging.getLogger('ftw.oidc')


class OIDCView(BrowserView):
    """Endpoints for OIDC"""

    implements(IPublishTraverse)

    def __init__(self, context, request):
        super(OIDCView, self).__init__(context, request)
        self.method = None

    def publishTraverse(self, request, name):
        if self.method is None:
            if name == 'callback':
                self.method = name
            else:
                raise NotFound(self, name, request)
        else:
            raise NotFound(self, name, request)
        return self

    def __call__(self):
        if self.method == 'callback':
            self.callback()
        else:
            raise zNotFound()

    def callback(self):
        code = self.request.form.get('code')
        state = self.request.form.get('state')
        client_auth = OIDCClientAuthentication(
            self.request, code, state)
        try:
            client_auth.authorize()
        except OIDCBaseError as ex:
            self.set_error_response(ex.status_code, ex.message)
            return

        if client_auth.has_been_authorized:
            self.request.response.redirect(client_auth.get_redirect())
            return
        else:
            self.set_error_response(400, 'Invalid Request')
            return

    def set_error_response(self, status, message):
        response = self.request.response
        response.setHeader('Content-Type', 'text/plain')
        response.setStatus(status, lock=1)
        response.setBody(message, lock=1)
