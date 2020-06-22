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
        self._method = None

    def publishTraverse(self, request, name):
        if self._method is None:
            if name == 'callback':
                self._method = name
            else:
                raise NotFound(self, name, request)
        else:
            raise NotFound(self, name, request)
        return self

    def __call__(self):
        if self._method == 'callback':
            self._callback()
        else:
            raise zNotFound()

    def _callback(self):
        code = self.request.form.get('code')
        state = self.request.form.get('state')
        client_auth = OIDCClientAuthentication(
            self.request, code, state)
        try:
            client_auth.authorize()
        except OIDCBaseError as ex:
            self._set_error_response(ex.status_code, ex.message)
            return

        if client_auth.has_been_authorized:
            client_auth.set_redirect()
            return
        else:
            self._set_error_response(400, 'Invalid Request')
            return

    def _set_error_response(self, status, message):
        response = self.request.response
        response.setHeader('Content-Type', 'text/plain')
        response.setStatus(status, lock=1)
        response.setBody(message, lock=1)
