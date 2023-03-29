import json
import base64
from binascii import b2a_base64, a2b_base64
from AccessControl import AuthEncoding
from plone import api
from plone.rest import Service
from zope.interface import implementer
from zope.publisher.interfaces import IPublishTraverse
from Products.CMFCore.utils import getToolByName


class User(dict):
    pass


@implementer(IPublishTraverse)
class KeyCloakService(Service):

    def __init__(self, context, request):
        super(KeyCloakService, self).__init__(context, request)
        self.params = []

    def publishTraverse(self, request, name):
        self.params.append(name)
        return self

    def render(self):
        print('users')
        import pdb;pdb.set_trace()
        print(self.params)
        AuthEncoding.pw_encrypt('danny')
        api.user.create(email="ck@nn.de", username="cklinger", password="passwort")
        if len(self.params) == 0:
            ret = []
            for user in api.user.get_users():
                ret.append(
                    User(
                        id=user.id,
                        email=user.getProperty('email'),
                        fristName='fN', #user.getProperty('firstName'),
                        lastName='lN', #user.getProperty('lastName')
                    )
                )
            #ret = [User(id="cklinger", email="ck@nova.de", dddfirstName="Christian", lastName="Klinger"),]
        elif len(self.params) == 1:
            if self.params[0] == "count":
                ret = {'count': len(api.user.get_users())}
            else:
                user = api.user.get(username=self.params[0])
                ret = User(
                        id=user.id,
                        email=user.getProperty('email'),
                        fristName='fN', #user.getProperty('firstName'),
                        lastName='lN', #user.getProperty('lastName')
                    )
        print(ret)
        return json.dumps(ret)


class PWResult(dict):
    pass


@implementer(IPublishTraverse)
class KeyCloakCredentials(Service):

    def __init__(self, context, request):
        super(KeyCloakCredentials, self).__init__(context, request)
        self.params = []

    def publishTraverse(self, request, name):
        self.params.append(name)
        return self

    def render(self):
        print('credentials')
        if not self.params:
            self.request.response.setStatus(400)
            print('No userid in request')
            return
        uid = self.params[0]
        if not api.user.get(uid):
            print('Submitted credential could not have been verified with given userId.')
            self.request.response.setStatus(400)
            return
        uf = getToolByName(self, 'acl_users')
        body = self.request.get('BODY')
        decoded_body = body.decode('utf-8')
        pw = json.loads(decoded_body).get('value')
        if uf.authenticate(uid, pw, self.request):
            self.request.response.setStatus(204)
            response = self.request.response
            response.setBody(uid)
            return 
        print('#/components/responses/UnauthorizedError')    
        self.request.response.setStatus(401)
        return

@implementer(IPublishTraverse)
class KeyCloakUpdateCredentials(Service):

    def __init__(self, context, request):
        super(KeyCloakUpdateCredentials, self).__init__(context, request)
        self.params = []

    def publishTraverse(self, request, name):
        self.params.append(name)
        return self

    def render(self):
        print('update_credentials')
        if not self.params:
            self.request.response.setStatus(400)
            print('No UserID in request')
            return
        uid = self.params[0]
        if not api.user.get(uid):
            print('Credential model update failed')
            self.request.response.setStatus(400)
            return
        pm = getToolByName(self, 'portal_membership')
        member = pm.getMemberById(uid)
        body = self.request.get('BODY')
        decoded_body = body.decode('utf-8')
        pw = json.loads(decoded_body).get('value')
        try:
            member.setSecurityProfile(password=pw)
            self.request.response.setStatus(204)
            response = self.request.response
            response.setBody(uid)
            return
        except:
            print('Authentication information is missing or invalid')
            self.request.response.setStatus(401)
            return
