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
        print(self.params)
        uf = getToolByName(self, 'acl_users')
        username = self.params[0]
        user = api.user.get(username=username)
        pw = uf.source_users._user_passwords.get(username, '')
        pw_b64 = a2b_base64(pw[6:])
        salt = pw_b64[20:]  #.decode('utf-8')
        salt = base64.b64encode(salt).decode('utf-8')
        value = pw_b64[:20]
        value = base64.b64encode(value).decode('utf-8')

        ret = PWResult(
            value=value,
            salt=salt,
            iterations=0,
            algorithm= "SSHA",
            type= "password"
        )
        print(ret)
        return json.dumps(ret)
