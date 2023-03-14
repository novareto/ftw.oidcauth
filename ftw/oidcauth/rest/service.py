import json
from plone import api
from plone.rest import Service
from zope.interface import implementer
from zope.publisher.interfaces import IPublishTraverse


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
        print self.params
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
        return json.dumps(ret)
