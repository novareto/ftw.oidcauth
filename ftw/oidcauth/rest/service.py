import json
import base64
from binascii import b2a_base64, a2b_base64
from AccessControl import AuthEncoding
from plone import api
from plone.rest import Service
from zope.interface import implementer
from zope.publisher.interfaces import IPublishTraverse
from Products.CMFCore.utils import getToolByName

def createUser(uid, pw, email="john.doe@dummy.de", fullname="John Doe"):
    props = {'fullname':fullname}
    user = api.user.create(email=email, username=uid, password=pw, properties=props)
    return user

def createUserDict(member):
    entry = {}
    entry['id'] = member.id
    entry['email'] = member.getProperty('email')
    fullname = member.getProperty('fullname')
    entry['firstName'] = ''
    entry['lastName'] = ''
    if fullname:
        parts = fullname.split(' ')
        entry['lastName'] = parts[-1]
        entry['firstName'] = ' '.join(parts[:-1])
    entry['attributes'] = {}
    entry['groups'] = ['Member']
    return entry


@implementer(IPublishTraverse)
class KeyCloakUsers(Service):
    """ endpoint: /users GET Services """

    def __init__(self, context, request):
        super(KeyCloakUsers, self).__init__(context, request)
        self.params = []

    def publishTraverse(self, request, name):
        self.params.append(name)
        return self

    def render(self):
        if not self.params:
            retlist = []
            memberlist = api.user.get_users()
            for i in memberlist:
                retlist.append(createUserDict(i))
            return json.dumps(retlist)
        elif 'count' in self.params:
            retobj = {'count':0}
            memberlist = api.user.get_users()
            retobj['count'] = len(memberlist)
            return json.dumps(retobj)
        elif 'email' in self.params:
            memberdict = {}
            email = self.params[-1]
            memberlist = api.user.get_users()
            for i in memberlist:
                if email == i.getProperty('email'):
                    return json.dumps(createUserDict(i))
            self.request.response.setStatus(401)
            return json.dumps(memberdict)
        else:
            memberdict = {}
            uid = self.params[0]
            member = api.user.get(userid = uid)
            if member:
                return json.dumps(createUserDict(member))
            self.request.response.setStatus(401)
            return json.dumps(memberdict)

@implementer(IPublishTraverse)
class KeyCloakCreateUser(Service):
    """ endpoint: /users POST Service """

    def __init__(self, context, request):
        super(KeyCloakCreateUser, self).__init__(context, request)
        self.params = []

    def publishTraverse(self, request, name):
        self.params.append(name)
        return self

    def render(self):
        print('createuser')
        body = self.request.get('BODY')
        decoded_body = body.decode('utf-8')
        userdict = json.loads(decoded_body)
        uid = userdict.get('id')
        pw="e$7UwQ5xO*5p" #Initialpassword für neue Benutzer
        email = userdict.get('email')
        fullname = ''
        if userdict.get('firstName') and userdict.get('lastName'):
            fullname = f"{userdict.get('firstName')} {userdict.get('lastName')}"
        if not api.user.get(uid):
            user = createUser(uid, pw, email, fullname)
            if user:
                print("New User created")
                self.request.response.setStatus(204)
            else:
                print("Error while user creation")
                self.request.response.setStatus(401)
            return
        print('Error while user already exists')    
        self.request.response.setStatus(401)
        return

@implementer(IPublishTraverse)
class KeyCloakUpdateUser(Service):
    """ endpoint: /users PUT Service """

    def __init__(self, context, request):
        super(KeyCloakUpdateUser, self).__init__(context, request)
        self.params = []

    def publishTraverse(self, request, name):
        self.params.append(name)
        return self

    def render(self):
        print('updateuser')
        body = self.request.get('BODY')
        decoded_body = body.decode('utf-8')
        userdict = json.loads(decoded_body)
        uid = userdict.get('id')
        if self.params[0] != uid:
            print("User-Ids in request and body are not the same")
            self.request.response.setStatus(401)
            return
        email = userdict.get('email')
        fullname = f"{userdict.get('firstName')} {userdict.get('lastName')}"
        pm = getToolByName(self, 'portal_membership')
        member = pm.getMemberById(uid)
        if not member:
            print("Member doesn't exist")
            self.request.response.setStatus(401)
            return
        mapping = {'email':email, 'fullname':fullname}
        try:
            member.setMemberProperties(mapping=mapping)
            self.request.response.setStatus(204)
        except:
            print("Error while user update")
            self.request.response.setStatus(401)
        return


@implementer(IPublishTraverse)
class KeyCloakDeleteUser(Service):
    """ endpoint: /users DELETE Service """

    def __init__(self, context, request):
        super(KeyCloakDeleteUser, self).__init__(context, request)
        self.params = []

    def publishTraverse(self, request, name):
        self.params.append(name)
        return self

    def render(self):
        print('deleteuser')
        if not self.params:
            print('No param in request')
            self.request.response.setStatus(401)
            return
        uid = self.params[0]
        user = api.user.get(username = uid)
        if not user:
            print("User not found")
            self.request.response.setStatus(404)
            return
        try:
            api.user.delete(username = uid)
            print("User successfully deleted")
            self.request.response.setStatus(404)
            return
        except:
            print("Error while delete user")
            self.request.response.setStatus(401)
            return
        

@implementer(IPublishTraverse)
class KeyCloakCredentials(Service):
    """ endpoint: /credentials POST Service """

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
    """ endpoint: /credentials PUT Service """

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
        body = self.request.get('BODY')
        decoded_body = body.decode('utf-8')
        pw = json.loads(decoded_body).get('value')
        if not api.user.get(uid):
            member = createUser(uid, pw)
            print('New User created')
            self.request.response.setStatus(204)
            return
        pm = getToolByName(self, 'portal_membership')
        member = pm.getMemberById(uid)
        try:
            member.setSecurityProfile(password=pw)
            print('Update Password successful')
        except:
            print('Authentication information is missing or invalid')
            self.request.response.setStatus(401)
            return
        self.request.response.setStatus(204)
        response = self.request.response
        response.setBody(uid)
        return
