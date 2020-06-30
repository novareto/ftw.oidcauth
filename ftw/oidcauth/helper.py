from plone import api
from six.moves.urllib.parse import quote
from six.moves.urllib.parse import urljoin


def get_oidc_request_url(quote_=False):
    portal = api.portal.get()
    base_path = portal.absolute_url()
    if not base_path.endswith('/'):
        base_path = base_path + '/'
    url = urljoin(base_path, 'oidc/callback')
    if quote_:
        return quote(url)
    else:
        return url
