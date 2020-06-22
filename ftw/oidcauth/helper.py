from plone import api
import sys
import urllib


if sys.version_info.major == 2:
    import urlparse
    urljoin = urlparse.urljoin
else:
    urljoin = urllib.parse.urljoin

if sys.version_info.major == 2:
    url_quote = urllib.quote
else:
    url_quote = urllib.parse.quote


def get_oidc_request_uri(do_url_quote=False):
    portal = api.portal.get()
    base_path = portal.absolute_url()
    if not base_path.endswith('/'):
        base_path = base_path + '/'
    url = urljoin(base_path, 'oidc/callback')
    if do_url_quote:
        return url_quote(url)
    else:
        return url
