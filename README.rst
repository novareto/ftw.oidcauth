ftw.oidcauth
============

A PAS plugin for authentication of users in Plone using OIDC.

Installation
------------

Add the package to your instance eggs like:

.. code-block::

    [instance]
    eggs +=
        ...
        ftw.oidcauth


Introduction
------------

The OIDC Plone PAS plugin can be added in `acl_users/manage_main`. After adding
a new Plugin it will be listed there and can be configured in detail.

OIDC Authorization Flow
***********************

.. code-block::

    1: Unauthorized User --------redirect--------> Authorization Endpoint
    2: Callback View    <--------redirect--------  Authorization Endpoint
    3: OIDC Plugin      <-------client call------> Token Endpoint
    4: OIDC Plugin      <-------client call------> JWKS Endpoint
    5: Validation of Token using the matching JWK
    6: OIDC Plugin      <-------client call------> User Info Endpoint
    7: Provision user in Plone


Configuration
*************

Once a plugin was added it can be configured by clicking on the plugin in
``acl_users/manage_main``.

| **Configuration:** general configurations (oidc routes, secret...)
| **Users:** manage users within this PAS plugin
| **Activate:** select plugins implemented by the plugin

Don't forget to add the plugin as the first to be challenged:

  - go to route: ``http://localhost:8080/Plone/acl_users/plugins/manage_plugins``
  - go to ``Challenge Plugins``
  - activate your freshly added plugin and move to the top


``Properties Mapping`` holds the information how to map userinformation. It has to
be valid json like:

.. code-block:: json

    {
        "plone_property1": "oidc_property1",
        "plone_property2": "oidc_property2",
        ...
    }

The ``Properties Mapping`` must contain the Plone property ``userid``.


Links
-----

- Github: https://github.com/4teamwork/ftw.oidcauth
- Issues: https://github.com/4teamwork/ftw.oidcauth/issues


Copyright
---------

This package is copyright by `4teamwork <http://www.4teamwork.ch/>`_.

``ftw.oidcauth`` is licensed under GNU General Public License, version 2.
