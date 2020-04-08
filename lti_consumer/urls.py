"""
URL mappings for edX Proctoring Server.
"""

from __future__ import absolute_import

from django.conf import settings
from django.conf.urls import url

from .views import (
    public_keyset_endpoint,
    launch_gate_endpoint,
)


urlpatterns = [
    url(
        'lti_consumer/v1/public_keysets/{}$'.format(settings.USAGE_ID_PATTERN),
        public_keyset_endpoint,
        name='lti_consumer.public_keyset_endpoint'
    ),
    url(
        'lti_consumer/v1/launch/(?:/(?P<suffix>.*))?$',
        launch_gate_endpoint,
        name='lti_consumer.launch_gate'
    )
]
