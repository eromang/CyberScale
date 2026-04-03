"""WSGI config for CyberScale web playground."""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cyberscale_web.settings")

application = get_wsgi_application()
