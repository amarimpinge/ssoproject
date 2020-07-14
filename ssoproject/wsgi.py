"""
WSGI config for ssoproject project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/2.0/howto/deployment/wsgi/
"""

import os
from django.conf.settings import BASE_DIR
from django.core.wsgi import get_wsgi_application
from whitenoise.django import DjangoWhiteNoise
from whitenoise import WhiteNoise
application = WhiteNoise(application, root=BASE_DIR +'/static')
application.add_files(BASE_DIR +'/static', prefix='more-files/')



os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ssoproject.settings")
application = get_wsgi_application()
application = DjangoWhiteNoise(application)