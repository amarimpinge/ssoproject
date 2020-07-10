from django.conf import settings
from rest_framework import exceptions
import jwt
from sso.models import User

import logging
logging.basicConfig(filename='debug.txt')
logger = logging.getLogger(__name__)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def user_authenticate_credentials(token):
    """
    Try to authenticate the given credentials. If authentication is
    successful, return the user and token. If not, throw an error.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY)
    except:
        msg = 'Invalid authentication. Could not decode token.'
        raise exceptions.AuthenticationFailed(msg)

    try:
        user = User.objects.get(pk=payload['id'])
    except User.DoesNotExist:
        msg = 'No user matching this token was found.'
        raise exceptions.AuthenticationFailed(msg)

    if not user.is_active:
        msg = 'This user has been deactivated.'
        raise exceptions.AuthenticationFailed(msg)

    return payload['id']


def user_authenticate_credentials_email(token):
    """
    Try to authenticate the given credentials. If authentication is
    successful, return the user and token. If not, throw an error.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY)
    except:
        msg = 'Invalid authentication. Could not decode token.'
        raise exceptions.AuthenticationFailed(msg)

    try:
        user = User.objects.get(pk=payload['id'])
    except User.DoesNotExist:
        msg = 'No user matching this token was found.'
        raise exceptions.AuthenticationFailed(msg)

    if not user.is_active:
        msg = 'This user has been deactivated.'
        raise exceptions.AuthenticationFailed(msg)

    return payload['email']