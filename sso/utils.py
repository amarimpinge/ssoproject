from django.conf import settings
from datetime import datetime, timedelta
import jwt
import base64
import pyotp

import logging
logging.basicConfig(filename='debug.txt')
logger = logging.getLogger(__name__)


def without_otp_otc_permission_jwt(user, session_key):
    payload = {
        'id': str(user.id) or '',
        'email': user.email or '',
        'jwt_secret': str(user.jwt_secret) or '',
        'session_key': session_key,
    }
    jwt_token = jwt.encode(payload, settings.SECRET_KEY)
    logger.debug('[User logged In]' + str(jwt_token))
    return jwt_token


def permission_jwt(user, session_key):
    payload = {
        'id': str(user.id) or '',
        'email': user.email or '',
        'jwt_secret': str(user.jwt_secret) or '',
        'session_key': session_key,

    }
    jwt_token = jwt.encode(payload, settings.SECRET_KEY)
    logger.debug('[User logged In]' + str(jwt_token))
    return jwt_token

def thinkific_jwt(payload):
    jwt_token = jwt.encode(payload, settings.SECRET_KEY)
    print(">>>>>>>>>>.",jwt_token)
    logger.debug('[User logged In]' + str(jwt_token))
    return jwt_token

