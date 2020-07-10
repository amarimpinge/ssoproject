from django.contrib.auth import login as django_login
from django.contrib.auth.models import Group, Permission
from django.contrib.sessions.models import Session
from django.core.mail import EmailMessage
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import login as django_login
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
from django.http import JsonResponse
from django.http import HttpResponseRedirect
from django.conf import settings
from rest_framework import viewsets
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.decorators import permission_classes
from rest_framework import permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK,
    HTTP_204_NO_CONTENT
)
import jwt
import uuid
import requests
from datetime import datetime, timedelta
# from user_agents import parse
# Also add these imports
from ssoproject.utils import get_client_ip
from sso.models import User
from sso.utils import without_otp_otc_permission_jwt, permission_jwt, thinkific_jwt
from sso.serializers import UserSerializer, UserSerializerList
from sso.permissions import IsLoggedInUserOrAdmin, IsAdminUser

import logging
logging.basicConfig(filename='debug.txt')
logger = logging.getLogger(__name__)


class UserViewSet(viewsets.ModelViewSet):
	queryset = User.objects.all()

	def get_serializer_class(self):
		if self.action == 'list':
			return UserSerializerList
		if self.action == 'retrieve':
			return UserSerializerList
		return UserSerializer

	def create(self, request, *args, **kwarg):
		res = {}
		serializer = self.get_serializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		serializer.save(password=make_password(request.data.get('password')))
		try:
		    user = User.objects.get(id = serializer.data.get('id'))
		except:
		    user = None
		if user:
			if user.is_superuser != True:
				django_login(request, user)
				jwt_token = permission_jwt(user, request.session.session_key)
				return Response({"token": jwt_token}, status=HTTP_200_OK)
			else:
				django_login(request, user)
				jwt_token = without_otp_otc_permission_jwt(user, request.session.session_key)
				return Response({"token": jwt_token}, status=HTTP_200_OK)
		else:
			return Response(status=HTTP_400_BAD_REQUEST)

	def get_permissions(self):
		permission_classes = []
		if self.action == 'create':
			permission_classes = [AllowAny]
		elif self.action == 'retrieve' or self.action == 'update' or self.action == 'partial_update':
			permission_classes = [IsLoggedInUserOrAdmin]
		elif self.action == 'list' or self.action == 'destroy':
			permission_classes = [IsAdminUser]
		return [permission() for permission in permission_classes]


@permission_classes((permissions.AllowAny,))
class LoginView(APIView):
	"""
	login view to login User
	"""

	def post(self, request):
		data = {}
		res = {}
		"""
		post method for class LoginView
		:param request:
		:return:
		"""
		if not request.data:
			res['status'] = "Please provide email/password"
			return Response(res, status=HTTP_400_BAD_REQUEST)
		email = request.data.get('email')
		password = request.data.get('password')
		if email and password:
			user = authenticate(email=email, password=password)
			if user:
				if user.is_active:
					data["user"] = user
				else:
					res['status'] = "User is deactivated."
					return Response(res, status=HTTP_400_BAD_REQUEST)
			else:
				res['status'] = "Unable to login with given credentials."
				return Response(res, status=HTTP_400_BAD_REQUEST)
		else:
			res['status'] = "Must provide username and password both."
			return Response(res, status=HTTP_400_BAD_REQUEST)

		if user.is_superuser != True:
			django_login(request, user)
			jwt_token = permission_jwt(user, request.session.session_key)
			return Response({"token": jwt_token, "thinkific_token":thinkific_token}, status=HTTP_200_OK)
		else:
			django_login(request, user)
			jwt_token = without_otp_otc_permission_jwt(user, request.session.session_key)
			return Response({"token": jwt_token, "thinkific_token":thinkific_token}, status=HTTP_200_OK)


class LogoutView(APIView):
	permission_classes = (IsAuthenticated,)

	def post(self, request):
		user = request.user
		user.jwt_secret = uuid.uuid4()
		user.save()
		logout(request)
		return Response(status=HTTP_200_OK)



@permission_classes((permissions.AllowAny,))
class ThinkificLoginView(APIView):
	"""
	login view to login ThinkificLogin User
	"""

	def post(self, request):
		data = {}
		res = {}
		"""
		post method for class LoginView
		:param request:
		:return:
		"""
		payload = {
				"first_name": "Thinkific",
				"last_name": "Admin",
				"email": "thinkific@thinkific.com",
				"iat": 1520875725,
				"external_id": "thinkific@thinkific.com",
				"bio": "Mostly harmless",
				"company": "Thinkific",
				"timezone": "America/Los_Angeles",
			}
		
		if not request.data:
			res['status'] = "Please provide payload as data "
			return Response(res, status=HTTP_400_BAD_REQUEST)
		payload = request.data.get('payload')
		if payload:
			try:
				thinkific_token = thinkific_jwt(payload)
				if thinkific_token:
					return_url = "https://www.thinkific.com/"
					error_url = "http://127.0.0.1:8000/api/v1/error"
					base_url = "https://{your-school}.thinkific.com/api/sso/v2/sso/jwt?jwt={%s}" % thinkific_token
					return_to = "&return_to={%s}" % return_url
					error_to = "&error_url={%s}" % error_url
					url = base_url+return_to+error_to
					# return HttpResponseRedirect(redirect_to=url)
					return Response({ "thinkific_token":thinkific_token}, status=HTTP_200_OK)
				else:
					res['status'] = "Some Error is occur to created thinkific_token"
					return Response(res, status=HTTP_400_BAD_REQUEST)
			except:
				res['status'] = "Some Error is occur to created thinkific_token"
				return Response(res, status=HTTP_400_BAD_REQUEST)
		else:
			res['status'] = "Please provide payload "
			return Response(res, status=HTTP_400_BAD_REQUEST)


@permission_classes((permissions.AllowAny,))
class ErrorView(APIView):

	def get(self, request):
		error = "some error occur to login"
		return JsonResponse({'error': error}, status=401)
