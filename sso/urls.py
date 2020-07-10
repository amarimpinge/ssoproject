from django.urls import include, path
from rest_framework import routers
from sso import views
from django.conf import settings
from django.conf.urls.static import static
from sso.views import *

router = routers.DefaultRouter(trailing_slash=True)
router.register(r'users', UserViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('login', LoginView.as_view()),
    path('login_thinkific', ThinkificLoginView.as_view()),
    path('logout', LogoutView.as_view()),
    path('error', ErrorView.as_view()),

]

if settings.DEBUG:
  urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)