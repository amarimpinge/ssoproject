from rest_framework import serializers
from sso.models import User


class UserSerializerList(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = User
        fields = ( 'url', 'id', 'username','email')


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id','username', 'email', 'phone', 'is_active', 'password')

