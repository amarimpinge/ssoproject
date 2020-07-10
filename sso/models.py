from django.db.models import *
from django.contrib.auth.models import AbstractUser
from django.utils.translation import ugettext_lazy as _
from django.conf import settings
import uuid

class User(AbstractUser):
    id                  = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username            = CharField(blank=True, null=True, max_length=10)
    email               = EmailField(_('email address'), unique=True)
    phone               = CharField(blank=True, null=True, max_length=30, unique=True)
    jwt_secret          = UUIDField(default=uuid.uuid4, editable=False)
    is_two_step_active  = BooleanField(_("two_step"), default = False)
    isDeleted           = BooleanField(default=False)
    USERNAME_FIELD      = 'email'
    REQUIRED_FIELDS     = ['username']

    def __str__(self):
        return "{}".format(self.email)




