import secrets
from datetime import datetime

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class OpenAPIAuth(models.Model):
    name = models.CharField(_("name"), max_length=100)
    desc = models.CharField(_("description"), max_length=255, blank=True, default="")
    enable = models.BooleanField(_("enable"), default=True)
    access_key = models.CharField(_("AccessKey"), max_length=100)
    secret_key = models.CharField(_("SecretKey"), max_length=100)
    expire_dt = models.DateTimeField(_("expiration time"), default=datetime.max)

    @property
    def is_expired(self):
        return self.expire_dt.timestamp() < timezone.now().timestamp()

    @classmethod
    def generate_key(cls):
        return secrets.token_urlsafe(32), secrets.token_urlsafe(32)

    def __str__(self):
        return "<Access Key> {}".format(self.access_key)

    class Meta:
        db_table = "openapi_auth"
        verbose_name = _("AccessKey")
        verbose_name_plural = verbose_name
