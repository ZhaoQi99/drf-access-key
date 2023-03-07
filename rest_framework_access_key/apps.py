from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class RestFrameworkAccessKeyConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'rest_framework_access_key'
    verbose_name = _("OpenAPI AccessKey")
