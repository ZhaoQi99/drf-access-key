from django.contrib import admin

from .models import OpenAPIAuth

from django.utils.translation import gettext_lazy as _


@admin.register(OpenAPIAuth)
class OpenApiAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "access_key",
        "name",
        "enable",
        "is_effective",
        "expire_dt",
        "desc",
    )
    list_display_links = ("access_key", )
    fieldsets = (
        (_("Basic"), {
            "fields": ("name", "desc", "expire_dt", "enable")
        }),
        (_("AccessKey/SecretKey"), {
            "fields": ("access_key", "secret_key")
        }),
    )
    readonly_fields = ("access_key", "secret_key")
    list_filter = ("enable", "expire_dt")
    search_fields = ("name", "desc", "access_key")
    actions = ["disable_selected"]

    def is_effective(self, obj):
        return not obj.is_expired

    is_effective.boolean = True
    is_effective.short_description = _("efficient")

    def get_readonly_fields(self, request, obj=None):
        if obj is None:
            return []
        return super().get_readonly_fields(request, obj)

    @admin.action(description=_("Disable select AccessKey"))
    def disable_selected(self, request, queryset):
        queryset.update(enable=False)

    def get_changeform_initial_data(self, request):
        data = super().get_changeform_initial_data(request)
        access_key, secret_key = OpenAPIAuth.generate_key()
        data.update(access_key=access_key, secret_key=secret_key)
        return data
