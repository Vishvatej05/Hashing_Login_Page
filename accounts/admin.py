from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.models import User

from .models import LoginFingerprint


class LoginFingerprintInline(admin.StackedInline):
    model = LoginFingerprint
    can_delete = False
    extra = 0
    readonly_fields = ('fingerprint', 'created_at')


@admin.register(LoginFingerprint)
class LoginFingerprintAdmin(admin.ModelAdmin):
    list_display = ('user', 'fingerprint', 'created_at')
    search_fields = ('user__username', 'fingerprint')
    readonly_fields = ('user', 'fingerprint', 'created_at')


class UserAdmin(DjangoUserAdmin):
    inlines = [LoginFingerprintInline]
    list_display = DjangoUserAdmin.list_display + ('password', 'get_fingerprint')

    def get_fingerprint(self, obj):
        lf = getattr(obj, 'login_fingerprint', None)
        return lf.fingerprint if lf else '-'

    get_fingerprint.short_description = 'Fingerprint'


admin.site.unregister(User)
admin.site.register(User, UserAdmin)

# Register your models here.
