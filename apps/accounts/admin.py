from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as AuthUserAdmin
from pdfxray.apps.accounts.models import user_profile

class user_profile_inline(admin.StackedInline):
    model = user_profile
    max_num = 1
    can_delete = False
    
class UserAdmin(AuthUserAdmin):
    inlines = [user_profile_inline]
    
admin.site.unregister(User)
admin.site.register(User,UserAdmin)