from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser

class CustomUserAdmin(BaseUserAdmin):
    model = CustomUser
    list_display = ['username', 'email', 'created_at', 'updated_at']
    search_fields = ['username', 'email', 'phone']
    list_filter = ['username', 'email', 'phone']
    fieldsets = [
        ('Personal Information', {'fields': ['username', 'email', 'phone']}),
    ]

admin.site.register(CustomUser, CustomUserAdmin)