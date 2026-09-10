"""
URL configuration for eduquity_hardware project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import redirect

def dashboard_redirect(request):
    """Redirect user to appropriate dashboard based on user type"""
    if request.user.is_authenticated:
        print(f"DEBUG: User: {request.user.username}, Type: '{request.user.user_type}'")
        
        if request.user.user_type == 'super_admin':
            return redirect('super_admin_dashboard')
        elif request.user.user_type == 'manager':
            return redirect('manager_dashboard')
        else:  # employee
            return redirect('employee_dashboard')
    return redirect('login')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', dashboard_redirect, name='home'),
    path('', include('hardware_management.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

admin.site.site_header = "Eduquity Hardware Management - Admin"
admin.site.site_title = "Eduquity Admin Portal"
admin.site.index_title = "Welcome to Eduquity Hardware Management System"