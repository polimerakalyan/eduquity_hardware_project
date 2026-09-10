from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages

class FirstLoginMiddleware:
    """
    Middleware to check if employee is on first login and redirect to change password page
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        allowed_urls = [
            reverse('change_password'),
            reverse('logout'),
            '/static/',
            '/media/',
        ]
        
        if request.user.is_authenticated:
            if (request.user.user_type == 'employee' and 
                request.user.is_first_login and 
                request.path not in allowed_urls and 
                not request.path.startswith('/static/') and
                not request.path.startswith('/media/')):
                
                messages.warning(request, 'Please change your password before accessing other pages.')
                return redirect('change_password')
        
        response = self.get_response(request)
        return response
    
