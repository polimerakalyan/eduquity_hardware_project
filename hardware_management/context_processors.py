from django.conf import settings

def company_info(request):
    """Add company information to all templates"""
    return {
        'company_name': getattr(settings, 'COMPANY_NAME', 'Eduquity'),
        'company_established': getattr(settings, 'COMPANY_ESTABLISHED', '2000'),
        'company_description': getattr(settings, 'COMPANY_DESCRIPTION', 'Thought-leader in the Indian assessment industry'),
        'current_year': 2024,
    }