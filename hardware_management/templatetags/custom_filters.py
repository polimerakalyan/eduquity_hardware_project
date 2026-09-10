from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """Get item from dictionary by key"""
    if dictionary is None:
        return 0
    return dictionary.get(key, 0)

# templatetags/custom_filters.py
from django import template

register = template.Library()

@register.filter
def divide(value, arg):
    """Divide the value by arg"""
    try:
        return float(value) / float(arg)
    except (ValueError, ZeroDivisionError):
        return 0

@register.filter
def multiply(value, arg):
    """Multiply the value by arg"""
    try:
        return float(value) * float(arg)
    except (ValueError, TypeError):
        return 0