from django import template

register = template.Library()

@register.filter
def lookup(dictionary, key):
    """Lookup value in dictionary by key"""
    try:
        return dictionary.get(key)
    except (AttributeError, TypeError):
        if hasattr(dictionary, '__getitem__'):
            try:
                return dictionary[key]
            except (KeyError, IndexError, TypeError):
                pass
        return None