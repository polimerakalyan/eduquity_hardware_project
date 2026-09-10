# hardware_management/decorators.py

from functools import wraps
from django.utils import timezone
from .utils.audit import create_audit_log

def audit_log(action, module, get_target_info=None, get_change_data=None):
    """
    Decorator to automatically log view actions
    
    Args:
        action: The action type from ACTION_CHOICES
        module: The module name
        get_target_info: Function to extract target info from request
        get_change_data: Function to extract change data from request
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Get target info before processing
            target_info = {}
            if get_target_info:
                target_info = get_target_info(request, *args, **kwargs)
            
            # Get old values if updating
            old_value = None
            if get_change_data:
                old_value = get_change_data(request, *args, **kwargs, before=True)
            
            # Execute the view
            response = view_func(request, *args, **kwargs)
            
            # Get new values after processing
            new_value = None
            if get_change_data:
                new_value = get_change_data(request, *args, **kwargs, before=False)
            
            # Create description
            description = f"{action.replace('_', ' ').title()}"
            if target_info.get('target_name'):
                description += f" - {target_info['target_name']}"
            
            # Create audit log
            create_audit_log(
                request=request,
                action=action,
                module=module,
                description=description,
                target_user=target_info.get('target_user'),
                target_model=target_info.get('target_model'),
                target_id=target_info.get('target_id'),
                old_value=old_value,
                new_value=new_value
            )
            
            return response
        return wrapped_view
    return decorator


def log_action(action, module):
    """Simple decorator for logging without target info"""
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            response = view_func(request, *args, **kwargs)
            create_audit_log(
                request=request,
                action=action,
                module=module,
                description=f"{action.replace('_', ' ').title()} performed"
            )
            return response
        return wrapped_view
    return decorator