# hardware_management/utils/audit.py

import json
from django.utils import timezone
from django.contrib.auth import get_user_model
from ..models import AuditLog

User = get_user_model()

def create_audit_log(
    request=None,
    user=None,
    role=None,
    action=None,
    module=None,
    description=None,
    target_user=None,
    target_model=None,
    target_id=None,
    old_value=None,
    new_value=None,
    **kwargs
):
    """
    Create an audit log entry with improved tracking
    
    Args:
        request: HTTP request object (optional)
        user: User object (optional, if not from request)
        role: User role (super_admin, manager, employee)
        action: Action type from ACTION_CHOICES
        module: Module name (e.g., 'Authentication', 'User Management')
        description: Human readable description
        target_user: Target user (if applicable)
        target_model: Target model name (e.g., 'Hardware', 'Assignment')
        target_id: Target object ID
        old_value: Previous value (if updating)
        new_value: New value (if updating)
    """
    
    # Determine user and role
    if user is None and request and hasattr(request, 'user'):
        user = request.user
    
    if role is None and user:
        role = user.user_type if user.is_authenticated else 'system'
    elif role is None:
        role = 'system'
    
    # Get IP and browser from request
    ip_address = None
    browser = ''
    request_path = ''
    request_method = ''
    session_key = None
    
    if request:
        ip_address = get_client_ip(request)
        browser = request.META.get('HTTP_USER_AGENT', '')[:500]
        request_path = request.path[:500]
        request_method = request.method
        if hasattr(request, 'session') and request.session.session_key:
            session_key = request.session.session_key
    
    # Convert complex objects to JSON for old/new values
    if old_value and isinstance(old_value, (dict, list)):
        old_value = json.dumps(old_value)[:1000]
    if new_value and isinstance(new_value, (dict, list)):
        new_value = json.dumps(new_value)[:1000]
    
    # Truncate description if too long
    if description and len(description) > 2000:
        description = description[:1997] + '...'
    
    try:
        audit_log = AuditLog.objects.create(
            user=user if user and user.is_authenticated else None,
            role=role,
            action=action,
            module=module or 'System',
            description=description or f"{action.replace('_', ' ').title()} performed",
            ip_address=ip_address,
            browser=browser,
            target_user=target_user,
            target_model=target_model,
            target_id=str(target_id) if target_id else None,
            old_value=old_value,
            new_value=new_value,
            request_path=request_path,
            request_method=request_method,
            session_key=session_key,
            created_at=timezone.now()
        )
        return audit_log
    except Exception as e:
        import traceback
        print(f"Failed to create audit log: {str(e)}")
        print(traceback.format_exc())
        return None


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '')
    return ip


def log_user_action(request, action, module, description, **kwargs):
    """Convenience function for user actions"""
    return create_audit_log(
        request=request,
        action=action,
        module=module,
        description=description,
        **kwargs
    )


def log_system_action(action, module, description, **kwargs):
    """Convenience function for system actions"""
    return create_audit_log(
        user=None,
        role='system',
        action=action,
        module=module,
        description=description,
        **kwargs
    )


def log_user_creation(request, new_user, created_by=None):
    """Helper to log user creation with all details"""
    return create_audit_log(
        request=request,
        user=created_by or request.user,
        action="user_create",
        module="User Management",
        description=f"Created new {new_user.user_type} user: {new_user.get_full_name() or new_user.username} ({new_user.email})",
        target_user=new_user,
        target_model="User",
        target_id=new_user.id,
        new_value={
            'username': new_user.username,
            'email': new_user.email,
            'user_type': new_user.user_type,
            'branch': getattr(new_user, 'branch_location', None),
            'is_active': new_user.is_active
        }
    )


def log_user_update(request, user, changes):
    """Helper to log user updates with before/after values"""
    return create_audit_log(
        request=request,
        user=request.user,
        action="user_update",
        module="User Management",
        description=f"Updated user: {user.get_full_name() or user.username}",
        target_user=user,
        target_model="User",
        target_id=user.id,
        old_value=changes.get('old', {}),
        new_value=changes.get('new', {})
    )


def log_user_deletion(request, user_to_delete):
    """Helper to log user deletion"""
    return create_audit_log(
        request=request,
        user=request.user,
        action="user_delete",
        module="User Management",
        description=f"Deleted user: {user_to_delete.get_full_name() or user_to_delete.username} ({user_to_delete.email})",
        target_user=user_to_delete,
        target_model="User",
        target_id=user_to_delete.id,
        old_value={
            'username': user_to_delete.username,
            'email': user_to_delete.email,
            'user_type': user_to_delete.user_type,
            'branch': getattr(user_to_delete, 'branch_location', None)
        }
    )


# hardware_management/utils/audit.py

import logging
from django.utils import timezone
from datetime import timedelta
from django.db import connection

logger = logging.getLogger(__name__)

def cleanup_old_audit_logs(days=30, batch_size=1000, dry_run=False):
    """
    Delete audit logs older than specified days
    
    Args:
        days (int): Number of days to keep logs (default: 30)
        batch_size (int): Number of logs to delete per batch (default: 1000)
        dry_run (bool): If True, only count logs without deleting
    
    Returns:
        dict: {'deleted_count': int, 'total_count': int}
    """
    from ..models import AuditLog
    
    cutoff_date = timezone.now() - timedelta(days=days)
    
    # Count logs to delete
    logs_to_delete = AuditLog.objects.filter(created_at__lt=cutoff_date)
    total_count = logs_to_delete.count()
    
    if total_count == 0:
        logger.info(f"No audit logs older than {days} days found.")
        return {'deleted_count': 0, 'total_count': 0}
    
    if dry_run:
        logger.info(f"DRY RUN: Would delete {total_count} audit logs older than {days} days.")
        return {'deleted_count': 0, 'total_count': total_count}
    
    # Delete in batches
    total_deleted = 0
    try:
        while True:
            logs = AuditLog.objects.filter(created_at__lt=cutoff_date)[:batch_size]
            count = logs.count()
            if count == 0:
                break
            log_ids = list(logs.values_list('id', flat=True))
            deleted = AuditLog.objects.filter(id__in=log_ids).delete()[0]
            total_deleted += deleted
            logger.info(f"Deleted {deleted} logs (total: {total_deleted})")
    except Exception as e:
        logger.error(f"Error deleting audit logs: {str(e)}")
        raise
    
    logger.info(f"Cleanup complete. Deleted {total_deleted} audit logs older than {days} days.")
    return {'deleted_count': total_deleted, 'total_count': total_count}