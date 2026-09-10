from email.policy import default
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib import messages
from django.http import JsonResponse
from django.template import TemplateDoesNotExist
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.db.models import Q
import json
import secrets
from datetime import datetime, time
from django.views.decorators.http import require_POST
from .models import *
from django.core.paginator import Paginator
from django.db.models import Q

from .utils.email_utils import send_transfer_approval_email_to_receiver, send_transfer_approval_email_to_sender, send_transfer_rejection_email_to_receiver, send_transfer_rejection_email_to_sender

import random
from django.utils import timezone
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from django.conf import settings

@login_required
def audit_otp_login(request):
    """
    OTP verification page for Audit Logs access.
    """
    # If the user already has a valid OTP session, redirect directly
    if request.session.get('audit_log_access_granted', False):
        return redirect('view_audit_logs')

    # Check if OTP was already sent (so we can show the input box)
    otp_sent = request.session.get('otp_just_sent', False)
    
    context = {
        'user_email': request.user.email,
        'otp_sent': otp_sent,
    }
    return render(request, 'auth/audit_otp_login.html', context)


@login_required
def audit_otp_send(request):
    """
    Generate and send a 6-digit OTP to the Super Admin's email.
    """
    if request.user.user_type != 'super_admin':
        messages.error(request, 'Unauthorized access.')
        return redirect('dashboard')

    # Generate 6-digit OTP
    otp = str(random.randint(100000, 999999))
    expiry_time = timezone.now() + timezone.timedelta(minutes=5)

    # Save to user model
    user = request.user
    user.otp_code = otp
    user.otp_expiry = expiry_time
    user.save()

    # Set session flag so the template knows to show the input box
    request.session['otp_just_sent'] = True

    # Send email
    try:
        subject = '🔐 Audit Logs OTP Verification - Eduquity'
        message = f"""
        Your OTP for Audit Logs access is: {otp}
        
        This OTP is valid for 5 minutes.
        Do not share this OTP with anyone.
        """
        html_message = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #E04D00;">🔐 Audit Logs OTP</h2>
            <p>Dear <strong>{user.get_full_name() or user.username}</strong>,</p>
            <p>You requested a One-Time Password to access the Audit Logs.</p>
            <div style="background: #f8f9fa; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; border: 2px dashed #E04D00;">
                {otp}
            </div>
            <p><strong>Valid for:</strong> 5 minutes</p>
            <p>If you did not request this, please ignore this email.</p>
            <hr>
            <p style="color: #6c757d; font-size: 12px;">Eduquity Hardware Management Team</p>
        </body>
        </html>
        """

        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Audit Logs",
            description=f"OTP sent to {user.email} for Audit Logs access",
            target_user=request.user
        )
        
        messages.success(request, f'📧 OTP sent to {user.email}. Check your inbox (valid for 5 minutes).')
    
    except Exception as e:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_error",
            module="Audit Logs",
            description=f"OTP email failed for Audit Logs: {str(e)}",
            target_user=request.user
        )
        messages.error(request, 'Failed to send OTP. Please try again later.')

    return redirect('audit_otp_login')

@login_required
def audit_otp_verify(request):
    """
    Verify the entered OTP and grant access to Audit Logs.
    """
    if request.user.user_type != 'super_admin':
        messages.error(request, 'Unauthorized access.')
        return redirect('dashboard')

    if request.method == 'POST':
        entered_otp = request.POST.get('otp', '').strip()
        user = request.user

        if not entered_otp:
            messages.error(request, 'Please enter the OTP.')
            return redirect('audit_otp_login')

        # Check if OTP matches and is not expired
        if user.otp_code == entered_otp and user.otp_expiry and user.otp_expiry > timezone.now():
            # Grant access
            request.session['audit_log_access_granted'] = True
            
            create_audit_log(
                request=request,
                user=request.user,
                action="login",
                module="Audit Logs",
                description=f"Audit Logs access granted via OTP for {user.username}",
                target_user=request.user
            )
            
            messages.success(request, '✅ OTP verified. Access granted to Audit Logs.')
            
            # Clear OTP for security
            user.otp_code = None
            user.otp_expiry = None
            user.save()
            
            return redirect('view_audit_logs')
        
        else:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Audit Logs",
                description=f"Invalid or expired OTP attempt for Audit Logs by {user.username}",
                target_user=request.user
            )
            messages.error(request, '❌ Invalid or expired OTP. Please request a new one.')
            return redirect('audit_otp_login')

    return redirect('audit_otp_login')

@login_required
def view_audit_logs(request):
    """Super Admin view all audit logs with OTP verification"""
    
    # ========== OTP SECURITY CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Audit Logs",
            description=f"Unauthorized audit log access attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to view audit logs.')
        return redirect('login')
    
    if not request.session.get('audit_log_access_granted', False):
        return redirect('audit_otp_login')
    # ========================================

    # Existing logic...
    logs = AuditLog.objects.all().select_related('user', 'target_user').order_by('-created_at')
    
    action_filter = request.GET.get('action', '')
    if action_filter:
        logs = logs.filter(action=action_filter)
    
    user_filter = request.GET.get('user', '')
    if user_filter:
        logs = logs.filter(
            Q(user__username__icontains=user_filter) |
            Q(target_user__username__icontains=user_filter)
        )
    
    role_filter = request.GET.get('role', '')
    if role_filter:
        logs = logs.filter(role=role_filter)
    
    module_filter = request.GET.get('module', '')
    if module_filter:
        logs = logs.filter(module__icontains=module_filter)
    
    date_filter = request.GET.get('date', '')
    if date_filter:
        try:
            date_obj = datetime.strptime(date_filter, '%Y-%m-%d')
            logs = logs.filter(created_at__date=date_obj)
        except ValueError:
            pass
    
    from django.utils import timezone
    import pytz
    ist = pytz.timezone('Asia/Kolkata')
    today_str = timezone.localtime(timezone.now(), ist).strftime('%Y-%m-%d')
    today_logs = logs.filter(created_at__startswith=today_str).count()
    
    total_logs = logs.count()
    failed_logins = logs.filter(action='failed_login').count()
    successful_logins = logs.filter(action='login').count()
    
    action_choices = sorted(set(logs.values_list('action', flat=True)))
    
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    create_audit_log(
        request=request,
        user=request.user,
        action="system_info",
        module="Audit Logs",
        description=f"Super Admin {request.user.username} viewed audit logs ({total_logs} records)",
        target_user=request.user
    )
    
    context = {
        'logs': page_obj,
        'total_logs': total_logs,
        'today_logs': today_logs,
        'failed_logins': failed_logins,
        'successful_logins': successful_logins,
        'action_choices': action_choices,
        'role_choices': AuditLog.ROLE_CHOICES,
        'action_filter': action_filter,
        'user_filter': user_filter,
        'role_filter': role_filter,
        'module_filter': module_filter,
        'date_filter': date_filter,
        'page_obj': page_obj,
        'paginator': paginator,
    }
    return render(request, 'super_admin/audit_logs.html', context)


@login_required
def export_audit_logs_excel(request):
    """Export audit logs to Excel (Super Admin only)"""
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Audit Logs",
            description=f"Unauthorized audit log export attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to export audit logs.')
        return redirect('login')
    
    # Get filter parameters
    action_filter = request.GET.get('action', '')
    user_filter = request.GET.get('user', '')
    role_filter = request.GET.get('role', '')
    module_filter = request.GET.get('module', '')
    
    logs = AuditLog.objects.all().select_related('user', 'target_user').order_by('-created_at')
    
    if action_filter:
        logs = logs.filter(action=action_filter)
    if user_filter:
        logs = logs.filter(Q(user__username__icontains=user_filter) | Q(target_user__username__icontains=user_filter))
    if role_filter:
        logs = logs.filter(role=role_filter)
    if module_filter:
        logs = logs.filter(module__icontains=module_filter)
    
    if not logs.exists():
        messages.warning(request, 'No logs found to export.')
        return redirect('view_audit_logs')
    
    # Create Excel workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Audit Logs"
    
    # Define styles
    header_font = Font(bold=True, color="FFFFFF", size=11)
    header_fill = PatternFill(start_color="2C3E50", end_color="2C3E50", fill_type="solid")
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    center_alignment = Alignment(horizontal="center", vertical="center")
    
    # Headers
    headers = ['ID', 'User', 'Role', 'Action', 'Module', 'Description', 'IP Address', 'Target User', 'Target Model', 'Target ID', 'Created At']
    
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = center_alignment
        cell.border = border
    
    # Data rows
    row = 2
    for log in logs:
        ws.cell(row=row, column=1, value=str(log.log_id)[:8]).border = border
        ws.cell(row=row, column=2, value=log.user.username if log.user else 'System').border = border
        ws.cell(row=row, column=3, value=log.role).border = border
        ws.cell(row=row, column=4, value=log.action).border = border
        ws.cell(row=row, column=5, value=log.module).border = border
        ws.cell(row=row, column=6, value=log.description).border = border
        ws.cell(row=row, column=7, value=log.ip_address or '-').border = border
        ws.cell(row=row, column=8, value=log.target_user.username if log.target_user else '-').border = border
        ws.cell(row=row, column=9, value=log.target_model or '-').border = border
        ws.cell(row=row, column=10, value=log.target_id or '-').border = border
        ws.cell(row=row, column=11, value=log.created_at.strftime('%Y-%m-%d %H:%M:%S')).border = border
        ws.cell(row=row, column=11).alignment = center_alignment
        row += 1
    
    # Auto-adjust column widths
    for col in range(1, len(headers) + 1):
        max_length = len(headers[col-1])
        for row_idx in range(2, row):
            cell_value = ws.cell(row=row_idx, column=col).value
            if cell_value:
                max_length = max(max_length, len(str(cell_value)))
        ws.column_dimensions[get_column_letter(col)].width = min(max_length + 4, 50)
    
    # Audit log for export
    create_audit_log(
        request=request,
        user=request.user,
        action="export_report",
        module="Audit Logs",
        description=f"Super Admin {request.user.username} exported audit logs ({logs.count()} records)",
        target_user=request.user,
        new_value={'record_count': logs.count()}
    )
    
    # Prepare response
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"audit_logs_{timestamp}.xlsx"
    
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    wb.save(response)
    messages.success(request, f'✅ Audit logs exported successfully! ({logs.count()} records)')
    return response

# views.py - Add this view

from hardware_management.utils.audit import cleanup_old_audit_logs

@login_required
def cleanup_audit_logs(request):
    """
    Manually trigger audit log cleanup (Super Admin only)
    """
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Audit Logs",
            description=f"Unauthorized cleanup attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to perform this action.')
        return redirect('login')
    
    if request.method == 'POST':
        retention_days = int(request.POST.get('retention_days', 30))
        confirm = request.POST.get('confirm', 'off') == 'on'
        
        if not confirm:
            messages.error(request, 'Please confirm that you want to delete old logs.')
            return redirect('cleanup_audit_logs')
        
        # Get count before deletion
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        count_before = AuditLog.objects.filter(created_at__lt=cutoff_date).count()
        
        # Log the cleanup attempt
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Audit Logs",
            description=f"Super Admin {request.user.username} initiated audit log cleanup (retention: {retention_days} days)",
            target_user=request.user,
            new_value={'retention_days': retention_days, 'logs_to_delete': count_before}
        )
        
        # Perform cleanup
        result = cleanup_old_audit_logs(days=retention_days)
        
        if result['deleted_count'] == 0:
            messages.info(request, f'No audit logs older than {retention_days} days found to delete.')
        else:
            messages.success(
                request, 
                f'✅ Successfully deleted {result["deleted_count"]} audit logs older than {retention_days} days.'
            )
        
        # Log the result
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Audit Logs",
            description=f"Audit log cleanup completed: {result['deleted_count']} logs deleted",
            target_user=request.user,
            new_value={
                'deleted_count': result['deleted_count'],
                'retention_days': retention_days,
                'total_checked': result['total_count']
            }
        )
        
        return redirect('view_audit_logs')
    
    # GET request - show cleanup form
    total_logs = AuditLog.objects.count()
    logs_7_days = AuditLog.objects.filter(
        created_at__lt=timezone.now() - timedelta(days=7)
    ).count()
    logs_30_days = AuditLog.objects.filter(
        created_at__lt=timezone.now() - timedelta(days=30)
    ).count()
    logs_60_days = AuditLog.objects.filter(
        created_at__lt=timezone.now() - timedelta(days=60)
    ).count()
    logs_90_days = AuditLog.objects.filter(
        created_at__lt=timezone.now() - timedelta(days=90)
    ).count()
    
    context = {
        'total_logs': total_logs,
        'logs_7_days': logs_7_days,
        'logs_30_days': logs_30_days,
        'logs_60_days': logs_60_days,
        'logs_90_days': logs_90_days,
    }
    return render(request, 'super_admin/cleanup_audit_logs.html', context)


# ============== AUTHENTICATION VIEWS ==============
# views.py - Updated Authentication Views

from hardware_management.utils.audit import create_audit_log, get_client_ip
from django.contrib.auth import login, authenticate, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib import messages
from django.shortcuts import render, redirect
from django.utils import timezone

def user_login(request):
    """User login with enhanced audit logging"""
    
    # Redirect if already authenticated
    if request.user.is_authenticated:
        if request.user.user_type == 'super_admin':
            return redirect('super_admin_dashboard')
        elif request.user.user_type == 'manager':
            return redirect('manager_dashboard')
        else:
            return redirect('employee_dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        
        client_ip = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]

        user = authenticate(username=username, password=password)

        if user is not None:
            if not user.is_active:
                create_audit_log(
                    request=request,
                    user=None,
                    role='system',
                    action="failed_login",
                    module="Authentication",
                    description=f"Login attempt for inactive user '{username}' from IP {client_ip}",
                    target_model="User",
                    target_id=username,
                    old_value="inactive_account"
                )
                messages.error(request, 'Your account has been deactivated. Please contact administrator.')
                return render(request, 'auth/login.html')

            login(request, user)
            
            create_audit_log(
                request=request,
                user=user,
                action="login",
                module="Authentication",
                description=f"User {user.username} ({user.get_user_type_display()}) logged in successfully from IP {client_ip}",
                target_user=user,
                target_model="User",
                target_id=user.id,
                new_value={
                    'user_type': user.user_type,
                    'branch': getattr(user, 'branch_location', None),
                    'ip': client_ip,
                    'user_agent': user_agent[:200]
                }
            )

            # ✅ REMOVED: First login password change requirement
            # Redirect based on user type
            if user.user_type == 'super_admin':
                return redirect('super_admin_dashboard')
            elif user.user_type == 'manager':
                return redirect('manager_dashboard')
            else:
                return redirect('employee_dashboard')

        else:
            # Failed login attempt with detailed logging
            from django.contrib.auth import get_user_model
            User = get_user_model()
            user_exists = User.objects.filter(username=username).exists()
            
            if user_exists:
                try:
                    target_user = User.objects.get(username=username)
                    create_audit_log(
                        request=request,
                        user=None,
                        role='system',
                        action="failed_login",
                        module="Authentication",
                        description=f"Failed login attempt for existing user '{username}' from IP {client_ip} - Invalid password",
                        target_user=target_user,
                        target_model="User",
                        target_id=target_user.id,
                        old_value=f"failed_login_attempt_{client_ip}"
                    )
                except User.DoesNotExist:
                    create_audit_log(
                        request=request,
                        user=None,
                        role='system',
                        action="failed_login",
                        module="Authentication",
                        description=f"Failed login attempt - Username '{username}' not found from IP {client_ip}",
                        target_model="User",
                        target_id=username,
                        old_value="username_not_found"
                    )
            else:
                create_audit_log(
                    request=request,
                    user=None,
                    role='system',
                    action="failed_login",
                    module="Authentication",
                    description=f"Failed login attempt - Username '{username}' not found from IP {client_ip}",
                    target_model="User",
                    target_id=username,
                    old_value="username_not_found"
                )

            messages.error(request, 'Invalid username or password!')

    return render(request, 'auth/login.html')

def user_logout(request):
    """User logout with enhanced audit logging"""
    
    if request.user.is_authenticated:
        username = request.user.username
        user_type = request.user.user_type
        user_id = request.user.id
        
        # Get client information
        client_ip = get_client_ip(request)
        
        # Enhanced audit log for logout
        create_audit_log(
            request=request,
            user=request.user,
            action="logout",
            module="Authentication",
            description=f"User {username} ({user_type}) logged out from IP {client_ip}",
            target_user=request.user,
            target_model="User",
            target_id=user_id,
            new_value={
                'user_type': user_type,
                'logout_time': timezone.now().isoformat(),
                'ip': client_ip
            }
        )
    
    # Perform logout
    logout(request)
    messages.success(request, 'You have been logged out successfully!')
    return redirect('login')

@login_required
def change_password(request):
    """Change password with enhanced audit logging"""
    
    # Get client information
    client_ip = get_client_ip(request)
    user = request.user
    
    # ========== ✅ CHECK LOCK STATUS ==========
    if user.user_type == 'employee' and user.password_change_locked:
        create_audit_log(
            request=request,
            user=user,
            action="system_warning",
            module="Authentication",
            description=f"Password change blocked - Employee {user.username} is locked by Super Admin",
            target_user=user,
            target_model="User",
            target_id=user.id
        )
        messages.error(request, '❌ Password change is disabled by Super Admin. Please contact your Super Admin.')
        return redirect('employee_dashboard')
    # =========================================
    
    if request.method == 'POST':
        old_password = request.POST.get('old_password', '')
        new_password = request.POST.get('new_password', '')
        confirm_password = request.POST.get('confirm_password', '')
        
        # Validate all fields are present
        if not all([old_password, new_password, confirm_password]):
            messages.error(request, 'All fields are required!')
            create_audit_log(
                request=request,
                user=user,
                action="system_warning",
                module="Authentication",
                description=f"Password change failed for {user.username} - Missing required fields",
                target_user=user,
                target_model="User",
                target_id=user.id
            )
            return redirect('change_password')

        # Check if new passwords match
        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match!')
            create_audit_log(
                request=request,
                user=user,
                action="system_warning",
                module="Authentication",
                description=f"Password change failed for {user.username} - Passwords do not match",
                target_user=user,
                target_model="User",
                target_id=user.id
            )
            return redirect('change_password')

        # Check if new password is same as old
        if old_password == new_password:
            messages.error(request, 'New password cannot be same as old password!')
            create_audit_log(
                request=request,
                user=user,
                action="system_warning",
                module="Authentication",
                description=f"Password change failed for {user.username} - New password same as old password",
                target_user=user,
                target_model="User",
                target_id=user.id
            )
            return redirect('change_password')

        # Verify old password
        if not user.check_password(old_password):
            messages.error(request, 'Current password is incorrect!')
            create_audit_log(
                request=request,
                user=user,
                action="system_warning",
                module="Authentication",
                description=f"Password change failed for {user.username} - Incorrect current password from IP {client_ip}",
                target_user=user,
                target_model="User",
                target_id=user.id,
                old_value="incorrect_password"
            )
            return redirect('change_password')

        # Validate new password strength
        try:
            validate_password(new_password, user)
        except ValidationError as e:
            for error in e.messages:
                messages.error(request, error)
            create_audit_log(
                request=request,
                user=user,
                action="system_warning",
                module="Authentication",
                description=f"Password change failed for {user.username} - Validation error: {', '.join(e.messages)}",
                target_user=user,
                target_model="User",
                target_id=user.id
            )
            return redirect('change_password')

        # Update password
        user.set_password(new_password)
        user.save()
        
        update_session_auth_hash(request, user)

        create_audit_log(
            request=request,
            user=user,
            action="password_change",
            module="Authentication",
            description=f"User {user.username} ({user.get_user_type_display()}) changed password successfully from IP {client_ip}",
            target_user=user,
            target_model="User",
            target_id=user.id,
            old_value="password_changed",
            new_value={
                'user_type': user.user_type,
                'ip': client_ip
            }
        )

        messages.success(
            request,
            'Password changed successfully! You can now access all features.'
        )

        # Redirect based on user type
        if user.user_type == 'super_admin':
            return redirect('super_admin_dashboard')
        elif user.user_type == 'manager':
            return redirect('manager_dashboard')
        else:
            return redirect('employee_dashboard')

    context = {
        'is_first_login': False,
        'user_type': request.user.user_type,
        'username': request.user.username,
    }

    return render(request, 'auth/change_password.html', context)

@login_required
@require_POST
def toggle_password_lock(request, employee_id):
    """
    Super Admin toggles the password change lock for a specific employee.
    """
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="User Management",
            description=f"Unauthorized password lock toggle attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to perform this action.')
        return redirect('login')
    
    try:
        employee = CustomUser.objects.get(id=employee_id, user_type='employee')
    except CustomUser.DoesNotExist:
        messages.error(request, 'Employee not found.')
        return redirect('super_admin_employees')
    
    # Toggle the lock
    employee.password_change_locked = not employee.password_change_locked
    employee.save()
    
    status = 'locked' if employee.password_change_locked else 'unlocked'
    
    create_audit_log(
        request=request,
        user=request.user,
        action="password_lock_toggle",
        module="User Management",
        description=f"Super Admin {request.user.username} {status} password change for {employee.get_full_name() or employee.username}",
        target_user=employee,
        target_model="User",
        target_id=employee.id,
        new_value={
            'password_change_locked': employee.password_change_locked,
            'employee_username': employee.username,
            'status': status
        }
    )
    
    messages.success(request, f'🔒 Password change for {employee.get_full_name() or employee.username} has been {status}.')
    return redirect('super_admin_employees')
    
# views.py

@login_required
@require_POST
def bulk_lock_employees(request):
    """
    Super Admin locks password change for ALL active employees at once.
    """
    if request.user.user_type != 'super_admin':
        messages.error(request, 'Unauthorized action.')
        return redirect('login')
    
    # Lock all active employees
    count = CustomUser.objects.filter(user_type='employee', is_active=True).update(password_change_locked=True)
    
    create_audit_log(
        request=request,
        user=request.user,
        action="bulk_password_lock",
        module="User Management",
        description=f"Super Admin {request.user.username} locked password change for {count} active employees",
        target_user=request.user,
        new_value={'locked_count': count}
    )
    
    messages.success(request, f'🔒 Successfully locked password change for {count} active employees.')
    return redirect('super_admin_employees')


@login_required
@require_POST
def bulk_unlock_employees(request):
    """
    Super Admin unlocks password change for ALL active employees at once.
    """
    if request.user.user_type != 'super_admin':
        messages.error(request, 'Unauthorized action.')
        return redirect('login')
    
    # Unlock all active employees
    count = CustomUser.objects.filter(user_type='employee', is_active=True).update(password_change_locked=False)
    
    create_audit_log(
        request=request,
        user=request.user,
        action="bulk_password_unlock",
        module="User Management",
        description=f"Super Admin {request.user.username} unlocked password change for {count} active employees",
        target_user=request.user,
        new_value={'unlocked_count': count}
    )
    
    messages.success(request, f'🔓 Successfully unlocked password change for {count} active employees.')
    return redirect('super_admin_employees')


def check_suspicious_activity(request, username, client_ip):
    """Check for suspicious login activity"""
    from django.utils import timezone
    from datetime import timedelta
    from .models import AuditLog
    
    # Check for multiple failed attempts in the last 5 minutes
    time_threshold = timezone.now() - timedelta(minutes=5)
    
    failed_attempts = AuditLog.objects.filter(
        action="failed_login",
        target_id=username,
        created_at__gte=time_threshold
    ).count()
    
    if failed_attempts >= 5:
        # Log suspicious activity
        create_audit_log(
            request=None,
            user=None,
            role='system',
            action="system_warning",
            module="Security",
            description=f"Suspicious activity detected - {failed_attempts} failed login attempts for '{username}' from IP {client_ip} in 5 minutes",
            target_model="Security",
            old_value="suspicious_activity"
        )
        return True
    
    return False
# ============== MANAGER VIEWS ==============

from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, Q, Sum
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .models import CustomUser, Project, Hardware, HardwareAssignment, HardwareSerialEntry, HardwareType

@login_required
def manager_dashboard(request):
    """
    Manager dashboard with hardware based on branch_location
    ✅ FIX: Uses branch_location for hardware counts
    """
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Dashboard",
            description=f"Unauthorized dashboard access attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to access the manager dashboard.')
        return redirect('employee_dashboard')
    
    # Log dashboard access
    create_audit_log(
        request=request,
        user=request.user,
        action="system_info",
        module="Dashboard",
        description=f"Manager {request.user.username} accessed dashboard",
        target_user=request.user
    )
    
    # ========== GET DATA WITH OPTIMIZED QUERIES ==========
    employees = CustomUser.objects.filter(user_type='employee', manager=request.user)
    projects = Project.objects.all().order_by('-created_at')
    
    # ✅ FIX: Get hardware based on branch_location, not created_by
    # This is the critical fix - hardware should be shown based on where it physically is
    hardware_items = Hardware.objects.filter(branch_location=request.user.branch_location)
    
    # For assignments, still use assigned_by (manager created the assignment)
    hardware_assignments = HardwareAssignment.objects.filter(assigned_by=request.user)
    
    # ========== PROJECT STATISTICS ==========
    active_projects = projects.filter(is_active=True)
    current_projects = active_projects.count()
    total_projects = projects.count()
    
    # ========== HARDWARE STATUS COUNTS (Based on branch_location) ==========
    available_count = hardware_items.filter(status='available').count()
    assigned_count = hardware_items.filter(status='assigned').count()
    in_use_count = hardware_items.filter(status='in_use').count()
    maintenance_count = hardware_items.filter(status='maintenance').count()
    total_hardware = hardware_items.count()
    
    # ========== HARDWARE BY TYPE ==========
    hardware_by_type = {}
    for hw in hardware_items.select_related('hardware_type'):
        type_name = hw.hardware_type.name if hw.hardware_type else 'Unknown'
        hardware_by_type[type_name] = hardware_by_type.get(type_name, 0) + 1
    
    # ========== CHART CALCULATIONS ==========
    max_display_value = max(available_count, assigned_count, in_use_count, maintenance_count) or 1
    chart_max = int(max_display_value * 1.2) + 5
    
    scale_values = [
        chart_max,
        int(chart_max * 0.75),
        int(chart_max * 0.5),
        int(chart_max * 0.25),
        0
    ]
    
    hardware_status = [
        {
            'name': 'Available',
            'count': available_count,
            'percentage': (available_count / total_hardware * 100) if total_hardware > 0 else 0,
            'height': (available_count / chart_max * 100) if chart_max > 0 else 0,
            'color': 'success'
        },
        {
            'name': 'Assigned',
            'count': assigned_count,
            'percentage': (assigned_count / total_hardware * 100) if total_hardware > 0 else 0,
            'height': (assigned_count / chart_max * 100) if chart_max > 0 else 0,
            'color': 'warning'
        },
        {
            'name': 'In Use',
            'count': in_use_count,
            'percentage': (in_use_count / total_hardware * 100) if total_hardware > 0 else 0,
            'height': (in_use_count / chart_max * 100) if chart_max > 0 else 0,
            'color': 'info'
        },
        {
            'name': 'Maintenance',
            'count': maintenance_count,
            'percentage': (maintenance_count / total_hardware * 100) if total_hardware > 0 else 0,
            'height': (maintenance_count / chart_max * 100) if chart_max > 0 else 0,
            'color': 'danger'
        },
    ]
    
    # ========== RECENT ACTIVITIES ==========
    recent_activities = []
    
    # Recent assignments (last 5)
    recent_assignments = hardware_assignments.select_related('employee', 'project').order_by('-assigned_date')[:5]
    for assignment in recent_assignments:
        recent_activities.append({
            'icon': 'clipboard-check',
            'color': 'primary',
            'title': 'New hardware assignment',
            'description': f'{assignment.employee.get_full_name() or assignment.employee.username} → {assignment.project.project_name}',
            'timestamp': assignment.assigned_date,
            'type': 'assignment',
            'badge': 'New'
        })
    
    # Recent employees (last 5)
    recent_employees = employees.select_related('manager').order_by('-date_joined')[:5]
    for employee in recent_employees:
        recent_activities.append({
            'icon': 'person-plus',
            'color': 'success',
            'title': 'New employee joined',
            'description': f'{employee.get_full_name() or employee.username} - {employee.email}',
            'timestamp': employee.date_joined,
            'type': 'employee',
            'badge': 'New'
        })
    
    # Recent projects
    recent_projects = projects.order_by('-created_at')[:5]
    for project in recent_projects:
        recent_activities.append({
            'icon': 'folder-plus',
            'color': 'warning',
            'title': 'New project created',
            'description': f'{project.project_name} ({project.project_id})',
            'timestamp': project.created_at,
            'type': 'project',
            'badge': 'New'
        })
    
    # Sort activities by timestamp (most recent first)
    recent_activities.sort(key=lambda x: x['timestamp'], reverse=True)
    recent_activities = recent_activities[:8]
    
    # ========== GROWTH PERCENTAGES ==========
    thirty_days_ago = timezone.now() - timedelta(days=30)
    
    current_employees = employees.count()
    last_month_employees = employees.filter(date_joined__lt=thirty_days_ago).count()
    if last_month_employees > 0:
        employee_growth = ((current_employees - last_month_employees) / last_month_employees * 100)
    else:
        employee_growth = 0 if current_employees == 0 else 100
    
    current_total_projects = projects.count()
    last_month_projects = projects.filter(created_at__lt=thirty_days_ago).count()
    if last_month_projects > 0:
        project_growth = ((current_total_projects - last_month_projects) / last_month_projects * 100)
    else:
        project_growth = 0 if current_total_projects == 0 else 100
    
    # ========== HARDWARE GROWTH ==========
    current_hardware = total_hardware
    last_month_hardware = hardware_items.filter(created_at__lt=thirty_days_ago).count()
    if last_month_hardware > 0:
        hardware_growth = ((current_hardware - last_month_hardware) / last_month_hardware * 100)
    else:
        hardware_growth = 0 if current_hardware == 0 else 100
    
    # ========== GET ASSIGNMENTS ==========
    assignments_list = hardware_assignments.select_related('employee', 'project').order_by('-assigned_date')[:10]
    
    # ========== GET EMPLOYEES LIST ==========
    employees_list = employees.select_related('manager').order_by('-date_joined')[:10]
    
    # ========== VERIFICATION STATS ==========
    total_verifications = HardwareSerialEntry.objects.filter(
        assignment_item__assignment__assigned_by=request.user
    ).count()
    
    verified_count = HardwareSerialEntry.objects.filter(
        assignment_item__assignment__assigned_by=request.user,
        verified=True
    ).count()
    
    pending_verifications = HardwareSerialEntry.objects.filter(
        assignment_item__assignment__assigned_by=request.user,
        verified=False
    ).count()
    
    verification_rate = int((verified_count / total_verifications * 100)) if total_verifications > 0 else 0
    
    # ========== HARDWARE TYPE DATA ==========
    hardware_type_data = []
    for hw_type in HardwareType.objects.all():
        count = hardware_items.filter(hardware_type=hw_type).count()
        if count > 0:
            hardware_type_data.append({
                'name': hw_type.name,
                'count': count,
                'percentage': int((count / total_hardware * 100)) if total_hardware > 0 else 0
            })
    
    context = {
        # Statistics
        'total_employees': current_employees,
        'total_projects': current_projects,
        'active_assignments': hardware_assignments.filter(actual_return_date__isnull=True).count(),
        'hardware_count': total_hardware,
        
        # Hardware status
        'hardware_status': hardware_status,
        'available_count': available_count,
        'assigned_count': assigned_count,
        'in_use_count': in_use_count,
        'maintenance_count': maintenance_count,
        
        # Hardware by type
        'hardware_by_type': hardware_by_type,
        'hardware_type_data': hardware_type_data,
        
        # Lists
        'employees': employees_list,
        'projects': projects[:10],
        'assignments': assignments_list,
        'recent_activities': recent_activities,
        
        # Growth percentages
        'employee_growth': round(employee_growth, 1),
        'project_growth': round(project_growth, 1),
        'hardware_growth': round(hardware_growth, 1),
        
        # Chart settings
        'chart_max': chart_max,
        'scale_values': scale_values,
        'max_count': max_display_value,
        
        # Verification stats
        'verification_rate': verification_rate,
        'pending_verifications': pending_verifications,
        'verified_count': verified_count,
        'total_verifications': total_verifications,
        
        # Date
        'today': timezone.now().date(),
        'current_time': timezone.now(),
        'current_branch': request.user.branch_location,
    }
    return render(request, 'manager/dashboard.html', context)

# views.py - Updated Employee Management Views with Audit Logging

from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password
from hardware_management.utils.audit import create_audit_log, get_client_ip
import io
import csv
import re

# Default password constant
DEFAULT_PASSWORD = 'Eduquity@2024'

# ============================================================
# CREATE EMPLOYEE - WITH AUDIT LOGGING
# ============================================================
@login_required
def create_employee(request):
    """
    Super Admin can create employees and assign to any branch/manager
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Management",
            description=f"Unauthorized employee creation attempt by {request.user.username} (user_type: {request.user.user_type})",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to create employees.')
        return redirect('login')
    
    # ========== POST REQUEST ==========
    if request.method == 'POST':
        # Get form data
        name = request.POST.get('name', '').strip()
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        phone = request.POST.get('phone', '').strip()
        branch = request.POST.get('branch', '').strip()
        manager_id = request.POST.get('manager')
        
        client_ip = get_client_ip(request)
        
        # ========== VALIDATION ==========
        validation_errors = []
        
        if not name or len(name) < 2:
            validation_errors.append('Please enter a valid name (minimum 2 characters).')
        
        if not branch:
            validation_errors.append('Please select a branch.')
        
        if not username:
            validation_errors.append('Username is required.')
        elif CustomUser.objects.filter(username=username).exists():
            validation_errors.append(f'Username "{username}" already exists.')
        
        if not email:
            validation_errors.append('Email is required.')
        elif CustomUser.objects.filter(email=email).exists():
            validation_errors.append(f'Email "{email}" already exists.')
        elif '@' not in email or '.' not in email:
            validation_errors.append('Please enter a valid email address.')
        
        if phone:
            if not re.match(r'^\+?[\d\s\-()]{10,15}$', phone):
                validation_errors.append('Please enter a valid phone number (10-15 digits).')
        
        if validation_errors:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Employee Management",
                description=f"Employee creation validation failed: {', '.join(validation_errors[:3])}",
                target_user=request.user,
                new_value={'name': name, 'username': username, 'email': email, 'branch': branch}
            )
            for error in validation_errors:
                messages.error(request, error)
            return redirect('create_employee')
        
        # ========== GET MANAGER ==========
        manager = None
        manager_name = 'Unassigned'
        if manager_id:
            try:
                manager = CustomUser.objects.get(
                    id=manager_id,
                    user_type='manager',
                    is_active=True
                )
                if manager.branch_location and manager.branch_location != branch:
                    messages.warning(
                        request,
                        f'Manager {manager.get_full_name() or manager.username} is from {manager.branch_location} branch. '
                        f'Employee created without manager.'
                    )
                    manager = None
                else:
                    manager_name = manager.get_full_name() or manager.username
            except CustomUser.DoesNotExist:
                messages.warning(request, 'Selected manager not found. Employee created without manager.')
        
        # ========== CREATE EMPLOYEE ==========
        try:
            name_parts = name.split(' ', 1)
            first_name = name_parts[0]
            last_name = name_parts[1] if len(name_parts) > 1 else ''
            
            user = CustomUser.objects.create_user(
                username=username,
                email=email,
                password=DEFAULT_PASSWORD,
                user_type='employee',
                manager=manager,
                phone=phone or '',
                # ✅ REMOVED: is_first_login=True (no longer needed)
                first_name=first_name,
                last_name=last_name,
                branch_location=branch,
            )
            
            # ========== AUDIT LOG - SUCCESS ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="employee_create",
                module="Employee Management",
                description=f"Super Admin {request.user.username} created employee {name} ({username}) in {branch} branch" + (f" under {manager_name}" if manager else ""),
                target_user=user,
                target_model="User",
                target_id=user.id,
                new_value={
                    'name': name,
                    'username': username,
                    'email': email,
                    'phone': phone,
                    'branch': branch,
                    'manager': manager_name,
                    'ip': client_ip
                }
            )
            
            # ========== SEND WELCOME EMAIL ==========
            email_sent = False
            try:
                send_mail(
                    subject='Your Eduquity Hardware Management Account Credentials',
                    message=f'''
Dear {name},

Welcome to Eduquity Hardware Management System!

Your account has been created successfully. Here are your login credentials:

Username: {username}
Password: {DEFAULT_PASSWORD}
Login URL: http://eduquityinventory.co.in/login/
Branch: {branch}

Important Instructions:
1. Keep your credentials secure
2. Do not share your password with anyone
3. If you have any issues, please contact your manager

Best regards,
Eduquity Hardware Management Team
                    ''',
                    html_message=get_welcome_email_html(name, username, DEFAULT_PASSWORD, branch, manager_name),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False,
                )
                email_sent = True
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Employee Management",
                    description=f"Welcome email failed for {email}: {str(e)}",
                    target_user=user
                )
            
            # ========== SUCCESS MESSAGE ==========
            success_msg = f'✅ Employee account created successfully for {name} in {branch}!'
            if email_sent:
                success_msg += f' Credentials sent to {email}.'
            else:
                success_msg += f' Default password: {DEFAULT_PASSWORD} (Email failed).'
            if manager:
                success_msg += f' Assigned to: {manager_name}.'
            messages.success(request, success_msg)
            
            return redirect('super_admin_employees')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Employee Management",
                description=f"Employee creation failed: {str(e)}",
                new_value={'name': name, 'username': username, 'email': email, 'branch': branch}
            )
            messages.error(request, f'Error creating employee: {str(e)}')
            return redirect('create_employee')
    
    # ========== GET REQUEST ==========
    branches = CustomUser.objects.filter(
        user_type='manager'
    ).values_list('branch_location', flat=True).distinct()
    branches = [b for b in branches if b]
    branches = sorted(set(branches)) or ['Hyderabad', 'Bangalore', 'Mumbai', 'Delhi', 'Chennai', 'Pune', 'Kolkata']
    
    managers = CustomUser.objects.filter(
        user_type='manager',
        is_active=True
    ).order_by('first_name')
    
    context = {
        'branches': branches,
        'managers': managers,
        'recent_employees': CustomUser.objects.filter(user_type='employee').order_by('-date_joined')[:10],
        'total_employees': CustomUser.objects.filter(user_type='employee').count(),
        'active_employees': CustomUser.objects.filter(user_type='employee', is_active=True).count(),
        'pending_employees': CustomUser.objects.filter(user_type='employee', is_active=False).count(),
        'default_password': DEFAULT_PASSWORD,
    }
    return render(request, 'super_admin/create_employee.html', context)


# ============================================================
# BULK CREATE EMPLOYEES - WITH AUDIT LOGGING
# ============================================================
@login_required
def bulk_create_employees(request):
    """
    Super Admin can bulk create employees and assign to branches and managers
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Management",
            description=f"Unauthorized bulk employee creation attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to bulk create employees.')
        return redirect('login')
    
    # ========== POST REQUEST ==========
    if request.method == 'POST':
        csv_file = request.FILES.get('csv_file')
        branch = request.POST.get('branch', '').strip()
        manager_id = request.POST.get('manager')
        
        client_ip = get_client_ip(request)
        
        # Validate inputs
        if not csv_file:
            messages.error(request, 'Please select a CSV file to upload!')
            return redirect('bulk_create_employees')
        
        if not branch:
            messages.error(request, 'Please select a branch for the employees!')
            return redirect('bulk_create_employees')
        
        if not csv_file.name.endswith('.csv'):
            messages.error(request, 'Please upload a valid CSV file!')
            return redirect('bulk_create_employees')
        
        # Get manager
        manager = None
        manager_name = 'Unassigned'
        if manager_id:
            try:
                manager = CustomUser.objects.get(
                    id=manager_id,
                    user_type='manager',
                    branch_location=branch,
                    is_active=True
                )
                manager_name = manager.get_full_name() or manager.username
            except CustomUser.DoesNotExist:
                messages.warning(request, 'Selected manager not found. Employees created without manager.')
        
        try:
            decoded_file = csv_file.read().decode('utf-8-sig')
            io_string = io.StringIO(decoded_file)
            
            dialect = csv.Sniffer().sniff(decoded_file[:1024])
            reader = csv.DictReader(io_string, dialect=dialect)
            reader.fieldnames = [name.strip() for name in reader.fieldnames]
            
            created_count = 0
            error_count = 0
            errors = []
            created_employees_list = []
            
            for row_num, row in enumerate(reader, start=2):
                name = row.get('name', '').strip()
                email = row.get('email', '').strip()
                phone = row.get('phone', '').strip()
                username = row.get('username', '').strip()
                
                # Auto-generate username if not provided
                if not username and email:
                    username = email.split('@')[0].lower()
                    username = re.sub(r'[^a-zA-Z0-9_]', '_', username)
                
                # Validate
                if not name or len(name) < 2:
                    errors.append(f"Row {row_num}: Name is required (min 2 chars)")
                    error_count += 1
                    continue
                
                if not email:
                    errors.append(f"Row {row_num}: Email is required")
                    error_count += 1
                    continue
                
                if CustomUser.objects.filter(username=username).exists():
                    errors.append(f"Row {row_num}: Username '{username}' already exists")
                    error_count += 1
                    continue
                
                if CustomUser.objects.filter(email=email).exists():
                    errors.append(f"Row {row_num}: Email '{email}' already exists")
                    error_count += 1
                    continue
                
                try:
                    name_parts = name.split(' ', 1)
                    first_name = name_parts[0]
                    last_name = name_parts[1] if len(name_parts) > 1 else ''
                    
                    user = CustomUser.objects.create_user(
                        username=username,
                        email=email,
                        password=DEFAULT_PASSWORD,
                        user_type='employee',
                        manager=manager,
                        phone=phone or '',
                        # ✅ REMOVED: is_first_login=True
                        first_name=first_name,
                        last_name=last_name,
                        branch_location=branch,
                    )
                    
                    created_employees_list.append({
                        'name': name,
                        'username': username,
                        'email': email,
                        'branch': branch,
                        'manager': manager_name
                    })
                    created_count += 1
                    
                except Exception as e:
                    errors.append(f"Row {row_num}: {str(e)}")
                    error_count += 1
            
            # ========== AUDIT LOG - BULK CREATION ==========
            if created_count > 0:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="employee_bulk_create",
                    module="Employee Management",
                    description=f"Super Admin {request.user.username} bulk created {created_count} employees in {branch} branch" + (f" under {manager_name}" if manager else ""),
                    target_model="User",
                    new_value={
                        'count': created_count,
                        'branch': branch,
                        'manager': manager_name,
                        'users': [e['username'] for e in created_employees_list],
                        'ip': client_ip
                    }
                )
            
            # ========== SEND BULK EMAILS ==========
            if created_employees_list:
                send_bulk_welcome_emails(created_employees_list, request.user, branch, manager)
            
            # ========== MESSAGES ==========
            if created_count > 0:
                messages.success(request, f'✅ Successfully created {created_count} employee(s) in {branch}!')
                messages.info(request, f'Default password for all employees: {DEFAULT_PASSWORD}')
                if manager:
                    messages.info(request, f'📋 All employees assigned to manager: {manager_name}')
            
            if errors:
                messages.warning(request, f'Created {created_count} employee(s). {error_count} error(s):')
                for error in errors[:10]:
                    messages.warning(request, error)
            
            return redirect('super_admin_employees')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Employee Management",
                description=f"Bulk employee creation failed: {str(e)}",
                new_value={'branch': branch, 'error': str(e)}
            )
            messages.error(request, f'Error reading CSV file: {str(e)}')
            return redirect('bulk_create_employees')
    
    # ========== GET REQUEST ==========
    branches = CustomUser.objects.filter(
        user_type='manager'
    ).values_list('branch_location', flat=True).distinct()
    branches = [b for b in branches if b]
    branches = sorted(set(branches)) or ['Hyderabad', 'Bangalore', 'Mumbai', 'Delhi', 'Chennai', 'Pune', 'Kolkata']
    
    managers = CustomUser.objects.filter(
        user_type='manager',
        is_active=True
    ).order_by('first_name')
    
    context = {
        'employee_count': CustomUser.objects.filter(user_type='employee').count(),
        'sample_csv': sample_csv_template(),
        'default_password': DEFAULT_PASSWORD,
        'branches': branches,
        'managers': managers,
    }
    return render(request, 'super_admin/bulk_create_employees.html', context)


# ============================================================
# DELETE EMPLOYEE (MANAGER) - WITH AUDIT LOGGING
# ============================================================

@login_required
def delete_employee(request, employee_id):
    """
    Manager can delete an employee account
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Management",
            description=f"Unauthorized employee deletion attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to delete employees.')
        return redirect('employee_dashboard')
    
    employee = get_object_or_404(
        CustomUser,
        id=employee_id,
        user_type='employee',
        manager=request.user
    )
    
    # ========== PROCESS DELETE ==========
    if request.method == 'POST':
        employee_name = employee.get_full_name() or employee.username
        employee_email = employee.email
        employee_branch = employee.branch_location
        
        # Check for active assignments
        active_assignments = HardwareAssignment.objects.filter(
            employee=employee,
            actual_return_date__isnull=True
        )
        
        if active_assignments.exists():
            assignment_count = active_assignments.count()
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Employee Management",
                description=f"Delete failed for {employee_name} - {assignment_count} active assignment(s)",
                target_user=employee,
                target_model="User",
                target_id=employee.id,
                old_value="delete_attempt_blocked"
            )
            messages.error(
                request,
                f'Cannot delete {employee_name} - {assignment_count} active assignment(s). Please return all hardware first.'
            )
            return redirect('employee_list')
        
        # ========== AUDIT LOG - DELETION ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_delete",
            module="Employee Management",
            description=f"Manager {request.user.username} deleted employee {employee_name} ({employee_email})",
            target_user=employee,
            target_model="User",
            target_id=employee.id,
            old_value={
                'name': employee_name,
                'email': employee_email,
                'branch': employee_branch,
                'username': employee.username
            }
        )
        
        employee.delete()
        messages.success(request, f'Employee {employee_name} deleted successfully.')
        return redirect('employee_list')
    
    # GET request - redirect to list
    return redirect('employee_list')


# ============================================================
# EMPLOYEE LIST (MANAGER) - WITH AUDIT LOGGING
# ============================================================

@login_required
def employee_list(request):
    """
    View all employees with management options
    With audit logging for view access
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Management",
            description=f"Unauthorized employee list access by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET EMPLOYEES ==========
    employees = CustomUser.objects.filter(
        user_type='employee',
        manager=request.user
    ).order_by('-date_joined')
    
    # Enrich employee data
    for emp in employees:
        emp.active_assignments = HardwareAssignment.objects.filter(
            employee=emp,
            actual_return_date__isnull=True
        ).count()
        emp.total_assignments = HardwareAssignment.objects.filter(
            employee=emp
        ).count()
        emp.has_pending_delete_request = EmployeeDeleteRequest.objects.filter(
            employee=emp,
            status='pending'
        ).exists()
        emp.has_pending_update_request = EmployeeUpdateRequest.objects.filter(
            employee=emp,
            status='pending'
        ).exists()
        emp.whatsapp_number = format_whatsapp_number(emp.phone)
    
    # ========== LOG VIEW ==========
    # Only log occasionally to avoid spam
    if request.session.get('last_employee_list_view', 0) < timezone.now().timestamp() - 300:  # 5 minutes
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Employee Management",
            description=f"Manager {request.user.username} viewed employee list ({employees.count()} employees)",
            target_user=request.user,
            new_value={'employee_count': employees.count()}
        )
        request.session['last_employee_list_view'] = timezone.now().timestamp()
    
    context = {
        'employees': employees,
        'total_employees': employees.count(),
        'active_employees': employees.filter(is_active=True).count(),
        'pending_employees': employees.filter(is_active=False).count(),
    }
    return render(request, 'manager/employee_list.html', context)


# ============================================================
# REQUEST EMPLOYEE UPDATE - WITH AUDIT LOGGING
# ============================================================

@login_required
def request_employee_update(request, employee_id):
    """
    Manager requests to update employee details
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Management",
            description=f"Unauthorized employee update request by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    employee = get_object_or_404(
        CustomUser,
        id=employee_id,
        user_type='employee',
        manager=request.user
    )
    
    # ========== PROCESS REQUEST ==========
    if request.method == 'POST':
        field_updated = request.POST.get('field_updated')
        proposed_value = request.POST.get('proposed_value', '').strip()
        reason = request.POST.get('reason', '').strip()
        
        # ========== VALIDATION ==========
        if not field_updated:
            messages.error(request, 'Please select a field to update.')
            return redirect('employee_list')
        
        if not proposed_value:
            messages.error(request, 'Please enter the proposed value.')
            return redirect('employee_list')
        
        if not reason:
            messages.error(request, 'Please provide a reason for the update.')
            return redirect('employee_list')
        
        # Get current value
        current_value = None
        if field_updated == 'name':
            current_value = employee.get_full_name() or employee.username
        elif field_updated == 'email':
            current_value = employee.email
        elif field_updated == 'phone':
            current_value = employee.phone or ''
        elif field_updated == 'branch':
            current_value = employee.branch_location or ''
        elif field_updated == 'manager':
            current_value = employee.manager.get_full_name() or employee.manager.username if employee.manager else 'Unassigned'
        elif field_updated == 'multiple':
            current_value = 'Multiple fields to update'
        
        # Check for existing pending request
        existing_request = EmployeeUpdateRequest.objects.filter(
            employee=employee,
            status='pending'
        ).first()
        
        if existing_request:
            messages.warning(
                request,
                f'Update request for {employee.get_full_name() or employee.username} is already pending.'
            )
            return redirect('employee_list')
        
        # ========== CREATE REQUEST ==========
        update_request = EmployeeUpdateRequest.objects.create(
            employee=employee,
            requested_by=request.user,
            field_updated=field_updated,
            current_value=current_value,
            proposed_value=proposed_value,
            reason=reason,
            status='pending'
        )
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_request_update",
            module="Employee Management",
            description=f"Manager {request.user.username} requested update for {employee.get_full_name() or employee.username}: {field_updated} -> '{proposed_value}'",
            target_user=employee,
            target_model="EmployeeUpdateRequest",
            target_id=update_request.id,
            old_value=current_value,
            new_value=proposed_value
        )
        
        # ========== SEND EMAIL ==========
        try:
            from hardware_management.utils.email_utils import send_employee_update_request_email
            email_sent = send_employee_update_request_email(update_request)
            if email_sent:
                messages.success(
                    request,
                    f'✅ Update request submitted. Email notification sent to Super Admin.'
                )
            else:
                messages.success(
                    request,
                    f'✅ Update request submitted. (Email notification could not be sent)'
                )
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Employee Management",
                description=f"Update request email failed: {str(e)}"
            )
            messages.success(
                request,
                f'✅ Update request submitted. (Email notification failed: {str(e)})'
            )
        
        return redirect('employee_list')
    
    # ========== GET REQUEST ==========
    context = {'employee': employee}
    return render(request, 'manager/request_employee_update.html', context)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_welcome_email_html(name, username, password, branch, manager_name):
    """Generate HTML for welcome email"""
    return f'''
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(90deg, #E04D00 0%, #FF6B1A 100%); color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
        .content {{ background: #f9f9f9; padding: 30px; border: 1px solid #ddd; border-top: none; border-radius: 0 0 5px 5px; }}
        .credentials {{ background: #e8f4fc; border: 2px solid #E04D00; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
        .btn {{ display: inline-block; padding: 10px 20px; background: #E04D00; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }}
        .btn:hover {{ background: #c44500; }}
        .important {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px 15px; margin: 10px 0; }}
        code {{ background: #fff; padding: 2px 6px; border-radius: 3px; font-weight: bold; color: #E04D00; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Welcome to Eduquity Hardware Management</h2>
        </div>
        <div class="content">
            <p>Dear <strong>{name}</strong>,</p>
            
            <p>Your account has been created successfully in the Eduquity Hardware Management System.</p>
            
            <div class="credentials">
                <h3 style="color: #E04D00; margin-top: 0;">Your Login Credentials:</h3>
                <p><strong>Username:</strong> <code>{username}</code></p>
                <p><strong>Password:</strong> <code>{password}</code></p>
                <p><strong>Branch:</strong> {branch}</p>
                <p><strong>Manager:</strong> {manager_name}</p>
                <p><strong>Login URL:</strong> <a href="http://eduquityinventory.co.in/login/">http://eduquityinventory.co.in/login/</a></p>
                <div style="text-align: center; margin-top: 15px;">
                    <a href="http://eduquityinventory.co.in/login/" class="btn">🚀 Login Now</a>
                </div>
            </div>
            
            <div class="footer">
                <p><strong>Eduquity Hardware Management Team</strong><br>
                Established in 2000 - Thought-leader in the Indian assessment industry</p>
                <p><em>This is an automated email. Please do not reply.</em></p>
            </div>
        </div>
    </div>
</body>
</html>
    '''


def send_bulk_welcome_emails(employees, admin, branch, manager=None):
    """Send welcome emails to multiple employees"""
    default_password = DEFAULT_PASSWORD
    manager_name = manager.get_full_name() or manager.username if manager else 'Not Assigned'
    
    email_count = 0
    for emp in employees:
        try:
            name = emp.get('name', 'Employee')
            username = emp.get('username', 'user')
            email = emp.get('email', '')
            
            if not email:
                continue
            
            send_mail(
                subject='Your Eduquity Hardware Management Account Credentials',
                message=f'''
Dear {name},

Welcome to Eduquity Hardware Management System!

Your account has been created successfully. Here are your login credentials:

Username: {username}
Password: {default_password}
Login URL: http://eduquityinventory.co.in/login/
Branch: {branch}
Manager: {manager_name}

Important Instructions:
1. Keep your credentials secure
2. Do not share your password with anyone

Best regards,
Eduquity Hardware Management Team
                ''',
                html_message=get_welcome_email_html(name, username, default_password, branch, manager_name),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=True,
            )
            email_count += 1
        except Exception as e:
            print(f"Failed to send email to {emp.get('email', 'unknown')}: {str(e)}")
    
    return email_count


def sample_csv_template():
    """Generate sample CSV template content"""
    return """name,email,phone,username
John Doe,john.doe@example.com,+91 9876543210,john_doe
Jane Smith,jane.smith@example.com,+91 9876543211,jane_smith
Mike Johnson,mike.johnson@example.com,+91 9876543212,mike_j"""


@login_required
def download_sample_csv(request):
    """Download sample CSV template"""
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="employee_import_template.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['name', 'email', 'phone', 'username'])
    writer.writerow(['John Doe', 'john.doe@example.com', '+91 9876543210', 'john_doe'])
    writer.writerow(['Jane Smith', 'jane.smith@example.com', '+91 9876543211', 'jane_smith'])
    writer.writerow(['Mike Johnson', 'mike.johnson@example.com', '+91 9876543212', 'mike_j'])
    
    return response


def format_whatsapp_number(phone):
    """Format phone number for WhatsApp API"""
    if not phone:
        return None
    
    cleaned = re.sub(r'[^0-9]', '', str(phone))
    cleaned = cleaned.lstrip('0')
    
    if cleaned and cleaned[0] in ['6', '7', '8', '9'] and len(cleaned) == 10:
        cleaned = '91' + cleaned
    
    if cleaned and len(cleaned) >= 10:
        return cleaned
    
    return None
# views.py - Updated Employee Request Management Views with Audit Logging

from hardware_management.utils.audit import create_audit_log, get_client_ip
from django.core.paginator import Paginator
from django.db.models import Q
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import EmployeeUpdateRequest, EmployeeDeleteRequest, CustomUser, HardwareAssignment
from hardware_management.utils.email_utils import (
    send_employee_delete_request_email,
    send_employee_delete_response_email,
    send_employee_update_response_email
)


# ============================================================
# SUPER ADMIN - VIEW UPDATE REQUESTS
# ============================================================

@login_required
def super_admin_update_requests(request):
    """
    Super Admin view all employee update requests
    With audit logging for access and filtering
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Update Requests",
            description=f"Unauthorized access to update requests by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to view update requests.')
        return redirect('login')
    
    # ========== GET REQUESTS ==========
    update_requests = EmployeeUpdateRequest.objects.all().select_related(
        'employee', 'requested_by', 'reviewed_by'
    ).order_by('-created_at')
    
    # Apply filters
    status_filter = request.GET.get('status', '')
    if status_filter:
        update_requests = update_requests.filter(status=status_filter)
    
    field_filter = request.GET.get('field', '')
    if field_filter:
        update_requests = update_requests.filter(field_updated=field_filter)
    
    search_query = request.GET.get('search', '')
    if search_query:
        update_requests = update_requests.filter(
            Q(employee__first_name__icontains=search_query) |
            Q(employee__last_name__icontains=search_query) |
            Q(employee__username__icontains=search_query) |
            Q(employee__email__icontains=search_query) |
            Q(requested_by__first_name__icontains=search_query) |
            Q(requested_by__last_name__icontains=search_query) |
            Q(requested_by__username__icontains=search_query)
        )
    
    # ========== STATISTICS ==========
    total = update_requests.count()
    pending = update_requests.filter(status='pending').count()
    approved = update_requests.filter(status='approved').count()
    rejected = update_requests.filter(status='rejected').count()
    completed = update_requests.filter(status='completed').count()
    
    # ========== AUDIT LOG ==========
    # Only log occasionally to avoid spam
    if request.session.get('last_update_requests_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Employee Update Requests",
            description=f"Super Admin {request.user.username} viewed update requests ({total} total, {pending} pending)",
            target_user=request.user,
            new_value={
                'total': total,
                'pending': pending,
                'approved': approved,
                'rejected': rejected,
                'completed': completed,
                'filters': {
                    'status': status_filter,
                    'field': field_filter,
                    'search': search_query
                }
            }
        )
        request.session['last_update_requests_view'] = timezone.now().timestamp()
    
    # ========== PAGINATION ==========
    paginator = Paginator(update_requests, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'update_requests': page_obj,
        'total': total,
        'pending': pending,
        'approved': approved,
        'rejected': rejected,
        'completed': completed,
        'status_filter': status_filter,
        'field_filter': field_filter,
        'search_query': search_query,
        'field_choices': EmployeeUpdateRequest.FIELD_CHOICES,
        'page_obj': page_obj,
        'paginator': paginator,
    }
    return render(request, 'super_admin/update_requests.html', context)


# ============================================================
# SUPER ADMIN - DELETE UPDATE REQUEST
# ============================================================

@login_required
def super_admin_delete_update_request(request, request_id):
    """
    Super Admin delete an employee update request
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Update Requests",
            description=f"Unauthorized delete attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    update_request = get_object_or_404(EmployeeUpdateRequest, id=request_id)
    employee_name = update_request.employee.get_full_name() or update_request.employee.username
    
    if request.method == 'POST':
        request_id_display = update_request.id
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_update_reject",  # Using reject as delete is similar
            module="Employee Update Requests",
            description=f"Super Admin {request.user.username} deleted update request #{request_id_display} for {employee_name}",
            target_user=update_request.employee,
            target_model="EmployeeUpdateRequest",
            target_id=update_request.id,
            old_value={
                'field': update_request.field_updated,
                'proposed_value': update_request.proposed_value,
                'requested_by': update_request.requested_by.username
            }
        )
        
        update_request.delete()
        messages.success(request, f'✅ Update request #{request_id_display} for {employee_name} deleted successfully!')
        return redirect('super_admin_update_requests')
    
    context = {'update_request': update_request}
    return render(request, 'super_admin/delete_update_request.html', context)


# ============================================================
# SUPER ADMIN - APPROVE UPDATE REQUEST
# ============================================================

@login_required
def super_admin_approve_update_request(request, request_id):
    """
    Super Admin approve employee update request
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Update Requests",
            description=f"Unauthorized approve attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    update_request = get_object_or_404(EmployeeUpdateRequest, id=request_id, status='pending')
    employee = update_request.employee
    employee_name = employee.get_full_name() or employee.username
    
    if request.method == 'POST':
        notes = request.POST.get('notes', '').strip()
        field_updated = update_request.field_updated
        proposed_value = update_request.proposed_value
        old_value = update_request.current_value
        
        # ========== AUDIT LOG - BEFORE UPDATE ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_approve_update",
            module="Employee Update Requests",
            description=f"Super Admin {request.user.username} approved update request #{update_request.id} for {employee_name} - {field_updated}: '{old_value}' → '{proposed_value}'",
            target_user=employee,
            target_model="EmployeeUpdateRequest",
            target_id=update_request.id,
            old_value=old_value,
            new_value=proposed_value
        )
        
        try:
            # ========== APPLY UPDATE ==========
            if field_updated == 'name':
                name_parts = proposed_value.strip().split(' ', 1)
                employee.first_name = name_parts[0]
                employee.last_name = name_parts[1] if len(name_parts) > 1 else ''
            
            elif field_updated == 'email':
                # Check if email already exists
                if CustomUser.objects.filter(email=proposed_value).exclude(id=employee.id).exists():
                    messages.error(request, f'Email "{proposed_value}" already exists!')
                    return redirect('super_admin_update_requests')
                employee.email = proposed_value
            
            elif field_updated == 'phone':
                employee.phone = proposed_value
            
            elif field_updated == 'branch':
                employee.branch_location = proposed_value
            
            elif field_updated == 'manager':
                try:
                    manager = CustomUser.objects.get(
                        username__iexact=proposed_value,
                        user_type='manager',
                        is_active=True
                    )
                    employee.manager = manager
                except CustomUser.DoesNotExist:
                    messages.error(request, f'Manager "{proposed_value}" not found. Request rejected.')
                    return redirect('super_admin_update_requests')
            
            elif field_updated == 'multiple':
                # For multiple fields, log but don't auto-apply
                messages.warning(request, 'Multiple field updates require manual processing.')
                # You can implement custom logic here
            
            employee.save()
            
            # ========== UPDATE REQUEST STATUS ==========
            update_request.status = 'approved'
            update_request.reviewed_by = request.user
            update_request.reviewed_at = timezone.now()
            if notes:
                update_request.notes = notes
            update_request.save()
            
            # ========== AUDIT LOG - AFTER UPDATE ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="employee_update",
                module="Employee Management",
                description=f"Super Admin {request.user.username} updated {employee_name}: {field_updated} changed",
                target_user=employee,
                target_model="User",
                target_id=employee.id,
                old_value=old_value,
                new_value=proposed_value
            )
            
            messages.success(
                request,
                f'✅ Update request approved! {employee_name} updated successfully.'
            )
            
            # ========== SEND EMAIL NOTIFICATION ==========
            try:
                from hardware_management.utils.email_utils import send_employee_update_response_email
                send_employee_update_response_email(update_request, 'approved', notes)
                messages.info(request, f'📧 Notification sent to {update_request.requested_by.email}')
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Employee Update Requests",
                    description=f"Email notification failed for update request #{update_request.id}: {str(e)}",
                    target_user=update_request.requested_by
                )
                messages.warning(request, f'Update approved but email notification failed: {str(e)}')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Employee Update Requests",
                description=f"Error applying update for {employee_name}: {str(e)}",
                target_user=employee
            )
            messages.error(request, f'Error updating employee: {str(e)}')
        
        return redirect('super_admin_update_requests')
    
    context = {'update_request': update_request}
    return render(request, 'super_admin/approve_update_request.html', context)


# ============================================================
# SUPER ADMIN - REJECT UPDATE REQUEST
# ============================================================

@login_required
def super_admin_reject_update_request(request, request_id):
    """
    Super Admin reject employee update request
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Update Requests",
            description=f"Unauthorized reject attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    update_request = get_object_or_404(EmployeeUpdateRequest, id=request_id, status='pending')
    employee_name = update_request.employee.get_full_name() or update_request.employee.username
    
    if request.method == 'POST':
        notes = request.POST.get('notes', '').strip()
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_reject_update",
            module="Employee Update Requests",
            description=f"Super Admin {request.user.username} rejected update request #{update_request.id} for {employee_name} - {update_request.field_updated}: '{update_request.proposed_value}'",
            target_user=update_request.employee,
            target_model="EmployeeUpdateRequest",
            target_id=update_request.id,
            old_value="pending",
            new_value="rejected",
            new_value_extra={'reason': notes}
        )
        
        # ========== UPDATE REQUEST STATUS ==========
        update_request.status = 'rejected'
        update_request.reviewed_by = request.user
        update_request.reviewed_at = timezone.now()
        if notes:
            update_request.notes = notes
        update_request.save()
        
        messages.warning(
            request,
            f'❌ Update request for {employee_name} rejected.'
        )
        
        # ========== SEND EMAIL NOTIFICATION ==========
        try:
            from hardware_management.utils.email_utils import send_employee_update_response_email
            send_employee_update_response_email(update_request, 'rejected', notes)
            messages.info(request, f'📧 Notification sent to {update_request.requested_by.email}')
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Employee Update Requests",
                description=f"Email notification failed for rejection: {str(e)}",
                target_user=update_request.requested_by
            )
            messages.warning(request, f'Request rejected but email notification failed: {str(e)}')
        
        return redirect('super_admin_update_requests')
    
    context = {'update_request': update_request}
    return render(request, 'super_admin/reject_update_request.html', context)


# ============================================================
# MANAGER - REQUEST EMPLOYEE DELETE
# ============================================================

@login_required
def request_employee_delete(request, employee_id):
    """
    Manager requests to delete an employee (sends request to Super Admin)
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Delete Requests",
            description=f"Unauthorized delete request attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    employee = get_object_or_404(
        CustomUser,
        id=employee_id,
        user_type='employee',
        manager=request.user
    )
    
    employee_name = employee.get_full_name() or employee.username
    
    # ========== CHECK ACTIVE ASSIGNMENTS ==========
    active_assignments = HardwareAssignment.objects.filter(
        employee=employee,
        actual_return_date__isnull=True
    ).count()
    
    if active_assignments > 0:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Delete Requests",
            description=f"Delete request blocked for {employee_name} - {active_assignments} active assignment(s)",
            target_user=employee,
            target_model="User",
            target_id=employee.id,
            old_value="blocked_active_assignments"
        )
        messages.error(
            request,
            f'Cannot request deletion - {employee_name} has {active_assignments} active assignment(s).'
        )
        return redirect('employee_list')
    
    # ========== CHECK EXISTING REQUEST ==========
    existing_request = EmployeeDeleteRequest.objects.filter(
        employee=employee,
        status='pending'
    ).first()
    
    if existing_request:
        messages.warning(
            request,
            f'Delete request for {employee_name} is already pending approval.'
        )
        return redirect('employee_list')
    
    # ========== PROCESS REQUEST ==========
    if request.method == 'POST':
        reason = request.POST.get('reason', '').strip()
        
        if not reason:
            messages.error(request, 'Please provide a reason for deletion request.')
            return redirect('employee_list')
        
        # ========== CREATE DELETE REQUEST ==========
        delete_request = EmployeeDeleteRequest.objects.create(
            employee=employee,
            requested_by=request.user,
            reason=reason,
            status='pending'
        )
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_request_delete",
            module="Employee Delete Requests",
            description=f"Manager {request.user.username} requested deletion of {employee_name} (Reason: {reason[:50]}...)",
            target_user=employee,
            target_model="EmployeeDeleteRequest",
            target_id=delete_request.id,
            new_value={
                'reason': reason,
                'employee': employee_name,
                'employee_email': employee.email,
                'branch': employee.branch_location
            }
        )
        
        # ========== SEND EMAIL ==========
        try:
            email_sent = send_employee_delete_request_email(delete_request)
            if email_sent:
                messages.success(
                    request,
                    f'✅ Delete request for {employee_name} submitted to Super Admin. Email notification sent.'
                )
            else:
                messages.success(
                    request,
                    f'✅ Delete request for {employee_name} submitted to Super Admin.'
                )
                messages.warning(request, '⚠️ Email notification could not be sent to Super Admin.')
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Employee Delete Requests",
                description=f"Delete request email failed: {str(e)}",
                target_user=employee
            )
            messages.success(
                request,
                f'✅ Delete request for {employee_name} submitted to Super Admin.'
            )
            messages.warning(request, f'⚠️ Email notification failed: {str(e)}')
        
        return redirect('employee_list')
    
    # ========== GET REQUEST ==========
    context = {
        'employee': employee,
        'active_assignments': active_assignments,
    }
    return render(request, 'manager/request_employee_delete.html', context)


# ============================================================
# SUPER ADMIN - VIEW DELETE REQUESTS
# ============================================================

@login_required
def super_admin_delete_requests(request):
    """
    Super Admin view all employee delete requests
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Delete Requests",
            description=f"Unauthorized access to delete requests by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    delete_requests = EmployeeDeleteRequest.objects.all().select_related(
        'employee', 'requested_by', 'reviewed_by'
    ).order_by('-created_at')
    
    # Apply filters
    status_filter = request.GET.get('status', '')
    if status_filter:
        delete_requests = delete_requests.filter(status=status_filter)
    
    search_query = request.GET.get('search', '')
    if search_query:
        delete_requests = delete_requests.filter(
            Q(employee__first_name__icontains=search_query) |
            Q(employee__last_name__icontains=search_query) |
            Q(employee__username__icontains=search_query) |
            Q(employee__email__icontains=search_query) |
            Q(requested_by__first_name__icontains=search_query) |
            Q(requested_by__last_name__icontains=search_query) |
            Q(requested_by__username__icontains=search_query)
        )
    
    # ========== STATISTICS ==========
    total = delete_requests.count()
    pending = delete_requests.filter(status='pending').count()
    approved = delete_requests.filter(status='approved').count()
    rejected = delete_requests.filter(status='rejected').count()
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_delete_requests_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Employee Delete Requests",
            description=f"Super Admin {request.user.username} viewed delete requests ({total} total, {pending} pending)",
            target_user=request.user,
            new_value={
                'total': total,
                'pending': pending,
                'approved': approved,
                'rejected': rejected
            }
        )
        request.session['last_delete_requests_view'] = timezone.now().timestamp()
    
    # ========== PAGINATION ==========
    paginator = Paginator(delete_requests, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'delete_requests': page_obj,
        'total': total,
        'pending': pending,
        'approved': approved,
        'rejected': rejected,
        'status_filter': status_filter,
        'search_query': search_query,
        'page_obj': page_obj,
        'paginator': paginator,
    }
    return render(request, 'super_admin/delete_requests.html', context)


# ============================================================
# SUPER ADMIN - APPROVE DELETE REQUEST
# ============================================================

@login_required
def super_admin_approve_delete_request(request, request_id):
    """
    Super Admin approve employee delete request
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Delete Requests",
            description=f"Unauthorized approve attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    delete_request = get_object_or_404(EmployeeDeleteRequest, id=request_id, status='pending')
    employee = delete_request.employee
    employee_name = employee.get_full_name() or employee.username
    employee_email = employee.email
    
    if request.method == 'POST':
        notes = request.POST.get('notes', '').strip()
        
        # ========== CHECK ACTIVE ASSIGNMENTS AGAIN ==========
        active_assignments = HardwareAssignment.objects.filter(
            employee=employee,
            actual_return_date__isnull=True
        ).count()
        
        if active_assignments > 0:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Employee Delete Requests",
                description=f"Delete blocked for {employee_name} - {active_assignments} active assignment(s)",
                target_user=employee,
                target_model="EmployeeDeleteRequest",
                target_id=delete_request.id,
                old_value="approve_blocked_active_assignments"
            )
            messages.error(
                request,
                f'Cannot delete - {employee_name} has {active_assignments} active assignment(s).'
            )
            return redirect('super_admin_delete_requests')
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_approve_delete",
            module="Employee Delete Requests",
            description=f"Super Admin {request.user.username} approved deletion of {employee_name} ({employee_email})",
            target_user=employee,
            target_model="EmployeeDeleteRequest",
            target_id=delete_request.id,
            old_value="pending",
            new_value="approved",
            new_value_extra={
                'employee_name': employee_name,
                'employee_email': employee_email,
                'branch': employee.branch_location,
                'requested_by': delete_request.requested_by.username
            }
        )
        
        # ========== UPDATE REQUEST ==========
        delete_request.status = 'approved'
        delete_request.reviewed_by = request.user
        delete_request.reviewed_at = timezone.now()
        if notes:
            delete_request.notes = notes
        delete_request.save()
        
        # ========== DELETE EMPLOYEE ==========
        try:
            # Store employee info before deletion for audit
            employee_info = {
                'name': employee_name,
                'email': employee_email,
                'username': employee.username,
                'branch': employee.branch_location,
                'manager': employee.manager.get_full_name() or employee.manager.username if employee.manager else 'Unassigned'
            }
            
            employee.delete()
            
            # ========== AUDIT LOG - DELETION COMPLETE ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="employee_delete",
                module="Employee Management",
                description=f"Super Admin {request.user.username} deleted employee {employee_name} via delete request #{delete_request.id}",
                target_model="User",
                target_id=employee.id,
                old_value=employee_info
            )
            
            messages.success(request, f'✅ Employee {employee_name} deleted successfully!')
            
            # ========== SEND EMAIL NOTIFICATION ==========
            try:
                from hardware_management.utils.email_utils import send_employee_delete_response_email
                send_employee_delete_response_email(delete_request, 'approved', notes)
                messages.info(request, f'📧 Notification sent to {delete_request.requested_by.email}')
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Employee Delete Requests",
                    description=f"Email notification failed for delete approval: {str(e)}",
                    target_user=delete_request.requested_by
                )
                messages.warning(request, f'Employee deleted but email notification failed: {str(e)}')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Employee Delete Requests",
                description=f"Error deleting {employee_name}: {str(e)}",
                target_user=employee
            )
            messages.error(request, f'Error deleting employee: {str(e)}')
        
        return redirect('super_admin_delete_requests')
    
    context = {'delete_request': delete_request}
    return render(request, 'super_admin/approve_delete_request.html', context)


# ============================================================
# SUPER ADMIN - REJECT DELETE REQUEST
# ============================================================

@login_required
def super_admin_reject_delete_request(request, request_id):
    """
    Super Admin reject employee delete request
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Delete Requests",
            description=f"Unauthorized reject attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    delete_request = get_object_or_404(EmployeeDeleteRequest, id=request_id, status='pending')
    employee_name = delete_request.employee.get_full_name() or delete_request.employee.username
    
    if request.method == 'POST':
        notes = request.POST.get('notes', '').strip()
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_reject_delete",
            module="Employee Delete Requests",
            description=f"Super Admin {request.user.username} rejected deletion request for {employee_name}",
            target_user=delete_request.employee,
            target_model="EmployeeDeleteRequest",
            target_id=delete_request.id,
            old_value="pending",
            new_value="rejected",
            new_value_extra={'reason': notes}
        )
        
        # ========== UPDATE REQUEST ==========
        delete_request.status = 'rejected'
        delete_request.reviewed_by = request.user
        delete_request.reviewed_at = timezone.now()
        if notes:
            delete_request.notes = notes
        delete_request.save()
        
        messages.warning(
            request,
            f'❌ Delete request for {employee_name} rejected.'
        )
        
        # ========== SEND EMAIL NOTIFICATION ==========
        try:
            from hardware_management.utils.email_utils import send_employee_delete_response_email
            send_employee_delete_response_email(delete_request, 'rejected', notes)
            messages.info(request, f'📧 Notification sent to {delete_request.requested_by.email}')
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Employee Delete Requests",
                description=f"Email notification failed for delete rejection: {str(e)}",
                target_user=delete_request.requested_by
            )
            messages.warning(request, f'Request rejected but email notification failed: {str(e)}')
        
        return redirect('super_admin_delete_requests')
    
    context = {'delete_request': delete_request}
    return render(request, 'super_admin/reject_delete_request.html', context)

# Add this import at the top of your views.py
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter
from django.http import HttpResponse
from datetime import datetime

# @login_required
# def create_project(request):
#     if request.user.user_type != 'manager':
#         return redirect('employee_dashboard')
    
#     if request.method == 'POST':
#         project_id = request.POST.get('project_id')
#         project_name = request.POST.get('project_name')
#         description = request.POST.get('description')
#         start_date = request.POST.get('start_date')
#         end_date = request.POST.get('end_date')
#         location = request.POST.get('location')
        
#         if Project.objects.filter(project_id=project_id).exists():
#             messages.error(request, 'Project ID already exists!')
#             return redirect('create_project')
        
#         if Project.objects.filter(project_name=project_name).exists():
#             messages.error(request, 'Project name already exists!')
#             return redirect('create_project')
        
#         Project.objects.create(
#             project_id=project_id,
#             project_name=project_name,
#             description=description,
#             start_date=start_date,
#             end_date=end_date,
#             location=location,
#             created_by=request.user
#         )
        
#         messages.success(request, f'Project "{project_name}" created successfully!')
#         return redirect('create_project')
    
#     # Get all projects
#     projects = Project.objects.filter(created_by=request.user).order_by('-created_at')
    
#     total_projects = projects.count()
#     active_projects = 0
#     total_hardware_assigned = 0
#     total_employees = set()
    
#     for project in projects:
#         # Get all active assignments for this project (not returned)
#         assignments = HardwareAssignment.objects.filter(
#             project=project,
#             assigned_by=request.user,
#             actual_return_date__isnull=True
#         )
        
#         # Count unique employees
#         project.employee_count = assignments.values('employee').distinct().count()
#         total_employees.add(project.employee_count)
        
#         # Initialize counters
#         project.total_hardware = 0
#         project.active_hardware = 0
#         project.assigned_hardware = 0
#         project.available_hardware = 0
#         hardware_by_type = {}
#         employee_assignments = []
        
#         for assignment in assignments:
#             for item in assignment.hardwareassignmentitem_set.all():
#                 hardware = item.hardware
#                 project.total_hardware += 1
                
#                 # Count by hardware type
#                 hw_type = hardware.hardware_type.name if hardware.hardware_type else 'Unknown'
#                 hardware_by_type[hw_type] = hardware_by_type.get(hw_type, 0) + 1
                
#                 # Count by status
#                 if hardware.status == 'in_use':
#                     project.active_hardware += 1
#                 elif hardware.status == 'assigned':
#                     project.assigned_hardware += 1
#                 elif hardware.status == 'available':
#                     project.available_hardware += 1
                
#                 # Get verification status
#                 verification_status = 'not_entered'
#                 verified = False
#                 try:
#                     serial_entry = HardwareSerialEntry.objects.get(assignment_item=item)
#                     if serial_entry.verified:
#                         verification_status = 'verified'
#                         verified = True
#                     else:
#                         verification_status = 'pending'
#                 except HardwareSerialEntry.DoesNotExist:
#                     pass
                
#                 # Add to employee assignments list
#                 employee_assignments.append({
#                     'employee_name': assignment.employee.get_full_name() or assignment.employee.username,
#                     'employee_email': assignment.employee.email,
#                     'exam_city': assignment.exam_city,
#                     'hardware_type': hw_type,
#                     'serial_number': hardware.serial_number,
#                     'model': hardware.model_name,
#                     'status': hardware.status,
#                     'verified': verified,
#                     'verification_status': verification_status,
#                     'assigned_date': assignment.assigned_date
#                 })
        
#         project.hardware_by_type = hardware_by_type
#         project.employee_assignments = employee_assignments
#         project.assignments = assignments
        
#         total_hardware_assigned += project.total_hardware
        
#         if assignments.exists():
#             active_projects += 1
    
#     context = {
#         'projects': projects,
#         'total_projects': total_projects,
#         'active_projects': active_projects,
#         'total_hardware_assigned': total_hardware_assigned,
#         'total_employees': len(total_employees),
#     }
#     return render(request, 'manager/create_project.html', context)


# @login_required
# def export_project_excel(request, project_id):
#     """Export project-wise hardware assignments to Excel"""
#     if request.user.user_type != 'manager':
#         return redirect('employee_dashboard')
    
#     # Get the project
#     project = get_object_or_404(Project, id=project_id, created_by=request.user)
    
#     # Get all active assignments for this project
#     assignments = HardwareAssignment.objects.filter(
#         project=project,
#         assigned_by=request.user,
#         actual_return_date__isnull=True
#     ).select_related('employee', 'project').prefetch_related('hardwareassignmentitem_set__hardware__hardware_type')
    
#     # Create workbook and worksheet
#     wb = openpyxl.Workbook()
    
#     # Create Summary Sheet
#     ws_summary = wb.active
#     ws_summary.title = "Project Summary"
    
#     # Define styles
#     header_font = Font(bold=True, color="FFFFFF", size=12)
#     header_fill = PatternFill(start_color="E04D00", end_color="E04D00", fill_type="solid")
#     subheader_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
#     border = Border(
#         left=Side(style='thin'),
#         right=Side(style='thin'),
#         top=Side(style='thin'),
#         bottom=Side(style='thin')
#     )
#     center_alignment = Alignment(horizontal='center', vertical='center')
    
#     # Project Summary Sheet
#     ws_summary.merge_cells('A1:F1')
#     ws_summary['A1'] = f'PROJECT SUMMARY - {project.project_name}'
#     ws_summary['A1'].font = Font(bold=True, size=16)
#     ws_summary['A1'].alignment = center_alignment
    
#     ws_summary['A3'] = 'Project ID'
#     ws_summary['B3'] = project.project_id
#     ws_summary['A4'] = 'Project Name'
#     ws_summary['B4'] = project.project_name
#     ws_summary['A5'] = 'Location'
#     ws_summary['B5'] = project.location
#     ws_summary['A6'] = 'Duration'
#     ws_summary['B6'] = f'{project.start_date.strftime("%d-%m-%Y")} to {project.end_date.strftime("%d-%m-%Y")}'
#     ws_summary['A7'] = 'Description'
#     ws_summary['B7'] = project.description or 'N/A'
#     ws_summary['A8'] = 'Created On'
#     ws_summary['B8'] = project.created_at.strftime("%d-%m-%Y %H:%M:%S")
    
#     # Format summary headers
#     for row in range(3, 9):
#         ws_summary[f'A{row}'].font = Font(bold=True)
#         ws_summary[f'A{row}'].fill = PatternFill(start_color="F2F2F2", end_color="F2F2F2", fill_type="solid")
    
#     # Hardware Statistics
#     ws_summary['A10'] = 'HARDWARE STATISTICS'
#     ws_summary.merge_cells(f'A10:F10')
#     ws_summary['A10'].font = Font(bold=True, size=12)
#     ws_summary['A10'].fill = subheader_fill
#     ws_summary['A10'].font = Font(bold=True, color="FFFFFF")
    
#     ws_summary['A11'] = 'Total Hardware Items'
#     ws_summary['B11'] = 0
#     ws_summary['A12'] = 'Hardware In Use'
#     ws_summary['B12'] = 0
#     ws_summary['A13'] = 'Hardware Assigned'
#     ws_summary['B13'] = 0
#     ws_summary['A14'] = 'Available Hardware'
#     ws_summary['B14'] = 0
    
#     total_hardware = 0
#     active_hardware = 0
#     assigned_hardware = 0
#     available_hardware = 0
#     hardware_type_summary = {}
    
#     for assignment in assignments:
#         for item in assignment.hardwareassignmentitem_set.all():
#             hardware = item.hardware
#             total_hardware += 1
            
#             hw_type = hardware.hardware_type.name if hardware.hardware_type else 'Unknown'
#             hardware_type_summary[hw_type] = hardware_type_summary.get(hw_type, 0) + 1
            
#             if hardware.status == 'in_use':
#                 active_hardware += 1
#             elif hardware.status == 'assigned':
#                 assigned_hardware += 1
#             elif hardware.status == 'available':
#                 available_hardware += 1
    
#     ws_summary['B11'] = total_hardware
#     ws_summary['B12'] = active_hardware
#     ws_summary['B13'] = assigned_hardware
#     ws_summary['B14'] = available_hardware
    
#     # Hardware by Type
#     ws_summary['A16'] = 'HARDWARE BY TYPE'
#     ws_summary.merge_cells(f'A16:F16')
#     ws_summary['A16'].font = Font(bold=True, color="FFFFFF")
#     ws_summary['A16'].fill = subheader_fill
    
#     row = 17
#     for hw_type, count in hardware_type_summary.items():
#         ws_summary[f'A{row}'] = hw_type
#         ws_summary[f'B{row}'] = count
#         row += 1
    
#     # Employee Statistics
#     ws_summary['A20'] = 'EMPLOYEE STATISTICS'
#     ws_summary.merge_cells(f'A20:F20')
#     ws_summary['A20'].font = Font(bold=True, color="FFFFFF")
#     ws_summary['A20'].fill = subheader_fill
    
#     unique_employees = {}
#     for assignment in assignments:
#         emp_id = assignment.employee.id
#         if emp_id not in unique_employees:
#             unique_employees[emp_id] = {
#                 'name': assignment.employee.get_full_name() or assignment.employee.username,
#                 'email': assignment.employee.email,
#                 'phone': assignment.employee.phone or 'N/A'
#             }
    
#     ws_summary['A21'] = 'Total Unique Employees'
#     ws_summary['B21'] = len(unique_employees)
    
#     # Create Hardware Details Sheet
#     ws_hardware = wb.create_sheet("Hardware Details")
    
#     # Headers for Hardware Details
#     hardware_headers = ['S.No', 'Employee Name', 'Employee Email', 'Exam City', 'Hardware Type', 
#                         'Serial Number', 'Model', 'Status', 'Verification Status', 'Assigned Date']
    
#     for col, header in enumerate(hardware_headers, 1):
#         cell = ws_hardware.cell(row=1, column=col, value=header)
#         cell.font = header_font
#         cell.fill = header_fill
#         cell.alignment = center_alignment
#         cell.border = border
    
#     # Add data to Hardware Details
#     row = 2
#     serial_no = 1
#     for assignment in assignments:
#         for item in assignment.hardwareassignmentitem_set.all():
#             hardware = item.hardware
            
#             # Get verification status
#             verification_status = 'Not Entered'
#             try:
#                 serial_entry = HardwareSerialEntry.objects.get(assignment_item=item)
#                 if serial_entry.verified:
#                     verification_status = 'Verified'
#                 else:
#                     verification_status = 'Pending'
#             except HardwareSerialEntry.DoesNotExist:
#                 pass
            
#             ws_hardware.cell(row=row, column=1, value=serial_no).border = border
#             ws_hardware.cell(row=row, column=2, value=assignment.employee.get_full_name() or assignment.employee.username).border = border
#             ws_hardware.cell(row=row, column=3, value=assignment.employee.email).border = border
#             ws_hardware.cell(row=row, column=4, value=assignment.exam_city).border = border
#             ws_hardware.cell(row=row, column=5, value=hardware.hardware_type.name if hardware.hardware_type else 'Unknown').border = border
#             ws_hardware.cell(row=row, column=6, value=hardware.serial_number).border = border
#             ws_hardware.cell(row=row, column=7, value=hardware.model_name or 'N/A').border = border
            
#             # Status with color
#             status_cell = ws_hardware.cell(row=row, column=8, value=hardware.status.upper())
#             if hardware.status == 'in_use':
#                 status_cell.fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
#             elif hardware.status == 'assigned':
#                 status_cell.fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
            
#             # Verification status with color
#             verify_cell = ws_hardware.cell(row=row, column=9, value=verification_status)
#             if verification_status == 'Verified':
#                 verify_cell.fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
#             elif verification_status == 'Pending':
#                 verify_cell.fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
            
#             ws_hardware.cell(row=row, column=10, value=assignment.assigned_date.strftime("%d-%m-%Y")).border = border
            
#             row += 1
#             serial_no += 1
    
#     # Auto-adjust column widths for Hardware Details
#     for col in range(1, len(hardware_headers) + 1):
#         max_length = len(hardware_headers[col-1])
#         for row in range(2, row):
#             cell_value = ws_hardware.cell(row=row, column=col).value
#             if cell_value:
#                 max_length = max(max_length, len(str(cell_value)))
#         adjusted_width = min(max_length + 2, 30)
#         ws_hardware.column_dimensions[get_column_letter(col)].width = adjusted_width
    
#     # Create Employee Summary Sheet
#     ws_employee = wb.create_sheet("Employee Summary")
    
#     employee_headers = ['S.No', 'Employee Name', 'Email', 'Phone', 'Exam City', 'Hardware Count', 'Hardware Types']
    
#     for col, header in enumerate(employee_headers, 1):
#         cell = ws_employee.cell(row=1, column=col, value=header)
#         cell.font = header_font
#         cell.fill = header_fill
#         cell.alignment = center_alignment
#         cell.border = border
    
#     # Group hardware by employee
#     employee_data = {}
#     for assignment in assignments:
#         emp_id = assignment.employee.id
#         emp_name = assignment.employee.get_full_name() or assignment.employee.username
        
#         if emp_id not in employee_data:
#             employee_data[emp_id] = {
#                 'name': emp_name,
#                 'email': assignment.employee.email,
#                 'phone': assignment.employee.phone or 'N/A',
#                 'exam_city': assignment.exam_city,
#                 'hardware_count': 0,
#                 'hardware_types': set()
#             }
        
#         for item in assignment.hardwareassignmentitem_set.all():
#             hardware = item.hardware
#             employee_data[emp_id]['hardware_count'] += 1
#             hw_type = hardware.hardware_type.name if hardware.hardware_type else 'Unknown'
#             employee_data[emp_id]['hardware_types'].add(hw_type)
    
#     row = 2
#     serial_no = 1
#     for emp_id, data in employee_data.items():
#         ws_employee.cell(row=row, column=1, value=serial_no).border = border
#         ws_employee.cell(row=row, column=2, value=data['name']).border = border
#         ws_employee.cell(row=row, column=3, value=data['email']).border = border
#         ws_employee.cell(row=row, column=4, value=data['phone']).border = border
#         ws_employee.cell(row=row, column=5, value=data['exam_city']).border = border
#         ws_employee.cell(row=row, column=6, value=data['hardware_count']).border = border
#         ws_employee.cell(row=row, column=7, value=', '.join(data['hardware_types'])).border = border
#         row += 1
#         serial_no += 1
    
#     # Auto-adjust column widths for Employee Summary
#     for col in range(1, len(employee_headers) + 1):
#         max_length = len(employee_headers[col-1])
#         for row in range(2, row):
#             cell_value = ws_employee.cell(row=row, column=col).value
#             if cell_value:
#                 max_length = max(max_length, len(str(cell_value)))
#         adjusted_width = min(max_length + 2, 35)
#         ws_employee.column_dimensions[get_column_letter(col)].width = adjusted_width
    
#     # Auto-adjust column widths for Summary Sheet
#     for col in ['A', 'B']:
#         ws_summary.column_dimensions[col].width = 25
    
#     # Prepare response
#     timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#     filename = f"project_{project.project_id}_{timestamp}.xlsx"
    
#     response = HttpResponse(
#         content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
#     )
#     response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
#     wb.save(response)
#     return response

# views.py - Updated Export All Projects Excel with Audit Logging

import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.contrib import messages
from django.utils import timezone
from datetime import datetime
from hardware_management.utils.audit import create_audit_log, get_client_ip

@login_required
def export_all_projects_excel(request):
    """
    Export all projects summary to Excel
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Unauthorized export attempt by {request.user.username} (user_type: {request.user.user_type})",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to export projects.')
        return redirect('employee_dashboard')
    
    # ========== GET PROJECTS ==========
    projects = Project.objects.filter(created_by=request.user).order_by('-created_at')
    
    if not projects.exists():
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Export attempt by {request.user.username} - No projects found",
            target_user=request.user
        )
        messages.warning(request, 'No projects found to export.')
        return redirect('manager_projects')
    
    # ========== CREATE WORKBOOK ==========
    try:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "All Projects Summary"
        
        # ========== DEFINE STYLES ==========
        header_font = Font(bold=True, color="FFFFFF", size=12)
        header_fill = PatternFill(start_color="E04D00", end_color="E04D00", fill_type="solid")
        sub_header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
        success_fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
        warning_fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
        danger_fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
        info_fill = PatternFill(start_color="DDEBF7", end_color="DDEBF7", fill_type="solid")
        
        border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )
        center_alignment = Alignment(horizontal='center', vertical='center')
        left_alignment = Alignment(horizontal='left', vertical='center')
        
        # ========== TITLE SECTION ==========
        ws.merge_cells('A1:J1')
        title_cell = ws.cell(row=1, column=1, value="EDUQUITY HARDWARE MANAGEMENT SYSTEM")
        title_cell.font = Font(bold=True, size=16)
        title_cell.alignment = center_alignment
        
        ws.merge_cells('A2:J2')
        subtitle_cell = ws.cell(row=2, column=1, value=f"ALL PROJECTS SUMMARY REPORT")
        subtitle_cell.font = Font(size=12, italic=True)
        subtitle_cell.alignment = center_alignment
        
        ws.merge_cells('A3:J3')
        generated_cell = ws.cell(row=3, column=1, value=f"Generated by: {request.user.get_full_name() or request.user.username} | Date: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        generated_cell.font = Font(size=10)
        generated_cell.alignment = center_alignment
        
        # ========== HEADERS ==========
        headers = ['S.No', 'Project ID', 'Project Name', 'Location', 'Start Date', 'End Date', 
                   'Total Hardware', 'Hardware In Use', 'Employees Count', 'Created Date']
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=5, column=col, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = center_alignment
            cell.border = border
        
        # ========== DATA ==========
        row = 6
        serial_no = 1
        total_hardware_all = 0
        total_active_hardware_all = 0
        total_employees_all = 0
        total_projects_count = projects.count()
        
        for project in projects:
            # Get project statistics
            assignments = HardwareAssignment.objects.filter(
                project=project,
                assigned_by=request.user,
                actual_return_date__isnull=True
            )
            
            total_hardware = 0
            active_hardware = 0
            hardware_by_type = {}
            
            for assignment in assignments:
                items = assignment.hardwareassignmentitem_set.all()
                for item in items:
                    total_hardware += 1
                    if item.hardware.status == 'in_use':
                        active_hardware += 1
                    
                    # Track hardware by type
                    hw_type = item.hardware.hardware_type.name if item.hardware.hardware_type else 'Unknown'
                    hardware_by_type[hw_type] = hardware_by_type.get(hw_type, 0) + 1
            
            employee_count = assignments.values('employee').distinct().count()
            
            # Update totals
            total_hardware_all += total_hardware
            total_active_hardware_all += active_hardware
            total_employees_all += employee_count
            
            # Write row data
            ws.cell(row=row, column=1, value=serial_no).border = border
            ws.cell(row=row, column=2, value=project.project_id).border = border
            ws.cell(row=row, column=3, value=project.project_name).border = border
            ws.cell(row=row, column=4, value=project.location or 'Not specified').border = border
            
            start_date_cell = ws.cell(row=row, column=5, value=project.start_date.strftime("%d-%m-%Y") if project.start_date else 'N/A')
            start_date_cell.border = border
            start_date_cell.alignment = center_alignment
            
            end_date_cell = ws.cell(row=row, column=6, value=project.end_date.strftime("%d-%m-%Y") if project.end_date else 'N/A')
            end_date_cell.border = border
            end_date_cell.alignment = center_alignment
            
            # Color code based on date
            if project.end_date and project.end_date < datetime.now().date():
                for col in range(1, 11):
                    ws.cell(row=row, column=col).fill = danger_fill  # Expired projects
            
            ws.cell(row=row, column=7, value=total_hardware).border = border
            ws.cell(row=row, column=8, value=active_hardware).border = border
            
            # Color code hardware utilization
            if total_hardware > 0:
                utilization = (active_hardware / total_hardware) * 100
                if utilization >= 80:
                    ws.cell(row=row, column=8).fill = success_fill  # High utilization
                elif utilization >= 50:
                    ws.cell(row=row, column=8).fill = warning_fill  # Medium utilization
            
            ws.cell(row=row, column=9, value=employee_count).border = border
            
            created_date_cell = ws.cell(row=row, column=10, value=project.created_at.strftime("%d-%m-%Y %H:%M") if project.created_at else 'N/A')
            created_date_cell.border = border
            created_date_cell.alignment = center_alignment
            
            row += 1
            serial_no += 1
        
        # ========== SUMMARY SECTION ==========
        summary_row = row + 2
        
        # Summary header
        ws.merge_cells(f'A{summary_row}:J{summary_row}')
        summary_header = ws.cell(row=summary_row, column=1, value="📊 SUMMARY STATISTICS")
        summary_header.font = Font(bold=True, size=14, color="FFFFFF")
        summary_header.fill = PatternFill(start_color="2C3E50", end_color="2C3E50", fill_type="solid")
        summary_header.alignment = center_alignment
        summary_header.border = border
        
        summary_row += 1
        
        # Summary data
        summary_data = [
            ['Total Projects', total_projects_count],
            ['Total Hardware Items', total_hardware_all],
            ['Hardware In Use', total_active_hardware_all],
            ['Total Employees', total_employees_all],
            ['Average Hardware per Project', f"{round(total_hardware_all / total_projects_count, 1) if total_projects_count > 0 else 0}"],
            ['Average Employees per Project', f"{round(total_employees_all / total_projects_count, 1) if total_projects_count > 0 else 0}"],
            ['', ''],
            ['Exported By', request.user.get_full_name() or request.user.username],
            ['Exported On', datetime.now().strftime('%d/%m/%Y %H:%M:%S')],
            ['IP Address', get_client_ip(request)],
        ]
        
        for idx, (label, value) in enumerate(summary_data):
            current_row = summary_row + idx
            
            label_cell = ws.cell(row=current_row, column=1, value=label)
            label_cell.font = Font(bold=True)
            label_cell.fill = info_fill
            label_cell.border = border
            
            value_cell = ws.cell(row=current_row, column=2, value=value)
            value_cell.border = border
            value_cell.alignment = center_alignment
            
            # Highlight key metrics
            if label in ['Total Projects', 'Total Hardware Items', 'Hardware In Use', 'Total Employees']:
                value_cell.font = Font(bold=True, color="E04D00")
                value_cell.fill = success_fill
        
        # ========== AUTO-ADJUST COLUMN WIDTHS ==========
        for col in range(1, len(headers) + 1):
            max_length = len(headers[col-1])
            for row_idx in range(5, row):
                cell_value = ws.cell(row=row_idx, column=col).value
                if cell_value:
                    max_length = max(max_length, len(str(cell_value)))
            adjusted_width = min(max_length + 4, 30)
            ws.column_dimensions[get_column_letter(col)].width = adjusted_width
        
        # ========== FREEZE HEADER ROW ==========
        ws.freeze_panes = 'A6'
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="export_report",
            module="Export Reports",
            description=f"Manager {request.user.username} exported all projects summary ({total_projects_count} projects, {total_hardware_all} hardware items)",
            target_user=request.user,
            new_value={
                'project_count': total_projects_count,
                'hardware_count': total_hardware_all,
                'active_hardware': total_active_hardware_all,
                'employee_count': total_employees_all,
                'export_type': 'all_projects_summary'
            }
        )
        
        # ========== PREPARE RESPONSE ==========
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"All_Projects_Summary_{request.user.username}_{timestamp}.xlsx"
        
        response = HttpResponse(
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        wb.save(response)
        
        messages.success(request, f'✅ Projects summary exported successfully! ({total_projects_count} projects)')
        return response
        
    except Exception as e:
        # ========== ERROR LOGGING ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="system_error",
            module="Export Reports",
            description=f"Export failed for {request.user.username}: {str(e)}",
            target_user=request.user,
            new_value={'error': str(e)}
        )
        messages.error(request, f'Error exporting projects: {str(e)}')
        return redirect('manager_projects')
    
# @login_required
# def delete_project(request, project_id):
#     """Delete a project if it has no active assignments"""
#     if request.user.user_type != 'manager':
#         return redirect('employee_dashboard')
    
#     project = get_object_or_404(Project, id=project_id, created_by=request.user)
    
#     # Check if project has any active hardware assignments
#     has_active_assignments = HardwareAssignment.objects.filter(
#         project=project,
#         actual_return_date__isnull=True
#     ).exists()
    
#     if has_active_assignments:
#         messages.error(request, f'Cannot delete "{project.project_name}" because it has active hardware assignments. Please return all hardware first.')
#     else:
#         project_name = project.project_name
#         project.delete()
#         messages.success(request, f'Project "{project_name}" has been deleted successfully.')
    
#     return redirect('create_project')    
# Add this import at the top of your views.py
# views.py - Updated Project Management Views with Audit Logging

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q
from datetime import datetime
from hardware_management.utils.audit import create_audit_log, get_client_ip


# ============================================================
# MANAGER PROJECTS - VIEW
# ============================================================

@login_required
def manager_projects(request):
    """
    Manager view all projects they have access to
    Including: Global projects, projects assigned to them, and projects they created
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Project Management",
            description=f"Unauthorized access to projects by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to view projects.')
        return redirect('employee_dashboard')
    
    # ========== GET PROJECTS ==========
    all_projects = Project.objects.filter(is_active=True)
    
    # Filter projects the manager has access to
    projects = all_projects.filter(
        Q(assigned_manager__isnull=True) |      # Global projects
        Q(assigned_manager=request.user) |      # Assigned to this manager
        Q(created_by=request.user)              # Created by this manager
    ).distinct().order_by('-created_at')
    
    # ========== CHECK EXPORT REQUEST ==========
    if request.GET.get('export') == 'excel':
        # Log export request
        create_audit_log(
            request=request,
            user=request.user,
            action="export_report",
            module="Project Management",
            description=f"Manager {request.user.username} exporting projects to Excel ({projects.count()} projects)",
            target_user=request.user,
            new_value={'project_count': projects.count()}
        )
        return export_manager_projects_excel(request, projects)
    
    # ========== ENRICH PROJECTS WITH STATISTICS ==========
    for project in projects:
        # Get active assignments for this project
        assignments = HardwareAssignment.objects.filter(
            project=project,
            assigned_by=request.user,
            actual_return_date__isnull=True
        )
        
        project.total_hardware = 0
        project.active_hardware = 0
        project.employee_count = assignments.values('employee').distinct().count()
        project.assignment_count = assignments.count()
        project.is_global = project.assigned_manager is None
        
        for assignment in assignments:
            items = HardwareAssignmentItem.objects.filter(assignment=assignment)
            project.total_hardware += items.count()
            project.active_hardware += items.filter(
                hardware__status='in_use'
            ).count()
        
        project.has_assignments = assignments.exists()
    
    # ========== STATISTICS ==========
    total_projects = projects.count()
    active_projects = projects.filter(
        start_date__lte=timezone.now().date(),
        end_date__gte=timezone.now().date(),
        is_active=True
    ).count()
    completed_projects = projects.filter(
        end_date__lt=timezone.now().date()
    ).count()
    assigned_to_me = projects.filter(assigned_manager=request.user).count()
    global_projects = projects.filter(assigned_manager__isnull=True).count()
    
    # ========== AUDIT LOG ==========
    # Only log occasionally to avoid spam
    last_view = request.session.get('last_projects_view', 0)
    if last_view < timezone.now().timestamp() - 300:  # 5 minutes
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Project Management",
            description=f"Manager {request.user.username} viewed projects ({total_projects} total, {active_projects} active)",
            target_user=request.user,
            new_value={
                'total': total_projects,
                'active': active_projects,
                'completed': completed_projects,
                'assigned_to_me': assigned_to_me,
                'global': global_projects
            }
        )
        request.session['last_projects_view'] = timezone.now().timestamp()
    
    context = {
        'projects': projects,
        'total_projects': total_projects,
        'active_projects': active_projects,
        'completed_projects': completed_projects,
        'assigned_to_me': assigned_to_me,
        'global_projects': global_projects,
        'user': request.user,
    }
    return render(request, 'manager/projects.html', context)


# ============================================================
# PROJECT ASSIGNMENTS - VIEW
# ============================================================

@login_required
def project_assignments(request, project_id):
    """
    View all employees assigned to a specific project
    With audit logging and partial return tracking
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Project Management",
            description=f"Unauthorized access to project assignments by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET PROJECT ==========
    project = get_object_or_404(
        Project.objects.filter(
            Q(assigned_manager__isnull=True) |      # Global projects
            Q(created_by=request.user) |            # Created by this manager
            Q(assigned_manager=request.user)        # Assigned to this manager
        ),
        project_id=project_id
    )
    
    # ========== GET ACTIVE ASSIGNMENTS ==========
    assignments = HardwareAssignment.objects.filter(
        project=project,
        assigned_by=request.user,
        actual_return_date__isnull=True
    ).select_related('employee').prefetch_related(
        'hardwareassignmentitem_set__hardware',
        'hardwareassignmentitem_set__hardware__hardware_type',
        'hardwareassignmentitem_set__asset_entry'
    ).order_by('-assigned_date')
    
    # ========== PROCESS DATA ==========
    total_hardware = 0
    active_hardware = 0
    assigned_hardware = 0
    returned_hardware = 0
    current_assigned_hardware = 0
    hardware_by_type = {}
    employees_dict = {}
    hardware_details_list = []
    
    for assignment in assignments:
        hardware_items = assignment.hardwareassignmentitem_set.all()
        item_count = hardware_items.count()
        total_hardware += item_count
        exam_center_name = getattr(assignment, 'exam_center_name', None)
        returned_count = 0
        
        for item in hardware_items:
            hardware = item.hardware
            hw_type = hardware.hardware_type.name if hardware.hardware_type else 'Unknown'
            hardware_by_type[hw_type] = hardware_by_type.get(hw_type, 0) + 1
            
            # Check if item is returned (partial return)
            is_returned = hasattr(item, 'returned_at') and item.returned_at is not None
            
            if is_returned:
                returned_count += 1
                returned_hardware += 1
                item.is_returned = True
                item.returned_date = item.returned_at
            else:
                item.is_returned = False
                item.returned_date = None
                # ONLY count items that are NOT returned AND are assigned/in_use
                if hardware.status in ['in_use', 'assigned']:
                    current_assigned_hardware += 1
            
            if hardware.status == 'in_use':
                active_hardware += 1
            elif hardware.status == 'assigned':
                assigned_hardware += 1
            
            verification_status = 'Not Entered'
            verified = False
            try:
                asset_entry = item.asset_entry
                if asset_entry.verified:
                    verification_status = 'Verified'
                    verified = True
                else:
                    expected_asset = hardware.asset_number if hardware.asset_number else 'N/A'
                    if asset_entry.entered_asset_number == expected_asset:
                        verification_status = 'Matched - Pending'
                    else:
                        verification_status = 'Mismatch'
            except HardwareAssetEntry.DoesNotExist:
                pass
            
            hardware_details_list.append({
                'employee_name': assignment.employee.get_full_name() or assignment.employee.username,
                'employee_email': assignment.employee.email,
                'exam_city': assignment.exam_city,
                'exam_center_name': exam_center_name,
                'hardware_type': hw_type,
                'serial_number': hardware.serial_number,
                'model': hardware.model_name,
                'brand': hardware.brand or 'N/A',
                'status': 'In Use' if hardware.status == 'in_use' else 'Assigned',
                'asset_number': hardware.asset_number if hardware.asset_number else 'N/A',
                'entered_asset': asset_entry.entered_asset_number if hasattr(item, 'asset_entry') and item.asset_entry else 'N/A',
                'verification_status': verification_status,
                'verified': verified,
                'assigned_date': assignment.assigned_date.strftime('%d-%m-%Y'),
                'assignment_id': assignment.id,
                'returned_at': item.returned_at.strftime('%d-%m-%Y') if is_returned else None,
                'return_status': 'Returned' if is_returned else 'Pending Return'
            })
        
        # Employee verification status
        verification_status_emp = 'not_entered'
        verified_emp = False
        all_verified = True
        any_pending = False
        any_mismatch = False
        
        for item in hardware_items:
            try:
                asset_entry = item.asset_entry
                if asset_entry.verified:
                    pass
                else:
                    all_verified = False
                    any_pending = True
                    expected_asset = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
                    if asset_entry.entered_asset_number != expected_asset:
                        any_mismatch = True
            except HardwareAssetEntry.DoesNotExist:
                all_verified = False
        
        if all_verified and hardware_items.exists():
            verified_emp = True
            verification_status_emp = 'verified'
        elif any_mismatch:
            verification_status_emp = 'mismatch'
        elif any_pending:
            verification_status_emp = 'pending'
        
        # ========== ✅ CRITICAL FIX: Store UUID assignment_id ==========
        employee_id = assignment.employee.id
        if employee_id not in employees_dict:
            employees_dict[employee_id] = {
                'id': employee_id,
                'name': assignment.employee.get_full_name() or assignment.employee.username,
                'email': assignment.employee.email,
                'exam_city': assignment.exam_city,
                'exam_center_name': exam_center_name,
                'status': 'Active',
                'verified': verified_emp,
                'verification_status': verification_status_emp,
                'assignment_id': assignment.assignment_id,  # <--- CHANGED TO UUID STRING
                'hardware_count': item_count,
                'return_count': returned_count,
            }
        else:
            existing = employees_dict[employee_id]
            existing['hardware_count'] += item_count
            existing['return_count'] += returned_count
            if verification_status_emp == 'verified' and existing['verification_status'] != 'verified':
                existing['verified'] = True
                existing['verification_status'] = 'verified'
            elif verification_status_emp == 'mismatch':
                existing['verification_status'] = 'mismatch'
                existing['verified'] = False
            elif verification_status_emp == 'pending' and existing['verification_status'] == 'not_entered':
                existing['verification_status'] = 'pending'
    
    # Calculate return percentage for each employee
    for emp_id, emp_data in employees_dict.items():
        if emp_data['hardware_count'] > 0:
            emp_data['return_percentage'] = (emp_data['return_count'] / emp_data['hardware_count'] * 100)
        else:
            emp_data['return_percentage'] = 0
    
    # ========== CHECK EXPORT REQUEST ==========
    if request.GET.get('export') == 'excel':
        create_audit_log(
            request=request,
            user=request.user,
            action="export_report",
            module="Project Management",
            description=f"Manager {request.user.username} exporting project {project.project_name} assignments to Excel",
            target_user=request.user,
            new_value={'project': project.project_name, 'hardware_count': total_hardware}
        )
        return export_project_hardware_excel(
            request,
            project,
            hardware_details_list,
            total_hardware,
            active_hardware,
            assigned_hardware,
            hardware_by_type
        )
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="system_info",
        module="Project Management",
        description=f"Manager {request.user.username} viewed assignments for project {project.project_name} ({project.project_id})",
        target_user=request.user,
        new_value={
            'project': project.project_name,
            'project_id': project.project_id,
            'employees': len(employees_dict),
            'hardware': total_hardware,
            'returned_hardware': returned_hardware,
            'pending_return': total_hardware - returned_hardware,
            'current_assigned_hardware': current_assigned_hardware
        }
    )
    
    employees_list = list(employees_dict.values())
    is_global = project.assigned_manager is None
    
    context = {
        'project': project,
        'employees': employees_list,
        'total_hardware': total_hardware,
        'active_hardware': active_hardware,
        'assigned_hardware': assigned_hardware,
        'returned_hardware': returned_hardware,
        'pending_return_hardware': total_hardware - returned_hardware,
        'current_assigned_hardware': current_assigned_hardware,
        'hardware_by_type': hardware_by_type,
        'employee_count': len(employees_list),
        'is_global': is_global,
    }
    return render(request, 'manager/project_assignments.html', context)
# ============================================================
# EXPORT MANAGER PROJECTS EXCEL
# ============================================================

@login_required
def export_manager_projects_excel(request, projects):
    """
    Export all manager projects to Excel with hardware assignment details
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Unauthorized export attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to export projects.')
        return redirect('employee_dashboard')
    
    if not projects.exists():
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Export attempt by {request.user.username} - No projects found",
            target_user=request.user
        )
        messages.warning(request, 'No projects found to export.')
        return redirect('manager_projects')
    
    try:
        wb = openpyxl.Workbook()
        
        # Define styles
        header_font = Font(bold=True, color="FFFFFF", size=11)
        header_fill = PatternFill(start_color="E04D00", end_color="E04D00", fill_type="solid")
        sub_header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
        success_fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
        warning_fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
        danger_fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
        info_fill = PatternFill(start_color="DDEBF7", end_color="DDEBF7", fill_type="solid")
        
        border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )
        center_alignment = Alignment(horizontal='center', vertical='center')
        left_alignment = Alignment(horizontal='left', vertical='center')
        
        # Remove default sheet
        wb.remove(wb.active)
        
        # ========== SHEET 1: Projects Summary ==========
        ws_summary = wb.create_sheet("Projects Summary")
        
        # Title
        ws_summary.merge_cells('A1:I1')
        title_cell = ws_summary.cell(row=1, column=1, value="MANAGER PROJECTS SUMMARY REPORT")
        title_cell.font = Font(bold=True, size=14)
        title_cell.alignment = center_alignment
        
        ws_summary.merge_cells('A2:I2')
        subtitle_cell = ws_summary.cell(row=2, column=1, value=f"Generated on {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        subtitle_cell.font = Font(size=10, italic=True)
        subtitle_cell.alignment = center_alignment
        
        ws_summary.merge_cells('A3:I3')
        manager_cell = ws_summary.cell(row=3, column=1, value=f"Manager: {request.user.get_full_name() or request.user.username}")
        manager_cell.font = Font(size=10, bold=True)
        manager_cell.alignment = center_alignment
        
        # Headers
        summary_headers = ['S.No', 'Project ID', 'Project Name', 'Location', 'Start Date', 'End Date', 
                           'Employees', 'Assignments', 'Hardware Items']
        
        for col, header in enumerate(summary_headers, 1):
            cell = ws_summary.cell(row=5, column=col, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = center_alignment
            cell.border = border
        
        # Write project data
        row = 6
        total_hardware_all = 0
        total_employees_all = 0
        
        for idx, project in enumerate(projects, 1):
            ws_summary.cell(row=row, column=1, value=idx).border = border
            ws_summary.cell(row=row, column=2, value=project.project_id).border = border
            ws_summary.cell(row=row, column=3, value=project.project_name).border = border
            ws_summary.cell(row=row, column=4, value=project.location or 'Not specified').border = border
            ws_summary.cell(row=row, column=5, value=project.start_date.strftime("%d/%m/%Y") if project.start_date else 'N/A').border = border
            ws_summary.cell(row=row, column=6, value=project.end_date.strftime("%d/%m/%Y") if project.end_date else 'N/A').border = border
            ws_summary.cell(row=row, column=7, value=project.employee_count).border = border
            ws_summary.cell(row=row, column=8, value=project.assignment_count).border = border
            ws_summary.cell(row=row, column=9, value=project.total_hardware).border = border
            
            total_hardware_all += project.total_hardware
            total_employees_all += project.employee_count
            
            # Color code based on hardware count
            if project.total_hardware == 0:
                for col in range(1, 10):
                    ws_summary.cell(row=row, column=col).fill = warning_fill
            elif project.active_hardware == project.total_hardware and project.total_hardware > 0:
                for col in range(1, 10):
                    ws_summary.cell(row=row, column=col).fill = success_fill
            
            row += 1
        
        # Add summary row
        summary_row = row + 1
        ws_summary.merge_cells(f'A{summary_row}:F{summary_row}')
        summary_label = ws_summary.cell(row=summary_row, column=1, value="TOTALS")
        summary_label.font = Font(bold=True)
        summary_label.fill = info_fill
        summary_label.border = border
        
        ws_summary.cell(row=summary_row, column=7, value=total_employees_all).border = border
        ws_summary.cell(row=summary_row, column=9, value=total_hardware_all).border = border
        
        # Auto-adjust column widths
        for col in range(1, len(summary_headers) + 1):
            max_length = len(summary_headers[col-1])
            for row_idx in range(5, row + 1):
                cell_value = ws_summary.cell(row=row_idx, column=col).value
                if cell_value:
                    max_length = max(max_length, len(str(cell_value)))
            ws_summary.column_dimensions[get_column_letter(col)].width = min(max_length + 4, 30)
        
        # Freeze header
        ws_summary.freeze_panes = 'A6'
        
        # ========== SHEET 2: Project Details with Hardware ==========
        ws_details = wb.create_sheet("Project Hardware Details")
        
        detail_headers = ['Project ID', 'Project Name', 'Employee', 'Exam City', 'Exam Center', 
                          'Hardware Type', 'Asset Number', 'Serial Number', 'Status', 'Verification']
        
        for col, header in enumerate(detail_headers, 1):
            cell = ws_details.cell(row=1, column=col, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = center_alignment
            cell.border = border
        
        current_row = 2
        total_rows = 0
        
        for project in projects:
            assignments = HardwareAssignment.objects.filter(
                project=project,
                assigned_by=request.user,
                actual_return_date__isnull=True
            ).select_related('employee').prefetch_related(
                'hardwareassignmentitem_set__hardware__hardware_type',
                'hardwareassignmentitem_set__asset_entry'
            )
            
            if not assignments.exists():
                ws_details.cell(row=current_row, column=1, value=project.project_id).border = border
                ws_details.cell(row=current_row, column=2, value=project.project_name).border = border
                ws_details.cell(row=current_row, column=3, value="No assignments").border = border
                ws_details.cell(row=current_row, column=4, value="-").border = border
                ws_details.cell(row=current_row, column=5, value="-").border = border
                ws_details.cell(row=current_row, column=6, value="-").border = border
                ws_details.cell(row=current_row, column=7, value="-").border = border
                ws_details.cell(row=current_row, column=8, value="-").border = border
                ws_details.cell(row=current_row, column=9, value="No Hardware").border = border
                ws_details.cell(row=current_row, column=10, value="-").border = border
                
                for col in range(1, 11):
                    ws_details.cell(row=current_row, column=col).fill = warning_fill
                
                current_row += 1
                total_rows += 1
                continue
            
            # Project header
            ws_details.merge_cells(f'A{current_row}:J{current_row}')
            project_header = ws_details.cell(row=current_row, column=1, 
                                             value=f"📁 PROJECT: {project.project_id} - {project.project_name} ({project.location or 'No location'})")
            project_header.font = Font(bold=True, size=11, color="FFFFFF")
            project_header.fill = sub_header_fill
            project_header.alignment = left_alignment
            project_header.border = border
            current_row += 1
            total_rows += 1
            
            for assignment in assignments:
                items = HardwareAssignmentItem.objects.filter(assignment=assignment)
                
                # Employee header
                ws_details.merge_cells(f'A{current_row}:J{current_row}')
                emp_header = ws_details.cell(row=current_row, column=1, 
                                             value=f"👤 {assignment.employee.get_full_name() or assignment.employee.username}")
                emp_header.font = Font(bold=True, size=10)
                emp_header.fill = info_fill
                emp_header.alignment = left_alignment
                emp_header.border = border
                current_row += 1
                total_rows += 1
                
                for item in items:
                    hardware = item.hardware
                    
                    verification_status = 'Not Entered'
                    entered_asset = 'N/A'
                    try:
                        asset_entry = item.asset_entry
                        entered_asset = asset_entry.entered_asset_number
                        if asset_entry.verified:
                            verification_status = 'Verified'
                        else:
                            expected_asset = hardware.asset_number if hardware.asset_number else 'N/A'
                            if asset_entry.entered_asset_number == expected_asset:
                                verification_status = 'Matched - Pending'
                            else:
                                verification_status = 'Mismatch'
                    except HardwareAssetEntry.DoesNotExist:
                        pass
                    
                    ws_details.cell(row=current_row, column=1, value=project.project_id).border = border
                    ws_details.cell(row=current_row, column=2, value=project.project_name).border = border
                    ws_details.cell(row=current_row, column=3, 
                                   value=assignment.employee.get_full_name() or assignment.employee.username).border = border
                    ws_details.cell(row=current_row, column=4, value=assignment.exam_city or 'Not specified').border = border
                    ws_details.cell(row=current_row, column=5, 
                                   value=getattr(assignment, 'exam_center_name', 'Not specified') or 'Not specified').border = border
                    ws_details.cell(row=current_row, column=6, 
                                   value=hardware.hardware_type.name if hardware.hardware_type else 'Unknown').border = border
                    ws_details.cell(row=current_row, column=7, value=hardware.asset_number or 'N/A').border = border
                    ws_details.cell(row=current_row, column=8, value=hardware.serial_number).border = border
                    
                    status_cell = ws_details.cell(row=current_row, column=9, 
                                                 value='In Use' if hardware.status == 'in_use' else 'Assigned')
                    if hardware.status == 'in_use':
                        status_cell.fill = success_fill
                    else:
                        status_cell.fill = warning_fill
                    status_cell.border = border
                    
                    verify_cell = ws_details.cell(row=current_row, column=10, value=verification_status)
                    if verification_status == 'Verified':
                        verify_cell.fill = success_fill
                        verify_cell.font = Font(color="006100", bold=True)
                    elif verification_status == 'Matched - Pending':
                        verify_cell.fill = warning_fill
                        verify_cell.font = Font(color="9C5700", bold=True)
                    elif verification_status == 'Mismatch':
                        verify_cell.fill = danger_fill
                        verify_cell.font = Font(color="9C0006", bold=True)
                    else:
                        verify_cell.fill = danger_fill
                        verify_cell.font = Font(color="9C0006", bold=True)
                    verify_cell.border = border
                    
                    current_row += 1
                    total_rows += 1
            
            # Empty row between projects
            current_row += 1
        
        # Auto-adjust column widths
        for col in range(1, len(detail_headers) + 1):
            max_length = len(detail_headers[col-1])
            for row_idx in range(2, current_row):
                cell_value = ws_details.cell(row=row_idx, column=col).value
                if cell_value:
                    max_length = max(max_length, len(str(cell_value)))
            ws_details.column_dimensions[get_column_letter(col)].width = min(max_length + 4, 35)
        
        ws_details.freeze_panes = 'A2'
        
        # ========== SHEET 3: Statistics Dashboard ==========
        ws_stats = wb.create_sheet("Statistics")
        
        ws_stats.merge_cells('A1:D1')
        stats_title = ws_stats.cell(row=1, column=1, value="PROJECT STATISTICS DASHBOARD")
        stats_title.font = Font(bold=True, size=14)
        stats_title.alignment = center_alignment
        
        stats_data = [
            ['Metric', 'Value'],
            ['Total Projects', projects.count()],
            ['Active Projects', projects.filter(
                hardware_assignments__actual_return_date__isnull=True
            ).distinct().count()],
            ['Total Assignments', sum(p.assignment_count for p in projects)],
            ['Total Hardware Items', sum(p.total_hardware for p in projects)],
            ['Total Employees', sum(p.employee_count for p in projects)],
            ['', ''],
            ['Generated By', request.user.get_full_name() or request.user.username],
            ['Generated On', datetime.now().strftime("%d/%m/%Y %H:%M:%S")],
            ['IP Address', get_client_ip(request)],
        ]
        
        for idx, (label, value) in enumerate(stats_data, 1):
            ws_stats.cell(row=idx, column=1, value=label).font = Font(bold=True)
            ws_stats.cell(row=idx, column=2, value=value)
            
            if idx >= 2 and idx <= 6:
                ws_stats.cell(row=idx, column=2).fill = info_fill
        
        ws_stats.column_dimensions['A'].width = 25
        ws_stats.column_dimensions['B'].width = 20
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="export_report",
            module="Export Reports",
            description=f"Manager {request.user.username} exported complete projects report ({projects.count()} projects, {total_hardware_all} hardware items)",
            target_user=request.user,
            new_value={
                'project_count': projects.count(),
                'hardware_count': total_hardware_all,
                'employee_count': total_employees_all,
                'total_rows': total_rows
            }
        )
        
        # ========== PREPARE RESPONSE ==========
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"MANAGER_PROJECTS_REPORT_{request.user.username}_{timestamp}.xlsx"
        
        response = HttpResponse(
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        wb.save(response)
        messages.success(request, f'✅ Projects report exported successfully! ({projects.count()} projects)')
        return response
        
    except Exception as e:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_error",
            module="Export Reports",
            description=f"Export failed for {request.user.username}: {str(e)}",
            target_user=request.user,
            new_value={'error': str(e)}
        )
        messages.error(request, f'Error exporting projects: {str(e)}')
        return redirect('manager_projects')


# ============================================================
# EXPORT PROJECT HARDWARE EXCEL
# ============================================================
@login_required
def export_project_hardware_excel(request, project, hardware_details_list, total_hardware, active_hardware, assigned_hardware, hardware_by_type):
    """
    Export project hardware details to Excel with employee-wise hardware details
    Showing ONLY currently assigned hardware (excluding removed and returned items)
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Unauthorized export attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to export project hardware.')
        return redirect('employee_dashboard')
    
    if not hardware_details_list:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Export attempt by {request.user.username} - No hardware found for project {project.project_name}",
            target_user=request.user,
            new_value={'project': project.project_name}
        )
        messages.warning(request, 'No hardware found to export for this project.')
        return redirect('project_assignments', project_id=project.id)
    
    try:
        wb = openpyxl.Workbook()
        
        # Define styles
        header_font = Font(bold=True, color="FFFFFF", size=12)
        header_fill = PatternFill(start_color="E04D00", end_color="E04D00", fill_type="solid")
        subheader_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
        success_fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
        warning_fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
        danger_fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
        info_fill = PatternFill(start_color="DDEBF7", end_color="DDEBF7", fill_type="solid")
        partial_fill = PatternFill(start_color="FFD966", end_color="FFD966", fill_type="solid")
        returned_fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
        
        border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )
        center_alignment = Alignment(horizontal='center', vertical='center')
        left_alignment = Alignment(horizontal='left', vertical='center')
        
        # Remove default sheet
        wb.remove(wb.active)
        
        # ========== FILTER: Get only CURRENT active assignments (not returned/removed) ==========
        active_assignments = HardwareAssignment.objects.filter(
            project=project,
            assigned_by=request.user,
            actual_return_date__isnull=True  # Only active assignments
        ).select_related('employee')
        
        # Get hardware items from active assignments only
        # EXCLUDE items that have been returned or removed
        active_hardware_items = []
        active_asset_numbers = set()
        removed_assets = []
        
        for assignment in active_assignments:
            items = HardwareAssignmentItem.objects.filter(
                assignment=assignment
            ).select_related('hardware__hardware_type')
            
            for item in items:
                asset_number = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
                
                # ✅ SKIP if item is already returned
                if hasattr(item, 'returned_at') and item.returned_at is not None:
                    removed_assets.append({
                        'employee': assignment.employee.get_full_name() or assignment.employee.username,
                        'asset': asset_number,
                        'type': item.hardware.hardware_type.name if item.hardware.hardware_type else 'Unknown',
                        'reason': 'Returned'
                    })
                    continue
                
                # Skip duplicates - only show each asset once (in its current assignment)
                if asset_number in active_asset_numbers:
                    continue
                active_asset_numbers.add(asset_number)
                
                # Get verification status
                verification_status = 'Not Entered'
                entered_asset = None
                is_verified = False
                try:
                    asset_entry = item.asset_entry
                    entered_asset = asset_entry.entered_asset_number
                    if asset_entry.verified:
                        verification_status = 'Verified'
                        is_verified = True
                    else:
                        expected_asset = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
                        if asset_entry.entered_asset_number == expected_asset:
                            verification_status = 'Matched - Pending'
                        else:
                            verification_status = 'Mismatch'
                except HardwareAssetEntry.DoesNotExist:
                    pass
                
                active_hardware_items.append({
                    'assignment': assignment,
                    'item': item,
                    'hardware': item.hardware,
                    'asset_number': asset_number,
                    'serial_number': item.hardware.serial_number,
                    'hardware_type': item.hardware.hardware_type.name if item.hardware.hardware_type else 'Unknown',
                    'model': item.hardware.model_name or 'N/A',
                    'brand': item.hardware.brand or 'N/A',
                    'status': 'In Use' if item.hardware.status == 'in_use' else 'Assigned',
                    'employee_name': assignment.employee.get_full_name() or assignment.employee.username,
                    'employee_email': assignment.employee.email,
                    'exam_city': assignment.exam_city or 'Not specified',
                    'exam_center_name': getattr(assignment, 'exam_center_name', 'Not specified') or 'Not specified',
                    'assignment_id': assignment.id,
                    'verification_status': verification_status,
                    'entered_asset': entered_asset,
                    'is_verified': is_verified,
                    'returned_at': None,
                    'return_status': 'Pending Return'
                })
        
        # ========== SHEET 1: Employee-Wise Hardware Details ==========
        ws_employee = wb.create_sheet("Employee Wise Hardware")
        
        # Group hardware by employee (only active assignments)
        employee_hardware = {}
        for hardware in active_hardware_items:
            emp_name = hardware['employee_name']
            if emp_name not in employee_hardware:
                employee_hardware[emp_name] = {
                    'email': hardware['employee_email'],
                    'exam_city': hardware['exam_city'],
                    'exam_center_name': hardware.get('exam_center_name', 'Not specified'),
                    'hardware_list': []
                }
            employee_hardware[emp_name]['hardware_list'].append(hardware)
        
        emp_headers = ['S.No', 'Employee Name', 'Email', 'Exam City', 'Exam Center', 
                       'Hardware Type', 'Asset Number', 'Serial Number', 'Model', 'Brand', 
                       'Status', 'Verification', 'Return Status']
        
        for col, header in enumerate(emp_headers, 1):
            cell = ws_employee.cell(row=1, column=col, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = center_alignment
            cell.border = border
        
        row = 2
        sno = 1
        total_verified = 0
        total_items = 0
        total_matched = 0
        total_mismatch = 0
        total_not_entered = 0
        
        for emp_name, emp_data in sorted(employee_hardware.items()):
            ws_employee.merge_cells(f'A{row}:M{row}')
            cell = ws_employee.cell(row=row, column=1, value=f"👤 EMPLOYEE: {emp_name}")
            cell.font = Font(bold=True, size=12, color="FFFFFF")
            cell.fill = subheader_fill
            cell.alignment = left_alignment
            cell.border = border
            row += 1
            
            ws_employee.cell(row=row, column=1, value="").border = border
            ws_employee.cell(row=row, column=2, value=emp_name).font = Font(bold=True)
            ws_employee.cell(row=row, column=3, value=emp_data['email']).border = border
            ws_employee.cell(row=row, column=4, value=emp_data['exam_city']).border = border
            ws_employee.cell(row=row, column=5, value=emp_data.get('exam_center_name', 'Not specified')).border = border
            for col in range(6, 14):
                ws_employee.cell(row=row, column=col, value="").border = border
            
            for col in range(1, 14):
                ws_employee.cell(row=row, column=col).fill = info_fill
            row += 1
            
            # Hardware headers
            hw_headers = ['', '', '', '', '', 'Hardware Type', 'Asset Number', 'Serial Number', 'Model', 'Brand', 'Status', 'Verification', 'Return Status']
            for col, header in enumerate(hw_headers, 1):
                cell = ws_employee.cell(row=row, column=col, value=header)
                cell.font = Font(bold=True)
                cell.fill = PatternFill(start_color="FDE4D3", end_color="FDE4D3", fill_type="solid")
                cell.alignment = center_alignment
                cell.border = border
            row += 1
            
            for hardware in emp_data['hardware_list']:
                total_items += 1
                if hardware['verification_status'] == 'Verified':
                    total_verified += 1
                elif hardware['verification_status'] == 'Matched - Pending':
                    total_matched += 1
                elif hardware['verification_status'] == 'Mismatch':
                    total_mismatch += 1
                else:
                    total_not_entered += 1
                
                ws_employee.cell(row=row, column=1, value=sno).border = border
                ws_employee.cell(row=row, column=2, value="").border = border
                ws_employee.cell(row=row, column=3, value="").border = border
                ws_employee.cell(row=row, column=4, value="").border = border
                ws_employee.cell(row=row, column=5, value="").border = border
                ws_employee.cell(row=row, column=6, value=hardware['hardware_type']).border = border
                
                asset_cell = ws_employee.cell(row=row, column=7, value=hardware['asset_number'])
                entered_asset = hardware.get('entered_asset', 'N/A')
                if entered_asset and entered_asset != 'N/A' and entered_asset != 'Not Entered':
                    if entered_asset == hardware['asset_number']:
                        asset_cell.fill = success_fill
                        asset_cell.font = Font(color="006100", bold=True)
                    else:
                        asset_cell.fill = danger_fill
                        asset_cell.font = Font(color="9C0006", bold=True)
                asset_cell.border = border
                
                ws_employee.cell(row=row, column=8, value=hardware['serial_number']).border = border
                ws_employee.cell(row=row, column=9, value=hardware.get('model', 'N/A')).border = border
                ws_employee.cell(row=row, column=10, value=hardware.get('brand', 'N/A')).border = border
                
                status_cell = ws_employee.cell(row=row, column=11, value=hardware['status'])
                if hardware['status'] == 'In Use':
                    status_cell.fill = success_fill
                    status_cell.font = Font(color="006100", bold=True)
                else:
                    status_cell.fill = warning_fill
                    status_cell.font = Font(color="9C5700", bold=True)
                status_cell.border = border
                
                verify_cell = ws_employee.cell(row=row, column=12, value=hardware['verification_status'])
                if hardware['verification_status'] == 'Verified':
                    verify_cell.fill = success_fill
                    verify_cell.font = Font(color="006100", bold=True)
                elif hardware['verification_status'] == 'Matched - Pending':
                    verify_cell.fill = warning_fill
                    verify_cell.font = Font(color="9C5700", bold=True)
                elif hardware['verification_status'] == 'Mismatch':
                    verify_cell.fill = danger_fill
                    verify_cell.font = Font(color="9C0006", bold=True)
                else:
                    verify_cell.fill = danger_fill
                    verify_cell.font = Font(color="9C0006", bold=True)
                verify_cell.border = border
                
                # Return Status
                return_cell = ws_employee.cell(row=row, column=13, value="Pending Return")
                return_cell.fill = warning_fill
                return_cell.font = Font(color="9C5700", bold=True)
                return_cell.border = border
                
                row += 1
                sno += 1
            
            # Employee summary with verification stats
            total_items_emp = len(emp_data['hardware_list'])
            emp_verified = sum(1 for h in emp_data['hardware_list'] if h['verification_status'] == 'Verified')
            emp_matched = sum(1 for h in emp_data['hardware_list'] if h['verification_status'] == 'Matched - Pending')
            emp_mismatch = sum(1 for h in emp_data['hardware_list'] if h['verification_status'] == 'Mismatch')
            emp_not_entered = total_items_emp - emp_verified - emp_matched - emp_mismatch
            emp_pending_return = total_items_emp  # All items in active assignments are pending return
            
            ws_employee.merge_cells(f'A{row}:E{row}')
            ws_employee.cell(row=row, column=1, value=f"📊 Summary for {emp_name}:").font = Font(bold=True)
            
            ws_employee.merge_cells(f'F{row}:M{row}')
            summary_text = f"Total: {total_items_emp} | Verified: {emp_verified} | Matched: {emp_matched} | Mismatch: {emp_mismatch} | Not Entered: {emp_not_entered} | Pending Return: {emp_pending_return}"
            ws_employee.cell(row=row, column=6, value=summary_text)
            
            for col in range(1, 14):
                ws_employee.cell(row=row, column=col).fill = info_fill
                ws_employee.cell(row=row, column=col).border = border
            
            row += 2
        
        # Auto-adjust column widths
        for col in range(1, len(emp_headers) + 1):
            max_length = len(emp_headers[col-1])
            for row_idx in range(2, row):
                cell_value = ws_employee.cell(row=row_idx, column=col).value
                if cell_value:
                    max_length = max(max_length, len(str(cell_value)))
            adjusted_width = min(max_length + 3, 30)
            ws_employee.column_dimensions[get_column_letter(col)].width = adjusted_width
        
        ws_employee.freeze_panes = 'A2'
        
        # ========== SHEET 2: Project Summary ==========
        ws_summary = wb.create_sheet("Project Summary")
        
        all_hardware_types = sorted(set([hw['hardware_type'] for hw in active_hardware_items]))
        verified_count = sum(1 for h in active_hardware_items if h['verification_status'] == 'Verified')
        matched_count = sum(1 for h in active_hardware_items if h['verification_status'] == 'Matched - Pending')
        mismatch_count = sum(1 for h in active_hardware_items if h['verification_status'] == 'Mismatch')
        not_entered_count = sum(1 for h in active_hardware_items if h['verification_status'] == 'Not Entered')
        total_items_count = len(active_hardware_items)
        
        ws_summary.merge_cells('A1:C1')
        ws_summary['A1'] = f'PROJECT SUMMARY - {project.project_name}'
        ws_summary['A1'].font = Font(bold=True, size=14)
        ws_summary['A1'].alignment = center_alignment
        
        ws_summary.merge_cells('A2:C2')
        ws_summary['A2'] = f'Generated on: {datetime.now().strftime("%d-%m-%Y at %H:%M:%S")}'
        ws_summary['A2'].alignment = center_alignment
        ws_summary['A2'].font = Font(italic=True, size=10)
        
        # Project Information
        ws_summary.merge_cells('A4:C4')
        ws_summary['A4'] = '📋 PROJECT INFORMATION'
        ws_summary['A4'].font = Font(bold=True, size=12, color="FFFFFF")
        ws_summary['A4'].fill = subheader_fill
        ws_summary['A4'].alignment = center_alignment
        
        project_info = [
            ['Project ID', project.project_id],
            ['Project Name', project.project_name],
            ['Location', project.location or 'Not specified'],
            ['Start Date', project.start_date.strftime("%d-%m-%Y") if project.start_date else 'N/A'],
            ['End Date', project.end_date.strftime("%d-%m-%Y") if project.end_date else 'N/A'],
            ['Duration', f'{(project.end_date - project.start_date).days} days' if project.end_date and project.start_date else 'N/A'],
            ['Created By', project.created_by.get_full_name() or project.created_by.username],
        ]
        
        row = 5
        for info in project_info:
            ws_summary.cell(row=row, column=1, value=info[0]).font = Font(bold=True)
            ws_summary.cell(row=row, column=1).fill = info_fill
            ws_summary.cell(row=row, column=2, value=info[1])
            ws_summary.merge_cells(f'B{row}:C{row}')
            for col in range(1, 4):
                ws_summary.cell(row=row, column=col).border = border
            row += 1
        
        # Hardware Statistics
        row += 1
        ws_summary.merge_cells(f'A{row}:C{row}')
        ws_summary[f'A{row}'] = '🔧 HARDWARE STATISTICS'
        ws_summary[f'A{row}'].font = Font(bold=True, size=12, color="FFFFFF")
        ws_summary[f'A{row}'].fill = subheader_fill
        ws_summary[f'A{row}'].alignment = center_alignment
        row += 1
        
        hardware_stats = [
            ['Total Hardware Items (Current)', total_items_count],
            ['Unique Hardware Types', len(all_hardware_types)],
            ['Total Employees', len(employee_hardware)],
            ['', ''],
            ['Hardware In Use', active_hardware],
            ['Hardware Assigned', assigned_hardware],
            ['', ''],
            ['📊 Verification Status', ''],
            ['✅ Verified', verified_count],
            ['🔄 Matched - Pending', matched_count],
            ['❌ Mismatch', mismatch_count],
            ['📝 Not Entered', not_entered_count],
            ['📈 Verification Rate', f"{(verified_count / total_items_count * 100):.1f}%" if total_items_count else '0%'],
            ['', ''],
            ['🔄 Return Status', ''],
            ['⏳ Pending Return', total_items_count],
        ]
        
        for stat in hardware_stats:
            if stat[0]:
                ws_summary.cell(row=row, column=1, value=stat[0]).font = Font(bold=True)
                ws_summary.cell(row=row, column=1).fill = info_fill
                ws_summary.cell(row=row, column=2, value=stat[1])
                ws_summary.merge_cells(f'C{row}:C{row}')
                for col in range(1, 4):
                    ws_summary.cell(row=row, column=col).border = border
                row += 1
            else:
                row += 1
        
        # Hardware by Type
        row += 1
        ws_summary.merge_cells(f'A{row}:C{row}')
        ws_summary[f'A{row}'] = '📊 HARDWARE BY TYPE'
        ws_summary[f'A{row}'].font = Font(bold=True, size=12, color="FFFFFF")
        ws_summary[f'A{row}'].fill = subheader_fill
        ws_summary[f'A{row}'].alignment = center_alignment
        row += 1
        
        ws_summary.cell(row=row, column=1, value="Hardware Type").font = Font(bold=True)
        ws_summary.cell(row=row, column=2, value="Count").font = Font(bold=True)
        ws_summary.cell(row=row, column=3, value="Percentage").font = Font(bold=True)
        for col in range(1, 4):
            ws_summary.cell(row=row, column=col).fill = header_fill
            ws_summary.cell(row=row, column=col).font = header_font
            ws_summary.cell(row=row, column=col).border = border
        row += 1
        
        hw_type_counts = {}
        for hw in active_hardware_items:
            hw_type_counts[hw['hardware_type']] = hw_type_counts.get(hw['hardware_type'], 0) + 1
        
        for hw_type, count in sorted(hw_type_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_items_count * 100) if total_items_count else 0
            ws_summary.cell(row=row, column=1, value=hw_type).border = border
            ws_summary.cell(row=row, column=2, value=count).border = border
            ws_summary.cell(row=row, column=3, value=f'{percentage:.1f}%').border = border
            row += 1
        
        ws_summary.column_dimensions['A'].width = 25
        ws_summary.column_dimensions['B'].width = 20
        ws_summary.column_dimensions['C'].width = 20
        
        # ========== SHEET 3: Asset Summary ==========
        ws_asset = wb.create_sheet("Asset Summary")
        
        asset_headers = ['Employee', 'Assignment ID', 'Hardware Type', 'Asset Number', 'Entered Asset', 'Status', 'Verification']
        
        for col, header in enumerate(asset_headers, 1):
            cell = ws_asset.cell(row=1, column=col, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = center_alignment
            cell.border = border
        
        row = 2
        for hardware in active_hardware_items:
            ws_asset.cell(row=row, column=1, value=hardware['employee_name']).border = border
            ws_asset.cell(row=row, column=2, value=hardware.get('assignment_id', 'N/A')).border = border
            ws_asset.cell(row=row, column=3, value=hardware['hardware_type']).border = border
            
            asset_cell = ws_asset.cell(row=row, column=4, value=hardware['asset_number'])
            entered_asset = hardware.get('entered_asset', 'N/A')
            
            if entered_asset and entered_asset != 'N/A' and entered_asset != 'Not Entered':
                if entered_asset == hardware['asset_number']:
                    asset_cell.fill = success_fill
                    asset_cell.font = Font(color="006100", bold=True)
                else:
                    asset_cell.fill = danger_fill
                    asset_cell.font = Font(color="9C0006", bold=True)
            asset_cell.border = border
            
            ws_asset.cell(row=row, column=5, value=entered_asset or 'N/A').border = border
            
            status_cell = ws_asset.cell(row=row, column=6, value=hardware['status'])
            if hardware['status'] == 'In Use':
                status_cell.fill = success_fill
            else:
                status_cell.fill = warning_fill
            status_cell.border = border
            
            verify_cell = ws_asset.cell(row=row, column=7, value=hardware['verification_status'])
            if hardware['verification_status'] == 'Verified':
                verify_cell.fill = success_fill
            elif hardware['verification_status'] == 'Matched - Pending':
                verify_cell.fill = warning_fill
            elif hardware['verification_status'] == 'Mismatch':
                verify_cell.fill = danger_fill
            else:
                verify_cell.fill = danger_fill
            verify_cell.border = border
            
            row += 1
        
        for col in range(1, len(asset_headers) + 1):
            max_length = len(asset_headers[col-1])
            for row_idx in range(2, row):
                cell_value = ws_asset.cell(row=row_idx, column=col).value
                if cell_value:
                    max_length = max(max_length, len(str(cell_value)))
            ws_asset.column_dimensions[get_column_letter(col)].width = min(max_length + 3, 30)
        
        # ========== SHEET 4: Removed/Returned Items Log ==========
        if removed_assets:
            ws_removed = wb.create_sheet("Removed Items Log")
            
            removed_headers = ['Employee', 'Hardware Type', 'Asset Number', 'Removal Reason']
            
            for col, header in enumerate(removed_headers, 1):
                cell = ws_removed.cell(row=1, column=col, value=header)
                cell.font = header_font
                cell.fill = PatternFill(start_color="DC3545", end_color="DC3545", fill_type="solid")
                cell.alignment = center_alignment
                cell.border = border
            
            row = 2
            for removed in removed_assets:
                ws_removed.cell(row=row, column=1, value=removed['employee']).border = border
                ws_removed.cell(row=row, column=2, value=removed['type']).border = border
                ws_removed.cell(row=row, column=3, value=removed['asset']).border = border
                ws_removed.cell(row=row, column=4, value=removed['reason']).border = border
                
                for col in range(1, 5):
                    ws_removed.cell(row=row, column=col).fill = danger_fill
                
                row += 1
            
            for col in range(1, len(removed_headers) + 1):
                max_length = len(removed_headers[col-1])
                for row_idx in range(2, row):
                    cell_value = ws_removed.cell(row=row_idx, column=col).value
                    if cell_value:
                        max_length = max(max_length, len(str(cell_value)))
                ws_removed.column_dimensions[get_column_letter(col)].width = min(max_length + 3, 30)
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="export_report",
            module="Export Reports",
            description=f"Manager {request.user.username} exported project {project.project_name} hardware report ({len(active_hardware_items)} current items, {len(employee_hardware)} employees)",
            target_user=request.user,
            new_value={
                'project': project.project_name,
                'project_id': project.project_id,
                'current_hardware_count': len(active_hardware_items),
                'employee_count': len(employee_hardware),
                'verified_count': verified_count,
                'matched_count': matched_count,
                'mismatch_count': mismatch_count,
                'not_entered_count': not_entered_count,
                'removed_items_count': len(removed_assets)
            }
        )
        
        # ========== PREPARE RESPONSE ==========
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"PROJECT_{project.project_name.replace(' ', '_')}_CURRENT_HARDWARE_{timestamp}.xlsx"
        
        response = HttpResponse(
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        wb.save(response)
        messages.success(request, f'✅ Project hardware report exported successfully! ({len(active_hardware_items)} current items)')
        return response
        
    except Exception as e:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_error",
            module="Export Reports",
            description=f"Project hardware export failed for {request.user.username}: {str(e)}",
            target_user=request.user,
            new_value={'project': project.project_name, 'error': str(e)}
        )
        messages.error(request, f'Error exporting project hardware: {str(e)}')
        return redirect('project_assignments', project_id=project.id)
    
from django.core.paginator import Paginator
from django.db.models import Q, Count, Case, When, Value, IntegerField
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.http import HttpResponse
from datetime import datetime
from hardware_management.utils.audit import create_audit_log, get_client_ip


# ============================================================
# MANAGE HARDWARE - MANAGER VIEW
# ============================================================

@login_required
def manage_hardware(request):
    """
    Manager view to manage hardware inventory in their branch
    ✅ FIX: Uses branch_location instead of created_by
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Unauthorized access to hardware management by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET HARDWARE ==========
    hardware_types = HardwareType.objects.all()
    
    # ✅ FIX: Filter by branch_location, not created_by
    # This ensures transferred hardware appears in the receiver's branch
    hardware_items = Hardware.objects.filter(branch_location=request.user.branch_location)
    
    # Get count of items per type
    hardware_items_count_list = hardware_items.values('hardware_type').annotate(
        count=Count('id')
    ).order_by()
    
    # ========== SEARCH AND FILTERS ==========
    search_query = request.GET.get('search', '')
    if search_query:
        hardware_items = hardware_items.filter(
            Q(asset_number__icontains=search_query) |
            Q(serial_number__icontains=search_query) |
            Q(hardware_type__name__icontains=search_query) |
            Q(model_name__icontains=search_query) |
            Q(brand__icontains=search_query)
        )
    
    type_filter = request.GET.get('type', '')
    if type_filter and type_filter != 'all':
        hardware_items = hardware_items.filter(hardware_type_id=type_filter)
    
    status_filter = request.GET.get('status', '')
    if status_filter and status_filter != 'all':
        hardware_items = hardware_items.filter(status=status_filter)
    
    # ========== GET REQUESTS ==========
    hardware_ids = hardware_items.values_list('id', flat=True)
    
    pending_requests_list = HardwareRequest.objects.filter(
        hardware_id__in=hardware_ids,
        status='pending'
    ).select_related('hardware', 'requested_by').order_by('-created_at')
    
    pending_requests = pending_requests_list.count()
    
    processed_requests = HardwareRequest.objects.filter(
        hardware_id__in=hardware_ids
    ).exclude(status='pending').select_related(
        'hardware', 'requested_by', 'reviewed_by'
    ).order_by('-updated_at')[:5]
    
    pending_update_ids = HardwareRequest.objects.filter(
        hardware_id__in=hardware_ids,
        request_type='update',
        status='pending'
    ).values_list('hardware_id', flat=True)
    
    pending_delete_ids = HardwareRequest.objects.filter(
        hardware_id__in=hardware_ids,
        request_type='delete',
        status='pending'
    ).values_list('hardware_id', flat=True)
    
    hardware_requests_list = HardwareRequest.objects.filter(
        hardware_id__in=hardware_ids
    ).select_related('requested_by', 'reviewed_by').order_by('-created_at')
    
    # ========== STATISTICS ==========
    available_count = hardware_items.filter(status='available').count()
    assigned_count = hardware_items.filter(status='assigned').count()
    in_use_count = hardware_items.filter(status='in_use').count()
    maintenance_count = hardware_items.filter(status='maintenance').count()
    retired_count = hardware_items.filter(status='retired').count()
    total_count = hardware_items.count()
    
    # ========== HARDWARE BY BRANCH (For debugging) ==========
    # Show which branch each hardware belongs to
    hardware_with_branch = hardware_items.values('branch_location').annotate(
        count=Count('id')
    ).order_by('branch_location')
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_hardware_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Hardware Management",
            description=f"Manager {request.user.username} viewed hardware inventory ({total_count} items in {request.user.branch_location} branch, {pending_requests} pending requests)",
            target_user=request.user,
            new_value={
                'total': total_count,
                'available': available_count,
                'assigned': assigned_count,
                'in_use': in_use_count,
                'maintenance': maintenance_count,
                'retired': retired_count,
                'pending_requests': pending_requests,
                'branch': request.user.branch_location,
                'filters': {
                    'search': search_query,
                    'type': type_filter,
                    'status': status_filter
                }
            }
        )
        request.session['last_hardware_view'] = timezone.now().timestamp()
    
    # ========== PAGINATION ==========
    paginator = Paginator(hardware_items, 10)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'hardware_types': hardware_types,
        'hardware_items': page_obj,
        'hardware_items_count_list': hardware_items_count_list,
        'available_count': available_count,
        'assigned_count': assigned_count,
        'in_use_count': in_use_count,
        'maintenance_count': maintenance_count,
        'retired_count': retired_count,
        'total_count': total_count,
        'search_query': search_query,
        'type_filter': type_filter,
        'status_filter': status_filter,
        'paginator': paginator,
        'page_obj': page_obj,
        'pending_requests': pending_requests,
        'pending_requests_list': pending_requests_list,
        'processed_requests': processed_requests,
        'pending_update_ids': list(pending_update_ids),
        'pending_delete_ids': list(pending_delete_ids),
        'hardware_requests_list': hardware_requests_list,
        'hardware_with_branch': hardware_with_branch,
        'current_branch': request.user.branch_location,
    }
    return render(request, 'manager/manage_hardware.html', context)

@login_required
def manager_active_hardware(request):
    """
    Manager view: Display all hardware currently assigned to active employees.
    Shows Employee Name, Exam City, and Exam Center.
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Unauthorized access by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET HARDWARE ==========
    # Get all hardware located in this manager's branch that are currently active
    hardware_items = Hardware.objects.filter(
        branch_location=request.user.branch_location,
        status__in=['in_use', 'assigned']
    ).select_related('hardware_type')
    
    # ========== SEARCH AND FILTERS ==========
    search_query = request.GET.get('search', '')
    if search_query:
        hardware_items = hardware_items.filter(
            Q(asset_number__icontains=search_query) |
            Q(serial_number__icontains=search_query) |
            Q(hardware_type__name__icontains=search_query) |
            Q(model_name__icontains=search_query)
        )
    
    type_filter = request.GET.get('type', '')
    if type_filter and type_filter != 'all':
        hardware_items = hardware_items.filter(hardware_type_id=type_filter)
    
    # ========== ENRICH WITH EMPLOYEE & EXAM DATA ==========
    enriched_hardware = []
    
    for hardware in hardware_items:
        # Find the current active assignment for this hardware
        assignment_item = HardwareAssignmentItem.objects.filter(
            hardware=hardware,
            assignment__actual_return_date__isnull=True
        ).select_related(
            'assignment',
            'assignment__employee',
            'assignment__project'
        ).first()
        
        employee_name = '-'
        exam_city = '-'
        exam_center = '-'
        assignment_id = None
        
        if assignment_item:
            assignment = assignment_item.assignment
            employee = assignment.employee
            assignment_id = assignment.assignment_id
            
            employee_name = employee.get_full_name() or employee.username
            exam_city = assignment.exam_city or '-'
            exam_center = getattr(assignment, 'exam_center_name', None) or '-'
        
        enriched_hardware.append({
            'hardware': hardware,
            'employee_name': employee_name,
            'exam_city': exam_city,
            'exam_center': exam_center,
            'assignment_id': assignment_id,
        })
    
    # ========== STATISTICS ==========
    total_items = hardware_items.count()
    in_use_count = hardware_items.filter(status='in_use').count()
    assigned_count = hardware_items.filter(status='assigned').count()
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_active_hardware_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Hardware Management",
            description=f"Manager {request.user.username} viewed active hardware inventory ({total_items} items)",
            target_user=request.user,
            new_value={
                'total': total_items,
                'in_use': in_use_count,
                'assigned': assigned_count,
                'filters': {
                    'search': search_query,
                    'type': type_filter
                }
            }
        )
        request.session['last_active_hardware_view'] = timezone.now().timestamp()
    
    # ========== PAGINATION ==========
    paginator = Paginator(enriched_hardware, 10)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'enriched_hardware': page_obj,
        'paginator': paginator,
        'page_obj': page_obj,
        'total_items': total_items,
        'in_use_count': in_use_count,
        'assigned_count': assigned_count,
        'search_query': search_query,
        'type_filter': type_filter,
        'current_branch': request.user.branch_location,
    }
    return render(request, 'manager/active_hardware.html', context)

# ============================================================
# REQUEST HARDWARE UPDATE
# ============================================================
from django.views.decorators.http import require_POST

# ============================================================
# REQUEST HARDWARE UPDATE
# ============================================================

@login_required
@require_POST  # ✅ Prevents GET requests from crashing the view
def request_hardware_update(request, hardware_id):
    """
    Manager requests hardware update from Super Admin
    With audit logging
    ✅ FIXED: Uses hardware_id (UUID) for lookup and redirects
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Unauthorized update request attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ✅ Lookup by hardware_id (UUID) - This works perfectly now!
    hardware = get_object_or_404(Hardware, hardware_id=hardware_id)
    reason = request.POST.get('reason', '').strip()
    
    if not reason:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Hardware update request failed - No reason provided for {hardware.asset_number}",
            target_user=request.user,
            target_model="Hardware",
            target_id=hardware.id
        )
        messages.error(request, 'Please provide a reason for the update request.')
        return redirect('manage_hardware')
    
    # Check for existing pending request
    existing_request = HardwareRequest.objects.filter(
        hardware=hardware,
        request_type='update',
        status='pending'
    ).first()
    
    if existing_request:
        messages.warning(request, f'You already have a pending update request for {hardware.asset_number}.')
        return redirect('manage_hardware')
    
    # ========== CREATE REQUEST ==========
    hw_request = HardwareRequest.objects.create(
        hardware=hardware,
        requested_by=request.user,
        request_type='update',
        reason=reason,
        status='pending'
    )
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="hardware_request_update",
        module="Hardware Management",
        description=f"Manager {request.user.username} requested update for hardware '{hardware.asset_number}' (Reason: {reason[:50]}...)",
        target_user=request.user,
        target_model="HardwareRequest",
        target_id=hw_request.id,
        new_value={
            'hardware': hardware.asset_number,
            'hardware_id': str(hardware.hardware_id),  # ✅ Log as string
            'hardware_type': hardware.hardware_type.name if hardware.hardware_type else 'Unknown',
            'reason': reason
        }
    )
    
    # ========== SEND EMAIL ==========
    try:
        from .utils.email_utils import send_request_notification
        email_sent = send_request_notification(request, hw_request, 'update')
        if email_sent:
            messages.success(
                request,
                f'✅ Update request for "{hardware.asset_number}" submitted to Super Admin. (Request ID: #{hw_request.id})'
            )
        else:
            messages.warning(
                request,
                f'✅ Update request submitted. (Request ID: #{hw_request.id}) - No Super Admins found to notify.'
            )
    except Exception as e:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Email notification failed for update request #{hw_request.id}: {str(e)}",
            target_user=request.user
        )
        messages.warning(
            request,
            f'✅ Update request submitted. (Request ID: #{hw_request.id}) - Email notification failed: {str(e)}'
        )
    
    return redirect('manage_hardware')


# ============================================================
# REQUEST HARDWARE DELETE
# ============================================================

@login_required
@require_POST  # ✅ Prevents GET requests from crashing the view
def request_hardware_delete(request, hardware_id):
    """
    Manager requests hardware deletion from Super Admin
    With audit logging
    ✅ FIXED: Uses hardware_id (UUID) for lookup and redirects
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Unauthorized delete request attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ✅ Lookup by hardware_id (UUID) - This works perfectly now!
    hardware = get_object_or_404(Hardware, hardware_id=hardware_id)
    reason = request.POST.get('reason', '').strip()
    
    if not reason:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Hardware delete request failed - No reason provided for {hardware.asset_number}",
            target_user=request.user,
            target_model="Hardware",
            target_id=hardware.id
        )
        messages.error(request, 'Please provide a reason for the deletion request.')
        return redirect('manage_hardware')
    
    # Check if hardware is assigned or in use
    if hardware.status in ['assigned', 'in_use']:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Hardware delete request blocked - {hardware.asset_number} is {hardware.status}",
            target_user=request.user,
            target_model="Hardware",
            target_id=hardware.id,
            old_value=hardware.status
        )
        messages.error(
            request,
            f'Cannot request deletion - {hardware.asset_number} is currently {hardware.get_status_display().lower()}.'
        )
        return redirect('manage_hardware')
    
    # Check for existing pending request
    existing_request = HardwareRequest.objects.filter(
        hardware=hardware,
        request_type='delete',
        status='pending'
    ).first()
    
    if existing_request:
        messages.warning(request, f'You already have a pending deletion request for {hardware.asset_number}.')
        return redirect('manage_hardware')
    
    # ========== CREATE REQUEST ==========
    hw_request = HardwareRequest.objects.create(
        hardware=hardware,
        requested_by=request.user,
        request_type='delete',
        reason=reason,
        status='pending'
    )
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="hardware_request_delete",
        module="Hardware Management",
        description=f"Manager {request.user.username} requested deletion of hardware '{hardware.asset_number}' (Reason: {reason[:50]}...)",
        target_user=request.user,
        target_model="HardwareRequest",
        target_id=hw_request.id,
        new_value={
            'hardware': hardware.asset_number,
            'hardware_id': str(hardware.hardware_id),  # ✅ Log as string
            'hardware_type': hardware.hardware_type.name if hardware.hardware_type else 'Unknown',
            'status': hardware.status,
            'reason': reason
        }
    )
    
    # ========== SEND EMAIL ==========
    try:
        from .utils.email_utils import send_request_notification
        email_sent = send_request_notification(request, hw_request, 'delete')
        if email_sent:
            messages.success(
                request,
                f'✅ Deletion request for "{hardware.asset_number}" submitted to Super Admin. (Request ID: #{hw_request.id})'
            )
        else:
            messages.warning(
                request,
                f'✅ Deletion request submitted. (Request ID: #{hw_request.id}) - No Super Admins found to notify.'
            )
    except Exception as e:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Email notification failed for delete request #{hw_request.id}: {str(e)}",
            target_user=request.user
        )
        messages.warning(
            request,
            f'✅ Deletion request submitted. (Request ID: #{hw_request.id}) - Email notification failed: {str(e)}'
        )
    
    return redirect('manage_hardware')

# ============================================================
# ADD HARDWARE - SUPER ADMIN
# ============================================================
@login_required
def add_hardware(request):
    """
    Super Admin can add hardware and assign to specific branch/manager
    With audit logging for single and bulk additions
    ✅ UPDATED: Records hardware_id (UUID) in audit logs and context
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Unauthorized hardware addition attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to add hardware.')
        return redirect('login')
    
    # ========== GET DATA FOR FORM ==========
    hardware_types = HardwareType.objects.all()
    managers = CustomUser.objects.filter(
        user_type='manager',
        is_active=True
    ).order_by('first_name')
    
    branches = CustomUser.objects.filter(
        user_type='manager'
    ).values_list('branch_location', flat=True).distinct()
    branches = [b for b in branches if b]
    branches = sorted(set(branches))
    
    if not branches:
        branches = ['Hyderabad', 'Bangalore', 'Mumbai', 'Delhi', 'Chennai', 'Pune', 'Kolkata']
    
    # ========== POST REQUEST ==========
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        
        # ========== BULK EXCEL IMPORT ==========
        if 'excel_file' in request.FILES:
            excel_file = request.FILES['excel_file']
            branch = request.POST.get('branch', '').strip()
            manager_id = request.POST.get('manager')
            
            if not branch:
                messages.error(request, 'Please select a branch for the hardware!')
                return redirect('add_hardware')
            
            if not excel_file.name.endswith(('.xlsx', '.xls')):
                messages.error(request, 'Please upload an Excel file (.xlsx or .xls)')
                return redirect('add_hardware')
            
            # Get manager
            manager = None
            manager_name = 'Unassigned'
            if manager_id:
                try:
                    manager = CustomUser.objects.get(
                        id=manager_id,
                        user_type='manager',
                        branch_location=branch,
                        is_active=True
                    )
                    manager_name = manager.get_full_name() or manager.username
                except CustomUser.DoesNotExist:
                    messages.warning(request, 'Selected manager not found. Hardware created without manager.')
            
            try:
                import pandas as pd
                df = pd.read_excel(excel_file)
                
                required_columns = ['hardware_type', 'asset_number', 'serial_number']
                missing_columns = [col for col in required_columns if col not in df.columns]
                if missing_columns:
                    messages.error(request, f'Missing required columns: {", ".join(missing_columns)}')
                    return redirect('add_hardware')
                
                success_count = 0
                error_count = 0
                errors = []
                created_hardware = []
                
                for index, row in df.iterrows():
                    try:
                        hardware_type_name = str(row['hardware_type']).strip()
                        asset_number = str(row['asset_number']).strip()
                        serial_number = str(row['serial_number']).strip()
                        model_name = str(row.get('model_name', '')).strip() if pd.notna(row.get('model_name')) else ''
                        brand = str(row.get('brand', '')).strip() if pd.notna(row.get('brand')) else ''
                        
                        if not hardware_type_name or not asset_number or not serial_number:
                            errors.append(f"Row {index + 2}: Missing required fields")
                            error_count += 1
                            continue
                        
                        # Get hardware type
                        try:
                            hardware_type = HardwareType.objects.get(name__iexact=hardware_type_name)
                        except HardwareType.DoesNotExist:
                            if hardware_type_name.isdigit():
                                try:
                                    hardware_type = HardwareType.objects.get(id=int(hardware_type_name))
                                except HardwareType.DoesNotExist:
                                    errors.append(f"Row {index + 2}: Hardware type ID '{hardware_type_name}' not found")
                                    error_count += 1
                                    continue
                            else:
                                errors.append(f"Row {index + 2}: Hardware type '{hardware_type_name}' not found")
                                error_count += 1
                                continue
                        
                        # Check duplicates
                        if Hardware.objects.filter(asset_number=asset_number).exists():
                            errors.append(f"Row {index + 2}: Asset number '{asset_number}' already exists")
                            error_count += 1
                            continue
                        
                        if Hardware.objects.filter(serial_number=serial_number).exists():
                            errors.append(f"Row {index + 2}: Serial number '{serial_number}' already exists")
                            error_count += 1
                            continue
                        
                        # Create hardware
                        hardware = Hardware.objects.create(
                            hardware_type=hardware_type,
                            asset_number=asset_number,
                            serial_number=serial_number,
                            model_name=model_name or None,
                            brand=brand or None,
                            status='available',
                            created_by=manager or request.user,
                            branch_location=branch,
                        )
                        success_count += 1
                        
                        # ✅ Capture hardware_id in the audit list
                        created_hardware.append({
                            'type': hardware_type.name,
                            'asset': asset_number,
                            'serial': serial_number,
                            'hardware_id': str(hardware.hardware_id)
                        })
                        
                    except Exception as e:
                        errors.append(f"Row {index + 2}: {str(e)}")
                        error_count += 1
                
                # ========== AUDIT LOG - BULK IMPORT ==========
                if success_count > 0:
                    create_audit_log(
                        request=request,
                        user=request.user,
                        action="hardware_bulk_create",
                        module="Hardware Management",
                        description=f"Super Admin {request.user.username} bulk imported {success_count} hardware items to {branch} branch" + (f" under {manager_name}" if manager else ""),
                        target_model="Hardware",
                        new_value={
                            'count': success_count,
                            'branch': branch,
                            'manager': manager_name,
                            'items': created_hardware[:10],  # First 10 for audit
                            'ip': client_ip
                        }
                    )
                
                # ========== MESSAGES ==========
                if success_count > 0:
                    messages.success(request, f'✅ Successfully imported {success_count} hardware items to {branch}!')
                    if manager:
                        messages.info(request, f'📋 Assigned to manager: {manager_name}')
                
                if error_count > 0:
                    error_message = f'Failed to import {error_count} items. '
                    if errors:
                        error_message += ' First few errors: ' + '; '.join(errors[:3])
                    messages.warning(request, error_message)
                
                return redirect('super_admin_hardware')
                
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_error",
                    module="Hardware Management",
                    description=f"Bulk hardware import failed: {str(e)}",
                    target_user=request.user,
                    new_value={'error': str(e)}
                )
                messages.error(request, f'Error reading Excel file: {str(e)}')
                return redirect('add_hardware')
        
        # ========== SINGLE HARDWARE ADDITION ==========
        else:
            hardware_type_id = request.POST.get('hardware_type')
            asset_number = request.POST.get('asset_number', '').strip()
            serial_number = request.POST.get('serial_number', '').strip()
            model_name = request.POST.get('model_name', '').strip()
            brand = request.POST.get('brand', '').strip()
            branch = request.POST.get('branch', '').strip()
            manager_id = request.POST.get('manager')
            
            # ========== VALIDATION ==========
            validation_errors = []
            
            if not hardware_type_id:
                validation_errors.append('Hardware type is required.')
            if not asset_number:
                validation_errors.append('Asset number is required.')
            if not serial_number:
                validation_errors.append('Serial number is required.')
            if not branch:
                validation_errors.append('Please select a branch.')
            
            if validation_errors:
                for error in validation_errors:
                    messages.error(request, error)
                return redirect('add_hardware')
            
            if Hardware.objects.filter(asset_number=asset_number).exists():
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Hardware Management",
                    description=f"Hardware addition failed - Asset '{asset_number}' already exists",
                    target_user=request.user
                )
                messages.error(request, 'Asset number already exists!')
                return redirect('add_hardware')
            
            if Hardware.objects.filter(serial_number=serial_number).exists():
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Hardware Management",
                    description=f"Hardware addition failed - Serial '{serial_number}' already exists",
                    target_user=request.user
                )
                messages.error(request, 'Serial number already exists!')
                return redirect('add_hardware')
            
            try:
                hardware_type = HardwareType.objects.get(id=hardware_type_id)
            except HardwareType.DoesNotExist:
                messages.error(request, 'Invalid hardware type selected!')
                return redirect('add_hardware')
            
            # Get manager
            manager = None
            manager_name = 'Unassigned'
            if manager_id:
                try:
                    manager = CustomUser.objects.get(
                        id=manager_id,
                        user_type='manager',
                        branch_location=branch,
                        is_active=True
                    )
                    manager_name = manager.get_full_name() or manager.username
                except CustomUser.DoesNotExist:
                    messages.warning(request, 'Selected manager not found. Hardware created without manager.')
            
            # ========== CREATE HARDWARE ==========
            hardware = Hardware.objects.create(
                hardware_type=hardware_type,
                asset_number=asset_number,
                serial_number=serial_number,
                model_name=model_name or None,
                brand=brand or None,
                status='available',
                created_by=manager or request.user,
                branch_location=branch,
            )
            
            # ========== AUDIT LOG ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="hardware_create",
                module="Hardware Management",
                description=f"Super Admin {request.user.username} added hardware: {hardware_type.name} - Asset: {asset_number} in {branch} branch" + (f" under {manager_name}" if manager else ""),
                target_model="Hardware",
                target_id=hardware.id,  # Integer ID for database linking
                new_value={
                    'type': hardware_type.name,
                    'asset_number': asset_number,
                    'serial_number': serial_number,
                    'model': model_name,
                    'brand': brand,
                    'branch': branch,
                    'manager': manager_name,
                    'hardware_id': str(hardware.hardware_id),  # ✅ UUID STRING
                    'ip': client_ip
                }
            )
            
            # ========== SUCCESS MESSAGE ==========
            success_msg = f'✅ {hardware_type.name} added successfully! Asset: {asset_number} | Branch: {branch}'
            if model_name:
                success_msg += f' | Model: {model_name}'
            if brand:
                success_msg += f' | Brand: {brand}'
            if manager:
                success_msg += f' | Assigned to: {manager_name}'
            messages.success(request, success_msg)
            
            return redirect('super_admin_hardware')
    
    # ========== GET REQUEST ==========
    context = {
        'hardware_types': hardware_types,
        'managers': managers,
        'branches': branches,
        'total_hardware': Hardware.objects.count(),
        'available_count': Hardware.objects.filter(status='available').count(),
    }
    return render(request, 'super_admin/add_hardware.html', context)


# ============================================================
# DOWNLOAD HARDWARE TEMPLATE
# ============================================================
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

@login_required
def download_hardware_template(request):
    """
    Download Excel template for bulk hardware import
    With audit logging
    ✅ UPDATED: Added hardware_id to instructions
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Unauthorized template download attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to download templates.')
        return redirect('login')
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="export_report",
        module="Hardware Management",
        description=f"Super Admin {request.user.username} downloaded hardware import template",
        target_user=request.user
    )
    
    try:
        wb = Workbook()
        ws = wb.active
        ws.title = "Hardware Template"
        
        # Define headers
        headers = ['hardware_type', 'asset_number', 'serial_number', 'model_name', 'brand', 'purchase_date', 'specifications']
        
        # Define column widths
        column_widths = {
            'A': 20, 'B': 18, 'C': 18, 'D': 20, 'E': 15, 'F': 15, 'G': 40
        }
        
        # Style for headers
        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="E04D00", end_color="E04D00", fill_type="solid")
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal='center', vertical='center')
            cell.border = Border(
                left=Side(style='thin'),
                right=Side(style='thin'),
                top=Side(style='thin'),
                bottom=Side(style='thin')
            )
        
        # Set column widths
        for col_letter, width in column_widths.items():
            ws.column_dimensions[col_letter].width = width
        
        # Get hardware types
        hardware_types = HardwareType.objects.all().order_by('name')
        
        # Create types list sheet
        ws_types_list = wb.create_sheet("HardwareTypesList")
        ws_types_list.cell(row=1, column=1, value="Hardware Type")
        ws_types_list.cell(row=1, column=2, value="Description")
        
        for col in range(1, 3):
            cell = ws_types_list.cell(row=1, column=col)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="E04D00", end_color="E04D00", fill_type="solid")
            cell.alignment = Alignment(horizontal='center', vertical='center')
        
        for idx, hw_type in enumerate(hardware_types, 2):
            ws_types_list.cell(row=idx, column=1, value=hw_type.name)
            ws_types_list.cell(row=idx, column=2, value=hw_type.description or '')
        
        # ✅ FIX: Create dropdown validation with proper import
        if hardware_types.exists():
            from openpyxl.worksheet.datavalidation import DataValidation
            
            # Create the range reference
            range_ref = f'HardwareTypesList!$A$2:$A${hardware_types.count() + 1}'
            
            # Create data validation
            dv = DataValidation(
                type="list", 
                formula1=range_ref, 
                allow_blank=False,
                showDropDown=True
            )
            dv.error = 'Please select a valid hardware type from the list'
            dv.errorTitle = 'Invalid Hardware Type'
            dv.prompt = 'Select hardware type from dropdown'
            dv.promptTitle = 'Hardware Type'
            
            # Add validation to column A
            ws.add_data_validation(dv)
            dv.add('A2:A1000')
        
        # Add example data
        example_data = []
        example_types = hardware_types[:10]
        
        for idx, hw_type in enumerate(example_types):
            example_data.append([
                hw_type.name,
                f'AST-{str(idx+1).zfill(4)}',
                f'{hw_type.name[:3].upper()}-{str(idx+1).zfill(3)}',
                f'Model-{idx+1}',
                f'Brand-{idx+1}',
                datetime.now().strftime('%Y-%m-%d'),
                f'RAM: 8GB, Storage: 256GB SSD, Processor: Intel i5'
            ])
        
        # Add empty rows for user input
        for i in range(5):
            example_data.append(['', '', '', '', '', '', ''])
        
        for row_idx, row_data in enumerate(example_data, 2):
            for col_idx, value in enumerate(row_data, 1):
                if value:
                    cell = ws.cell(row=row_idx, column=col_idx, value=value)
                    cell.border = Border(
                        left=Side(style='thin'),
                        right=Side(style='thin'),
                        top=Side(style='thin'),
                        bottom=Side(style='thin')
                    )
        
        # Add notes sheet
        ws_notes = wb.create_sheet("Instructions")
        
        notes = [
            ["📋 INSTRUCTIONS FOR BULK HARDWARE IMPORT"],
            [""],
            ["🔹 REQUIRED COLUMNS (Must be filled):"],
            ["   1. hardware_type - Select from dropdown or enter exact name from list below"],
            ["   2. asset_number - Unique asset tag number (must not exist in system)"],
            ["   3. serial_number - Unique serial number (must not exist in system)"],
            [""],
            ["📌 OPTIONAL COLUMNS:"],
            ["   4. model_name - Hardware model name"],
            ["   5. brand - Manufacturer brand"],
            ["   6. purchase_date - Date of purchase (format: YYYY-MM-DD)"],
            ["   7. specifications - Detailed hardware specifications"],
            [""],
            ["⚠️ IMPORTANT NOTES:"],
            ["   • Hardware types must already exist (see complete list below)"],
            ["   • Asset numbers must be unique across entire system"],
            ["   • Serial numbers must be unique across entire system"],
            ["   • Hardware will be added with 'Available' status by default"],
            ["   • Do not modify the column headers"],
            ["   • Remove example rows before importing"],
            [""],
            ["📋 COMPLETE LIST OF AVAILABLE HARDWARE TYPES:"],
            [""],
        ]
        
        notes.append(["   " + "=" * 70])
        notes.append(["   {:.<30} {:.<20}".format("HARDWARE TYPE", "DESCRIPTION")])
        notes.append(["   " + "-" * 70])
        
        for hw_type in hardware_types:
            desc = hw_type.description if hw_type.description else "—"
            notes.append([f"   • {hw_type.name:<28} {desc:<30}"])
        
        notes.append(["   " + "=" * 70])
        notes.append([f"   Total Hardware Types: {hardware_types.count()}"])
        
        for row_idx, row_data in enumerate(notes, 1):
            for col_idx, value in enumerate(row_data, 1):
                cell = ws_notes.cell(row=row_idx, column=col_idx, value=value)
                if row_idx == 1:
                    cell.font = Font(bold=True, size=14, color="E04D00")
                elif "COMPLETE LIST" in str(value):
                    cell.font = Font(bold=True, size=12, color="0d6efd")
                elif "Total Hardware Types" in str(value):
                    cell.font = Font(bold=True, size=12, color="28a745")
        
        # Auto-adjust column widths
        for col in range(1, len(headers) + 1):
            max_length = len(headers[col-1])
            for row in range(2, len(example_data) + 2):
                cell_value = ws.cell(row=row, column=col).value
                if cell_value:
                    max_length = max(max_length, len(str(cell_value)))
            adjusted_width = min(max_length + 3, 40)
            ws.column_dimensions[get_column_letter(col)].width = adjusted_width
        
        ws_types_list.column_dimensions['A'].width = 25
        ws_types_list.column_dimensions['B'].width = 40
        
        max_notes_length = 0
        for row in notes:
            for cell in row:
                if cell:
                    max_notes_length = max(max_notes_length, len(str(cell)))
        ws_notes.column_dimensions['A'].width = min(max_notes_length + 5, 100)
        
        ws_types_list.sheet_state = 'hidden'
        
        # ========== PREPARE RESPONSE ==========
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"hardware_import_template_{timestamp}.xlsx"
        
        response = HttpResponse(
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        wb.save(response)
        return response
        
    except Exception as e:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_error",
            module="Hardware Management",
            description=f"Template download failed: {str(e)}",
            target_user=request.user,
            new_value={'error': str(e)}
        )
        messages.error(request, f'Error generating template: {str(e)}')
        return redirect('super_admin_hardware')

# views.py - Updated Hardware Type Management Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count
from django.utils import timezone
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import HardwareType, Hardware


# ============================================================
# MANAGE HARDWARE TYPES - SUPER ADMIN
# ============================================================

@login_required
def manage_hardware_types(request):
    """
    Super Admin can manage hardware types (CRUD operations)
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Type Management",
            description=f"Unauthorized access to hardware type management by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to manage hardware types.')
        return redirect('login')
    
    # ========== GET HARDWARE TYPES ==========
    hardware_types = HardwareType.objects.annotate(
        hardware_count=Count('hardware_items')
    ).order_by('name')
    
    total_types = hardware_types.count()
    total_hardware = Hardware.objects.count()
    
    # ========== POST REQUEST - CREATE NEW TYPE ==========
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        description = request.POST.get('description', '').strip()
        icon = request.POST.get('icon', 'laptop')
        client_ip = get_client_ip(request)
        
        # ========== VALIDATION ==========
        if not name:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Type Management",
                description=f"Hardware type creation failed - No name provided by {request.user.username}",
                target_user=request.user
            )
            messages.error(request, 'Please enter a hardware type name!')
            return redirect('manage_hardware_types')
        
        if HardwareType.objects.filter(name__iexact=name).exists():
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Type Management",
                description=f"Hardware type creation failed - '{name}' already exists",
                target_user=request.user,
                new_value={'name': name}
            )
            messages.error(request, f'Hardware type "{name}" already exists!')
            return redirect('manage_hardware_types')
        
        # ========== CREATE HARDWARE TYPE ==========
        try:
            hardware_type = HardwareType.objects.create(
                name=name,
                description=description,
                icon=icon
            )
            
            # ========== AUDIT LOG ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="hardware_type_create",
                module="Hardware Type Management",
                description=f"Super Admin {request.user.username} created hardware type '{name}'",
                target_model="HardwareType",
                target_id=hardware_type.id,
                new_value={
                    'name': name,
                    'description': description,
                    'icon': icon,
                    'ip': client_ip
                }
            )
            
            messages.success(request, f'✅ Hardware type "{name}" added successfully!')
            return redirect('manage_hardware_types')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Hardware Type Management",
                description=f"Hardware type creation failed: {str(e)}",
                target_user=request.user,
                new_value={'name': name, 'error': str(e)}
            )
            messages.error(request, f'Error creating hardware type: {str(e)}')
            return redirect('manage_hardware_types')
    
    # ========== AUDIT LOG - VIEW ==========
    if request.session.get('last_hw_types_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Hardware Type Management",
            description=f"Super Admin {request.user.username} viewed hardware types ({total_types} types, {total_hardware} hardware items)",
            target_user=request.user,
            new_value={
                'total_types': total_types,
                'total_hardware': total_hardware
            }
        )
        request.session['last_hw_types_view'] = timezone.now().timestamp()
    
    # ========== CONTEXT ==========
    context = {
        'hardware_types': hardware_types,
        'total_types': total_types,
        'total_hardware': total_hardware,
    }
    return render(request, 'super_admin/manage_hardware_types.html', context)


# ============================================================
# SUPER ADMIN - EDIT HARDWARE TYPE
# ============================================================

@login_required
def super_admin_edit_hardware_type(request, type_id):
    """
    Super Admin edit a hardware type
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Type Management",
            description=f"Unauthorized edit attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to edit hardware types.')
        return redirect('login')
    
    hardware_type = get_object_or_404(HardwareType, id=type_id)
    old_name = hardware_type.name
    old_description = hardware_type.description
    old_icon = hardware_type.icon
    
    # ========== POST REQUEST ==========
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        description = request.POST.get('description', '').strip()
        icon = request.POST.get('icon', 'laptop')
        client_ip = get_client_ip(request)
        
        # ========== VALIDATION ==========
        if not name:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Type Management",
                description=f"Hardware type edit failed - No name provided for type ID {type_id}",
                target_user=request.user,
                target_model="HardwareType",
                target_id=type_id
            )
            messages.error(request, 'Please enter a hardware type name!')
            return redirect('super_admin_edit_hardware_type', type_id=type_id)
        
        # Check if name already exists (excluding current)
        if HardwareType.objects.filter(name__iexact=name).exclude(id=type_id).exists():
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Type Management",
                description=f"Hardware type edit failed - '{name}' already exists",
                target_user=request.user,
                target_model="HardwareType",
                target_id=type_id,
                new_value={'name': name}
            )
            messages.error(request, f'Hardware type "{name}" already exists!')
            return redirect('super_admin_edit_hardware_type', type_id=type_id)
        
        # ========== UPDATE HARDWARE TYPE ==========
        try:
            hardware_type.name = name
            hardware_type.description = description
            hardware_type.icon = icon
            hardware_type.save()
            
            # ========== AUDIT LOG ==========
            changes = []
            if old_name != name:
                changes.append(f"name: '{old_name}' → '{name}'")
            if old_description != description:
                changes.append(f"description updated")
            if old_icon != icon:
                changes.append(f"icon: '{old_icon}' → '{icon}'")
            
            create_audit_log(
                request=request,
                user=request.user,
                action="hardware_type_update",
                module="Hardware Type Management",
                description=f"Super Admin {request.user.username} updated hardware type '{name}'. Changes: {', '.join(changes) if changes else 'No changes'}",
                target_model="HardwareType",
                target_id=hardware_type.id,
                old_value={
                    'name': old_name,
                    'description': old_description,
                    'icon': old_icon
                },
                new_value={
                    'name': name,
                    'description': description,
                    'icon': icon,
                    'ip': client_ip
                }
            )
            
            messages.success(request, f'✅ Hardware type "{name}" updated successfully!')
            return redirect('manage_hardware_types')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Hardware Type Management",
                description=f"Hardware type edit failed: {str(e)}",
                target_user=request.user,
                target_model="HardwareType",
                target_id=type_id,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Error updating hardware type: {str(e)}')
            return redirect('super_admin_edit_hardware_type', type_id=type_id)
    
    # ========== GET REQUEST ==========
    context = {
        'hardware_type': hardware_type,
    }
    return render(request, 'super_admin/edit_hardware_type.html', context)


# ============================================================
# SUPER ADMIN - DELETE HARDWARE TYPE
# ============================================================

@login_required
def super_admin_delete_hardware_type(request, type_id):
    """
    Super Admin delete a hardware type
    With audit logging and validation
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Type Management",
            description=f"Unauthorized delete attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to delete hardware types.')
        return redirect('login')
    
    hardware_type = get_object_or_404(HardwareType, id=type_id)
    type_name = hardware_type.name
    
    # Check if hardware type has associated hardware
    hardware_count = Hardware.objects.filter(hardware_type=hardware_type).count()
    
    # ========== POST REQUEST ==========
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        
        # ========== CHECK ASSOCIATED HARDWARE ==========
        if hardware_count > 0:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Type Management",
                description=f"Hardware type deletion blocked - '{type_name}' has {hardware_count} associated hardware items",
                target_user=request.user,
                target_model="HardwareType",
                target_id=type_id,
                old_value={'hardware_count': hardware_count}
            )
            messages.error(
                request,
                f'Cannot delete "{type_name}" - It has {hardware_count} hardware item(s) associated with it.'
            )
            return redirect('manage_hardware_types')
        
        # ========== DELETE HARDWARE TYPE ==========
        try:
            # Store info for audit before deletion
            type_info = {
                'name': type_name,
                'description': hardware_type.description,
                'icon': hardware_type.icon
            }
            
            hardware_type.delete()
            
            # ========== AUDIT LOG ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="hardware_type_delete",
                module="Hardware Type Management",
                description=f"Super Admin {request.user.username} deleted hardware type '{type_name}'",
                target_model="HardwareType",
                target_id=type_id,
                old_value=type_info,
                new_value={'deleted': True, 'ip': client_ip}
            )
            
            messages.success(request, f'✅ Hardware type "{type_name}" deleted successfully!')
            return redirect('manage_hardware_types')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Hardware Type Management",
                description=f"Hardware type deletion failed: {str(e)}",
                target_user=request.user,
                target_model="HardwareType",
                target_id=type_id,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Error deleting hardware type: {str(e)}')
            return redirect('manage_hardware_types')
    
    # ========== GET REQUEST - SHOW CONFIRMATION ==========
    context = {
        'hardware_type': hardware_type,
        'hardware_count': hardware_count,
    }
    return render(request, 'super_admin/confirm_delete_hardware_type.html', context)

# views.py - Updated Assignment Management Views with Audit Logging

from django.db.models import Q, Count
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings
import json
from hardware_management.utils.audit import create_audit_log, get_client_ip
from hardware_management.utils.email_utils import send_assignment_email


# ============================================================
# CREATE ASSIGNMENT
# ============================================================

@login_required
def create_assignment(request):
    """
    Create a new hardware assignment for an employee
    Supports manager-created, assigned-to-manager, AND global projects
    With comprehensive audit logging and draft support
    ✅ FIXED: Automatically picks up partially returned hardware due to branch_location fix
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Unauthorized assignment creation attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET DATA ==========
    employees = CustomUser.objects.filter(
        user_type='employee',
        manager=request.user,
        is_active=True
    )
    
    projects = Project.objects.filter(
        Q(assigned_manager__isnull=True) |
        Q(assigned_manager=request.user) |
        Q(created_by=request.user)
    ).distinct().order_by('-created_at')
    
    hardware_types = HardwareType.objects.all()
    
    # ========== GET OR CREATE DRAFT ==========
    draft, created = AssignmentDraft.objects.get_or_create(
        user=request.user,
        is_completed=False,
        defaults={
            'data': {},
            'last_saved': timezone.now()
        }
    )
    
    draft_data = draft.data if draft.data else {}
    
    # ========== POST REQUEST ==========
    if request.method == 'POST':
        # Check if this is an AJAX request for auto-save
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            try:
                data = json.loads(request.body)
                action = data.get('action')
                
                if action == 'save_draft':
                    # Save draft data
                    draft_data = {
                        'employee_id': data.get('employee_id', ''),
                        'project_id': data.get('project_id', ''),
                        'exam_city': data.get('exam_city', ''),
                        'exam_center_name': data.get('exam_center_name', ''),
                        'expected_return_date': data.get('expected_return_date', ''),
                        'notes': data.get('notes', ''),
                        'hardware_items': data.get('hardware_items', [])
                    }
                    
                    draft.data = draft_data
                    draft.last_saved = timezone.now()
                    draft.is_completed = False
                    draft.save()
                    
                    create_audit_log(
                        request=request,
                        user=request.user,
                        action="draft_save",
                        module="Assignment Management",
                        description=f"Manager {request.user.username} saved assignment draft",
                        target_user=request.user,
                        new_value={'draft_id': draft.id}
                    )
                    
                    return JsonResponse({
                        'success': True,
                        'message': 'Draft saved successfully',
                        'saved_at': draft.last_saved.strftime('%H:%M:%S')
                    })
                
                elif action == 'clear_draft':
                    # Clear the draft
                    draft.data = {}
                    draft.last_saved = timezone.now()
                    draft.is_completed = False
                    draft.save()
                    
                    create_audit_log(
                        request=request,
                        user=request.user,
                        action="draft_cleared",
                        module="Assignment Management",
                        description=f"Manager {request.user.username} cleared assignment draft",
                        target_user=request.user
                    )
                    
                    return JsonResponse({
                        'success': True,
                        'message': 'Draft cleared successfully'
                    })
                    
            except json.JSONDecodeError:
                return JsonResponse({
                    'success': False,
                    'error': 'Invalid JSON data'
                }, status=400)
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'error': str(e)
                }, status=400)
        
        # ========== REGULAR FORM SUBMISSION ==========
        employee_id = request.POST.get('employee')
        project_id = request.POST.get('project')
        expected_return_date = request.POST.get('expected_return_date')
        exam_city = request.POST.get('exam_city', '').strip()
        exam_center_name = request.POST.get('exam_center_name', '').strip()
        notes = request.POST.get('notes', '').strip()
        
        # Get hardware items as JSON
        hardware_items_data = request.POST.get('hardware_items_json', '[]')
        try:
            hardware_items = json.loads(hardware_items_data)
        except json.JSONDecodeError:
            hardware_items = []
        
        client_ip = get_client_ip(request)
        
        # ========== VALIDATION ==========
        validation_errors = []
        
        if not employee_id:
            validation_errors.append('Please select an employee.')
        if not project_id:
            validation_errors.append('Please select a project.')
        if not expected_return_date:
            validation_errors.append('Please select an expected return date.')
        if not exam_city:
            validation_errors.append('Please enter an exam city.')
        if not hardware_items:
            validation_errors.append('Please add at least one hardware item.')
        
        if validation_errors:
            for error in validation_errors:
                messages.error(request, error)
            return redirect('create_assignment')
        
        # ========== GET EMPLOYEE AND PROJECT ==========
        try:
            employee = CustomUser.objects.get(id=employee_id, manager=request.user)
        except CustomUser.DoesNotExist:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Assignment Management",
                description=f"Assignment creation failed - Employee {employee_id} not found",
                target_user=request.user
            )
            messages.error(request, 'Invalid employee selected!')
            return redirect('create_assignment')
        
        try:
            project = Project.objects.get(
                Q(assigned_manager__isnull=True) |
                Q(assigned_manager=request.user) |
                Q(created_by=request.user),
                id=project_id
            )
        except Project.DoesNotExist:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Assignment Management",
                description=f"Assignment creation failed - Project {project_id} not found",
                target_user=request.user
            )
            messages.error(request, 'Invalid project selected!')
            return redirect('create_assignment')
        
        # ========== VALIDATE HARDWARE ==========
        valid_hardware = []
        errors = []
        
        # ✅ CRITICAL FIX: Filter hardware by branch_location, not created_by
        manager_branch = request.user.branch_location or ""
        
        for item in hardware_items:
            hardware_type_id = item.get('hardware_type_id')
            asset_number = item.get('asset_number', '').strip()
            
            if not asset_number:
                errors.append(f"Asset number required for {item.get('hardware_type_name', 'Unknown')}")
                continue
            
            try:
                # ✅ Allow any available hardware in the manager's branch, regardless of who created it
                if manager_branch:
                    hardware = Hardware.objects.get(
                        hardware_type_id=hardware_type_id,
                        asset_number=asset_number,
                        status='available',
                        branch_location=manager_branch
                    )
                else:
                    # If manager has no branch set, fallback to any available hardware
                    hardware = Hardware.objects.get(
                        hardware_type_id=hardware_type_id,
                        asset_number=asset_number,
                        status='available'
                    )
                    
                valid_hardware.append(hardware)
            except Hardware.DoesNotExist:
                try:
                    hardware_type = HardwareType.objects.get(id=hardware_type_id)
                    errors.append(f"Asset '{asset_number}' (Type: {hardware_type.name}) is not available in your branch '{manager_branch}'.")
                except HardwareType.DoesNotExist:
                    errors.append(f"Hardware type ID {hardware_type_id} not found")
        
        if errors:
            for error in errors[:5]:
                messages.error(request, error)
            if len(errors) > 5:
                messages.error(request, f'...and {len(errors) - 5} more errors')
            return redirect('create_assignment')
        
        if not valid_hardware:
            messages.error(request, 'No valid hardware items to assign!')
            return redirect('create_assignment')
        
        # ========== CREATE ASSIGNMENT ==========
        try:
            assignment = HardwareAssignment.objects.create(
                employee=employee,
                project=project,
                assigned_by=request.user,
                expected_return_date=expected_return_date,
                exam_city=exam_city,
                exam_center_name=exam_center_name,
                notes=notes
            )
            
            # Create assignment items
            hardware_details = []
            for hardware in valid_hardware:
                HardwareAssignmentItem.objects.create(
                    assignment=assignment,
                    hardware=hardware,
                    quantity=1,
                    condition_at_assignment='Assigned for exam duty'
                )
                hardware.status = 'assigned'
                hardware.save()
                
                hardware_details.append({
                    'type': hardware.hardware_type.name,
                    'asset_number': hardware.asset_number,
                    'serial_number': hardware.serial_number,
                    'model': hardware.model_name,
                    'brand': hardware.brand or 'N/A'
                })
            
            # ========== CLEAR DRAFT ==========
            draft.data = {}
            draft.is_completed = True
            draft.last_saved = timezone.now()
            draft.save()
            
            # ========== AUDIT LOG ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="assignment_create",
                module="Assignment Management",
                description=f"Manager {request.user.username} created assignment for {employee.get_full_name() or employee.username} with {len(valid_hardware)} items. Project: {project.project_name}",
                target_user=employee,
                target_model="HardwareAssignment",
                target_id=assignment.id,
                new_value={
                    'employee': employee.username,
                    'employee_email': employee.email,
                    'project': project.project_name,
                    'project_id': project.project_id,
                    'exam_city': exam_city,
                    'exam_center': exam_center_name,
                    'expected_return_date': expected_return_date,
                    'hardware_count': len(valid_hardware),
                    'hardware_items': hardware_details,
                    'ip': client_ip,
                    'assigned_from_branch': manager_branch
                }
            )
            
            # ========== SEND EMAIL ==========
            email_sent = False
            try:
                send_assignment_email(assignment, employee, project, hardware_details)
                email_sent = True
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Assignment Management",
                    description=f"Assignment email failed for {employee.email}: {str(e)}",
                    target_user=employee,
                    target_model="HardwareAssignment",
                    target_id=assignment.id
                )
            
            # ========== SUCCESS MESSAGE ==========
            success_msg = f'✅ Assignment created successfully with {len(valid_hardware)} hardware item(s)!'
            if email_sent:
                success_msg += f' Email sent to {employee.email}'
            else:
                success_msg += f' (Email could not be sent)'
            messages.success(request, success_msg)
            
            return redirect('view_assignments')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Assignment Management",
                description=f"Assignment creation failed: {str(e)}",
                target_user=request.user,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Error creating assignment: {str(e)}')
            return redirect('create_assignment')
    
    # ========== GET REQUEST (Display Form) ==========
    manager_branch = request.user.branch_location or ""
    
    for hw_type in hardware_types:
        if manager_branch:
            hw_type.hardware_list = Hardware.objects.filter(
                hardware_type=hw_type,
                status='available',
                branch_location=manager_branch
            ).values('id', 'asset_number', 'serial_number')
        else:
            # Fallback: Show all available hardware if branch is not set
            hw_type.hardware_list = Hardware.objects.filter(
                hardware_type=hw_type,
                status='available'
            ).values('id', 'asset_number', 'serial_number')
    
    created_projects_count = Project.objects.filter(created_by=request.user).count()
    assigned_projects_count = Project.objects.filter(assigned_manager=request.user).count()
    global_projects_count = Project.objects.filter(assigned_manager__isnull=True).count()
    
    # ========== AUDIT LOG - VIEW ==========
    if request.session.get('last_create_assignment_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Assignment Management",
            description=f"Manager {request.user.username} viewed assignment creation form",
            target_user=request.user,
            new_value={
                'employees_available': employees.count(),
                'projects_available': projects.count()
            }
        )
        request.session['last_create_assignment_view'] = timezone.now().timestamp()
    
    # ========== RESTORE DRAFT DATA ==========
    draft_data = draft.data if draft.data else {}
    has_draft = bool(draft_data and (
        draft_data.get('employee_id') or 
        draft_data.get('project_id') or 
        draft_data.get('exam_city') or 
        draft_data.get('hardware_items') or
        draft_data.get('notes')
    ))
    
    context = {
        'employees': employees,
        'projects': projects,
        'hardware_types': hardware_types,
        'today': timezone.now().date(),
        'user': request.user,
        'created_projects_count': created_projects_count,
        'assigned_projects_count': assigned_projects_count,
        'global_projects_count': global_projects_count,
        'draft_data': draft_data,
        'has_draft': has_draft,
        'draft_last_saved': draft.last_saved if draft.last_saved else None,
    }
    return render(request, 'manager/create_assignment.html', context)

# ============================================================
# VIEW ASSIGNMENTS
# ============================================================
@login_required
def view_assignments(request):
    """
    View all assignments for a manager
    With audit logging and filtering
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Unauthorized assignment view by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET ASSIGNMENTS ==========
    all_assignments = HardwareAssignment.objects.filter(
        assigned_by=request.user
    ).order_by('-assigned_date')
    
    today = timezone.now().date()
    due_soon_date = today + timedelta(days=3)
    
    # ========== FILTER LOGIC ==========
    assignments = all_assignments
    
    # Status filter
    status_filter = request.GET.get('status', 'all')
    if status_filter == 'active':
        assignments = assignments.filter(actual_return_date__isnull=True)
    elif status_filter == 'returned':
        assignments = assignments.filter(actual_return_date__isnull=False)
    elif status_filter == 'overdue':
        assignments = assignments.filter(
            actual_return_date__isnull=True,
            expected_return_date__lt=today
        )
    elif status_filter == 'due_soon':
        assignments = assignments.filter(
            actual_return_date__isnull=True,
            expected_return_date__gte=today,
            expected_return_date__lte=due_soon_date
        )
    elif status_filter == 'pending':
        assignments = assignments.filter(
            actual_return_date__isnull=True,
            expected_return_date__lte=due_soon_date
        )
    
    # Search filter
    search_query = request.GET.get('search', '')
    if search_query:
        assignments = assignments.filter(
            Q(employee__first_name__icontains=search_query) |
            Q(employee__last_name__icontains=search_query) |
            Q(employee__username__icontains=search_query) |
            Q(project__project_name__icontains=search_query) |
            Q(exam_city__icontains=search_query) |
            Q(assignment_id__icontains=search_query)
        )
    
    # City filter
    city_filter = request.GET.get('city', '')
    if city_filter:
        assignments = assignments.filter(exam_city=city_filter)
    
    # Project filter
    project_filter = request.GET.get('project', '')
    if project_filter:
        assignments = assignments.filter(project_id=project_filter)
    
    # Date range filter
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    if date_from:
        try:
            date_from_parsed = datetime.strptime(date_from, '%Y-%m-%d').date()
            assignments = assignments.filter(assigned_date__gte=date_from_parsed)
        except ValueError:
            pass
    if date_to:
        try:
            date_to_parsed = datetime.strptime(date_to, '%Y-%m-%d').date()
            assignments = assignments.filter(assigned_date__lte=date_to_parsed)
        except ValueError:
            pass
    
    # ========== STATISTICS ==========
    total_assignments = all_assignments.count()
    active_assignments = all_assignments.filter(actual_return_date__isnull=True).count()
    returned_assignments = all_assignments.filter(actual_return_date__isnull=False).count()
    
    overdue_count = all_assignments.filter(
        actual_return_date__isnull=True,
        expected_return_date__lt=today
    ).count()
    
    due_soon_count = all_assignments.filter(
        actual_return_date__isnull=True,
        expected_return_date__gte=today,
        expected_return_date__lte=due_soon_date
    ).count()
    
    pending_return_count = overdue_count + due_soon_count
    
    unique_cities = all_assignments.exclude(
        exam_city__isnull=True
    ).exclude(
        exam_city__exact=''
    ).values('exam_city').distinct().count()
    
    # Get unique cities and projects for filter dropdowns
    city_list = all_assignments.exclude(
        exam_city__isnull=True
    ).exclude(
        exam_city__exact=''
    ).values_list('exam_city', flat=True).distinct().order_by('exam_city')
    
    project_list = all_assignments.values_list('project_id', 'project__project_name').distinct().order_by('project__project_name')
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_assignments_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Assignment Management",
            description=f"Manager {request.user.username} viewed assignments ({total_assignments} total, {active_assignments} active, {overdue_count} overdue)",
            target_user=request.user,
            new_value={
                'total': total_assignments,
                'active': active_assignments,
                'returned': returned_assignments,
                'overdue': overdue_count,
                'due_soon': due_soon_count,
                'unique_cities': unique_cities,
                'filters': {
                    'status': status_filter,
                    'search': search_query,
                    'city': city_filter,
                    'project': project_filter,
                }
            }
        )
        request.session['last_assignments_view'] = timezone.now().timestamp()
    
    # Clear any existing pending filter if other filters are applied
    if request.GET and 'pending' in request.GET and any(key != 'pending' for key in request.GET.keys()):
        # If there are other filters, remove pending parameter
        pass
    
    context = {
        'assignments': assignments,
        'total_assignments': total_assignments,
        'active_assignments': active_assignments,
        'returned_assignments': returned_assignments,
        'pending_return_count': pending_return_count,
        'overdue_count': overdue_count,
        'due_soon_count': due_soon_count,
        'unique_cities': unique_cities,
        'today': today,
        'due_soon_date': due_soon_date,
        'city_list': city_list,
        'project_list': project_list,
        'current_filters': {
            'status': status_filter,
            'search': search_query,
            'city': city_filter,
            'project': project_filter,
            'date_from': date_from,
            'date_to': date_to,
        }
    }
    return render(request, 'manager/view_assignments.html', context)


# ============================================================
# ASSIGNMENT DETAILS
# ============================================================

@login_required
def assignment_details(request, assignment_id):
    """
    View assignment details with hardware items, removal options, and partial return status
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Unauthorized assignment details view by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    assignment = get_object_or_404(
        HardwareAssignment,
        assignment_id=assignment_id,
        assigned_by=request.user
    )
    
    # ========== GET ITEMS ==========
    items = HardwareAssignmentItem.objects.filter(
        assignment=assignment
    ).select_related('hardware__hardware_type')
    
    verified_count = 0
    pending_count = 0
    not_entered_count = 0
    unverified_count = 0
    returned_count = 0
    pending_return_count = 0
    
    # Process items
    for item in items:
        # ✅ CRITICAL: Attach serial_number to the item object
        item.asset_number = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
        item.serial_number = item.hardware.serial_number  # <--- THIS LINE MUST BE HERE
        item.hardware_type_name = item.hardware.hardware_type.name if item.hardware.hardware_type else 'Unknown'
        item.hardware_status = item.hardware.status
        
        # Check if item is returned
        if hasattr(item, 'returned_at') and item.returned_at:
            item.is_returned = True
            item.returned_date = item.returned_at
            returned_count += 1
        else:
            item.is_returned = False
            item.returned_date = None
            pending_return_count += 1
        
        # Check asset entry
        item.has_asset_entry = hasattr(item, 'asset_entry')
        if item.has_asset_entry:
            item.entered_asset = item.asset_entry.entered_asset_number
            item.is_verified = item.asset_entry.verified
            if item.asset_entry.verified:
                verified_count += 1
            else:
                pending_count += 1
                unverified_count += 1
        else:
            item.entered_asset = None
            item.is_verified = False
            not_entered_count += 1
            unverified_count += 1
        
        # Check if item was added after assignment (extra item)
        item.is_extra_item = hasattr(item, 'created_at') and item.created_at > assignment.assigned_date if hasattr(item, 'created_at') else False
        
        # Check if item can be removed (not verified, not returned, assignment not returned)
        item.can_remove = not item.is_verified and not assignment.actual_return_date and not item.is_returned
    
    exam_center_name = getattr(assignment, 'exam_center_name', None)
    is_returned = assignment.actual_return_date is not None
    
    # Calculate partial return status
    total_items = items.count()
    if total_items > 0:
        return_percentage = (returned_count / total_items * 100)
        if returned_count == total_items and total_items > 0:
            return_status = 'fully_returned'
            return_status_text = 'All items returned'
            return_status_color = 'success'
        elif returned_count > 0:
            return_status = 'partially_returned'
            return_status_text = f'Partial return ({returned_count}/{total_items} items returned)'
            return_status_color = 'warning'
        else:
            return_status = 'not_returned'
            return_status_text = 'No items returned'
            return_status_color = 'danger'
    else:
        return_status = 'no_items'
        return_status_text = 'No items in assignment'
        return_status_color = 'secondary'
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="system_info",
        module="Assignment Management",
        description=f"Manager {request.user.username} viewed assignment {assignment.assignment_id} for {assignment.employee.get_full_name() or assignment.employee.username}",
        target_user=assignment.employee,
        target_model="HardwareAssignment",
        target_id=assignment.id,
        new_value={
            'assignment_id': str(assignment.assignment_id),
            'employee': assignment.employee.username,
            'project': assignment.project.project_name,
            'items_count': total_items,
            'verified': verified_count,
            'pending': pending_count,
            'not_entered': not_entered_count,
            'returned': returned_count,
            'pending_return': pending_return_count,
            'return_status': return_status,
            'is_returned': is_returned
        }
    )
    
    context = {
        'assignment': assignment,
        'items': items,
        'verified_count': verified_count,
        'pending_count': pending_count,
        'not_entered_count': not_entered_count,
        'unverified_items_count': unverified_count,
        'total_items': total_items,
        'returned_count': returned_count,
        'pending_return_count': pending_return_count,
        'return_percentage': return_percentage if total_items > 0 else 0,
        'return_status': return_status,
        'return_status_text': return_status_text,
        'return_status_color': return_status_color,
        'exam_center_name': exam_center_name,
        'is_returned': is_returned,
    }
    return render(request, 'manager/assignment_details.html', context)

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from hardware_management.utils.audit import create_audit_log, get_client_ip


# ============================================================
# REMOVE HARDWARE FROM ASSIGNMENT
# ============================================================

@login_required
def remove_hardware_from_assignment(request, assignment_id, item_id):
    """
    Remove a single hardware item from an assignment
    Handles partial returns properly - if all items are returned/removed, assignment is completed
    With comprehensive audit logging
    ✅ FIXED: Lookup by assignment_id (UUID) instead of id (Integer)
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Unauthorized hardware removal attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== ✅ CRITICAL FIX: Use assignment_id field for UUID ==========
    assignment = get_object_or_404(
        HardwareAssignment,
        assignment_id=assignment_id,  # <--- CHANGED FROM 'id' TO 'assignment_id'
        assigned_by=request.user,
        actual_return_date__isnull=True  # Only active assignments
    )
    
    item = get_object_or_404(
        HardwareAssignmentItem,
        id=item_id,
        assignment=assignment
    )
    
    hardware = item.hardware
    hardware_type = hardware.hardware_type.name if hardware.hardware_type else 'Unknown'
    asset_number = hardware.asset_number or 'N/A'
    serial_number = hardware.serial_number
    
    # ========== CHECK IF ALREADY RETURNED ==========
    if hasattr(item, 'returned_at') and item.returned_at is not None:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Hardware removal blocked - Item {asset_number} already returned",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id,
            old_value={'item_id': item_id, 'asset': asset_number, 'status': 'returned'}
        )
        messages.error(request, 'Cannot remove an already returned hardware item!')
        return redirect('assignment_details', assignment_id=assignment.assignment_id)
    
    # ========== CHECK IF VERIFIED ==========
    if hasattr(item, 'asset_entry') and item.asset_entry.verified:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Hardware removal blocked - Item {asset_number} is verified",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id,
            old_value={'item_id': item_id, 'asset': asset_number, 'status': 'verified'}
        )
        messages.error(request, 'Cannot remove verified hardware item!')
        return redirect('assignment_details', assignment_id=assignment.assignment_id)
    
    # ========== POST REQUEST - CONFIRM REMOVAL ==========
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        was_verified = hasattr(item, 'asset_entry') and item.asset_entry.verified
        was_returned = hasattr(item, 'returned_at') and item.returned_at is not None
        
        try:
            # Delete asset entry if exists
            if hasattr(item, 'asset_entry'):
                item.asset_entry.delete()
            
            # Delete the assignment item
            item.delete()
            
            # Update hardware status to available
            hardware.status = 'available'
            hardware.save()
            
            # Get remaining items
            remaining_items = HardwareAssignmentItem.objects.filter(assignment=assignment)
            remaining_count = remaining_items.count()
            
            # Check if all remaining items are already returned (partial return)
            all_remaining_returned = True
            for rem_item in remaining_items:
                if not (hasattr(rem_item, 'returned_at') and rem_item.returned_at is not None):
                    all_remaining_returned = False
                    break
            
            was_auto_returned = False
            return_type = "Partial Return"
            
            # Case 1: No items left in assignment - Full Return/Complete
            if remaining_count == 0:
                assignment.actual_return_date = timezone.now().date()
                assignment.save()
                was_auto_returned = True
                return_type = "Full Return"
            
            # Case 2: All remaining items are already returned - Assignment is complete
            elif all_remaining_returned and remaining_count > 0:
                assignment.actual_return_date = timezone.now().date()
                assignment.save()
                was_auto_returned = True
                return_type = "Full Return (All items returned)"
            
            # Case 3: Some items remain and not all are returned - Partial Return
            else:
                return_type = f"Partial Return ({remaining_count} item(s) remaining, {len([r for r in remaining_items if hasattr(r, 'returned_at') and r.returned_at is not None])} already returned)"
            
            # ========== AUDIT LOG ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="assignment_item_remove",
                module="Assignment Management",
                description=f"Manager {request.user.username} removed {hardware_type} (Asset: {asset_number}) from assignment {assignment.assignment_id}" + 
                           (f" - Assignment completed" if was_auto_returned else f" - {remaining_count} item(s) remaining"),
                target_user=assignment.employee,
                target_model="HardwareAssignment",
                target_id=assignment.id,
                old_value={
                    'item_id': item_id,
                    'hardware_type': hardware_type,
                    'asset_number': asset_number,
                    'serial_number': serial_number,
                    'was_verified': was_verified,
                    'was_returned': was_returned,
                    'employee': assignment.employee.username,
                    'project': assignment.project.project_name
                },
                new_value={
                    'remaining_items': remaining_count,
                    'assignment_returned': was_auto_returned,
                    'return_type': return_type,
                    'ip': client_ip
                }
            )
            
            # ========== SUCCESS MESSAGE ==========
            if was_auto_returned:
                messages.success(
                    request,
                    f'✅ Removed {hardware_type} (Asset: {asset_number}) from assignment. '
                    f'All items completed, assignment marked as returned.'
                )
            else:
                messages.success(
                    request,
                    f'✅ Successfully removed {hardware_type} (Asset: {asset_number}) from assignment. '
                    f'{remaining_count} item(s) remaining.'
                )
            
            return redirect('assignment_details', assignment_id=assignment.assignment_id)
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Assignment Management",
                description=f"Hardware removal failed: {str(e)}",
                target_user=request.user,
                target_model="HardwareAssignment",
                target_id=assignment.id,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Error removing hardware: {str(e)}')
            return redirect('assignment_details', assignment_id=assignment.assignment_id)
    
    # ========== GET REQUEST - SHOW CONFIRMATION ==========
    has_asset_entry = hasattr(item, 'asset_entry')
    entered_asset = item.asset_entry.entered_asset_number if has_asset_entry else None
    is_last_item = HardwareAssignmentItem.objects.filter(assignment=assignment).count() == 1
    is_returned = hasattr(item, 'returned_at') and item.returned_at is not None
    
    # Check if all other items are returned
    other_items = HardwareAssignmentItem.objects.filter(assignment=assignment).exclude(id=item_id)
    all_others_returned = True
    for other in other_items:
        if not (hasattr(other, 'returned_at') and other.returned_at is not None):
            all_others_returned = False
            break
    
    context = {
        'assignment': assignment,
        'item': item,
        'hardware': item.hardware,
        'asset_number': asset_number,
        'has_asset_entry': has_asset_entry,
        'entered_asset': entered_asset,
        'is_last_item': is_last_item,
        'is_returned': is_returned,
        'all_others_returned': all_others_returned,
        'other_items_count': other_items.count(),
    }
    return render(request, 'manager/confirm_remove_item.html', context)

# ============================================================
# REMOVE ALL UNVERIFIED HARDWARE
# ============================================================

@login_required
def remove_all_unverified_hardware(request, assignment_id):
    """
    Remove all unverified hardware items from an assignment
    Handles partial returns properly - if all items are returned/removed, assignment is completed
    With comprehensive audit logging
    ✅ FIXED: Redirects using the UUID string instead of the integer ID.
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Unauthorized bulk removal attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET ASSIGNMENT ==========
    assignment = get_object_or_404(
        HardwareAssignment,
        assignment_id=assignment_id,
        assigned_by=request.user,
        actual_return_date__isnull=True
    )
    
    # ========== GET UNVERIFIED AND NOT RETURNED ITEMS ==========
    items = HardwareAssignmentItem.objects.filter(assignment=assignment)
    unverified_items = []
    returned_items = []
    
    for item in items:
        is_verified = hasattr(item, 'asset_entry') and item.asset_entry.verified
        is_returned = hasattr(item, 'returned_at') and item.returned_at is not None
        
        if is_returned:
            returned_items.append(item)
        elif not is_verified:
            unverified_items.append(item)
    
    if not unverified_items:
        messages.info(request, 'No unverified items to remove.')
        # ✅ FIX: Use assignment.assignment_id
        return redirect('assignment_details', assignment_id=assignment.assignment_id)
    
    # ========== POST REQUEST - CONFIRM REMOVAL ==========
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        removed_count = 0
        removed_details = []
        
        try:
            for item in unverified_items:
                hardware = item.hardware
                removed_details.append({
                    'type': hardware.hardware_type.name if hardware.hardware_type else 'Unknown',
                    'asset_number': hardware.asset_number or 'N/A',
                    'serial_number': hardware.serial_number
                })
                
                # Delete asset entry if exists
                if hasattr(item, 'asset_entry'):
                    item.asset_entry.delete()
                
                # Delete the assignment item
                item.delete()
                
                # Update hardware status to available
                hardware.status = 'available'
                hardware.save()
                removed_count += 1
            
            # Get remaining items after removal
            remaining_items = HardwareAssignmentItem.objects.filter(assignment=assignment)
            remaining_count = remaining_items.count()
            
            # Check if all remaining items are already returned
            all_remaining_returned = True
            for rem_item in remaining_items:
                if not (hasattr(rem_item, 'returned_at') and rem_item.returned_at is not None):
                    all_remaining_returned = False
                    break
            
            was_auto_returned = False
            return_type = "Partial Return"
            
            # Case 1: No items left in assignment - Full Return/Complete
            if remaining_count == 0:
                assignment.actual_return_date = timezone.now().date()
                assignment.save()
                was_auto_returned = True
                return_type = "Full Return"
            
            # Case 2: All remaining items are already returned - Assignment is complete
            elif all_remaining_returned and remaining_count > 0:
                assignment.actual_return_date = timezone.now().date()
                assignment.save()
                was_auto_returned = True
                return_type = "Full Return (All items returned)"
            
            # Case 3: Some items remain and not all are returned - Partial Return
            else:
                returned_count = len([r for r in remaining_items if hasattr(r, 'returned_at') and r.returned_at is not None])
                return_type = f"Partial Return ({remaining_count} item(s) remaining, {returned_count} already returned)"
            
            # ========== AUDIT LOG ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="assignment_item_remove_all",
                module="Assignment Management",
                description=f"Manager {request.user.username} removed {removed_count} unverified items from assignment {assignment.assignment_id}" +
                           (f" - Assignment completed" if was_auto_returned else f" - {remaining_count} item(s) remaining"),
                target_user=assignment.employee,
                target_model="HardwareAssignment",
                target_id=assignment.id,
                old_value={
                    'removed_count': removed_count,
                    'items': removed_details,
                    'employee': assignment.employee.username,
                    'project': assignment.project.project_name,
                    'returned_items_before': len(returned_items)
                },
                new_value={
                    'remaining_items': remaining_count,
                    'assignment_returned': was_auto_returned,
                    'return_type': return_type,
                    'ip': client_ip
                }
            )
            
            # ========== SUCCESS MESSAGE ==========
            if was_auto_returned:
                messages.success(
                    request,
                    f'✅ Removed {removed_count} unverified items. '
                    f'All items completed, assignment marked as returned.'
                )
            else:
                messages.success(
                    request,
                    f'✅ Successfully removed {removed_count} unverified hardware item(s) from assignment. '
                    f'{remaining_count} item(s) remaining.'
                )
            
            # ✅ CRITICAL FIX: Redirect using assignment.assignment_id (UUID)
            return redirect('assignment_details', assignment_id=assignment.assignment_id)
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Assignment Management",
                description=f"Bulk hardware removal failed: {str(e)}",
                target_user=request.user,
                target_model="HardwareAssignment",
                target_id=assignment.id,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Error removing hardware: {str(e)}')
            # ✅ CRITICAL FIX: Redirect using assignment.assignment_id (UUID)
            return redirect('assignment_details', assignment_id=assignment.assignment_id)
    
    # ========== GET REQUEST - SHOW CONFIRMATION ==========
    total_items = HardwareAssignmentItem.objects.filter(assignment=assignment).count()
    is_all_items = len(unverified_items) == total_items
    has_returned_items = len(returned_items) > 0
    
    # Check if removing these items would complete the assignment
    would_complete = False
    if len(unverified_items) + len(returned_items) == total_items:
        would_complete = True
    
    context = {
        'assignment': assignment,
        'unverified_items': unverified_items,
        'count': len(unverified_items),
        'is_all_items': is_all_items,
        'has_returned_items': has_returned_items,
        'returned_count': len(returned_items),
        'total_items': total_items,
        'would_complete': would_complete,
    }
    return render(request, 'manager/confirm_remove_all.html', context)

# ============================================================
# REMOVE VERIFIED HARDWARE WARNING
# ============================================================

@login_required
def remove_verified_hardware_warning(request, assignment_id, item_id):
    """
    Show warning when trying to remove verified hardware
    Redirects back with error message
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Unauthorized verified removal attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET ASSIGNMENT AND ITEM ==========
    assignment = get_object_or_404(
        HardwareAssignment,
        id=assignment_id,
        assigned_by=request.user
    )
    
    item = get_object_or_404(
        HardwareAssignmentItem,
        id=item_id,
        assignment=assignment
    )
    
    hardware = item.hardware
    asset_number = hardware.asset_number or 'N/A'
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="system_warning",
        module="Assignment Management",
        description=f"Verified hardware removal blocked - Manager {request.user.username} attempted to remove verified item {asset_number} from assignment {assignment.assignment_id}",
        target_user=request.user,
        target_model="HardwareAssignment",
        target_id=assignment.id,
        old_value={
            'item_id': item_id,
            'asset_number': asset_number,
            'serial_number': hardware.serial_number,
            'status': 'verified'
        }
    )
    
    messages.error(request, 'Cannot remove verified hardware items. Please contact support if you need to remove this item.')
    return redirect('assignment_details', assignment_id=assignment_id)


# ============================================================
# ADD EXTRA HARDWARE TO ASSIGNMENT
# ============================================================

from hardware_management.utils.email_utils import send_extra_hardware_email

@login_required
def add_extra_hardware_to_assignment(request, assignment_id):
    """
    Manager adds extra hardware items to an existing active assignment.
    ✅ FIXED: Uses UUID for lookups and calls centralized email helper.
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Unauthorized hardware addition attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET ASSIGNMENT ==========
    assignment = get_object_or_404(
        HardwareAssignment,
        assignment_id=assignment_id,
        assigned_by=request.user,
        actual_return_date__isnull=True  # Only active assignments
    )
    
    # ========== DETERMINE BRANCH TO FILTER ==========
    manager_branch = request.user.branch_location or ""
    assignment_branch = assignment.exam_city or ""
    target_branch = manager_branch if manager_branch else assignment_branch
    
    # ========== GET AVAILABLE HARDWARE ==========
    base_query = Hardware.objects.filter(
        status='available'
    ).exclude(
        status='maintenance'
    ).select_related('hardware_type')
    
    if target_branch:
        available_hardware = base_query.filter(branch_location=target_branch)
    else:
        available_hardware = base_query
    
    # ========== ✅ CRITICAL FIX: EXCLUDE RETURNED ITEMS ==========
    existing_items = HardwareAssignmentItem.objects.filter(
        assignment=assignment,
        returned_at__isnull=True  # ✅ Only check items that have NOT been returned
    ).select_related('hardware__hardware_type')
    
    existing_hardware_ids = list(existing_items.values_list('hardware_id', flat=True))
    
    # ========== AUDIT LOG - VIEW ==========
    if request.session.get('last_add_hardware_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Assignment Management",
            description=f"Manager {request.user.username} viewed add hardware form for assignment {assignment.assignment_id}",
            target_user=assignment.employee,
            target_model="HardwareAssignment",
            target_id=assignment.id,
            new_value={
                'available_count': available_hardware.count(),
                'existing_count': existing_items.count(),
                'filtering_by_branch': target_branch or 'ALL (No branch set)'
            }
        )
        request.session['last_add_hardware_view'] = timezone.now().timestamp()
    
    # ========== POST REQUEST ==========
    if request.method == 'POST':
        hardware_ids = request.POST.getlist('hardware_ids')
        condition_notes = request.POST.get('condition_notes', '').strip()
        add_notes = request.POST.get('add_notes', '').strip()
        client_ip = get_client_ip(request)
        
        if not hardware_ids:
            messages.error(request, 'Please select at least one hardware item to add!')
            return redirect('add_extra_hardware_to_assignment', assignment_id=assignment_id)
        
        added_count = 0
        errors = []
        added_hardware_details = []
        
        for hw_id in hardware_ids:
            try:
                if target_branch:
                    # ✅ Search by UUID (hardware_id) instead of integer id
                    hardware = Hardware.objects.get(
                        hardware_id=hw_id,  # Changed from 'id' to 'hardware_id'
                        status='available',
                        branch_location=target_branch
                    )
                else:
                    hardware = Hardware.objects.get(
                        hardware_id=hw_id,  # Changed from 'id' to 'hardware_id'
                        status='available'
                    )
                
                if hardware.id in existing_hardware_ids:
                    errors.append(f"Hardware '{hardware.asset_number or hardware.serial_number}' is already in this assignment")
                    continue
                
                assignment_item = HardwareAssignmentItem.objects.create(
                    assignment=assignment,
                    hardware=hardware,
                    quantity=1,
                    condition_at_assignment=condition_notes or 'Assigned for exam duty'
                )
                
                hardware.status = 'assigned'
                hardware.save(update_fields=['status', 'updated_at'])
                
                added_count += 1
                added_hardware_details.append({
                    'type': hardware.hardware_type.name if hardware.hardware_type else 'Unknown',
                    'asset_number': hardware.asset_number,
                    'serial_number': hardware.serial_number,
                    'branch': hardware.branch_location
                })
                
            except Hardware.DoesNotExist:
                errors.append(f"Hardware ID {hw_id} not found, not available, or not located in branch '{target_branch or 'None/All'}'")
            except Exception as e:
                errors.append(f"Error adding hardware: {str(e)}")
        
        # ========== AUDIT LOG ==========
        if added_count > 0:
            create_audit_log(
                request=request,
                user=request.user,
                action="assignment_item_add",
                module="Assignment Management",
                description=f"Manager {request.user.username} added {added_count} hardware item(s) to assignment {assignment.assignment_id}",
                target_user=assignment.employee,
                target_model="HardwareAssignment",
                target_id=assignment.id,
                new_value={
                    'added_count': added_count,
                    'items': added_hardware_details,
                    'notes': add_notes,
                    'condition': condition_notes,
                    'ip': client_ip,
                    'branch': target_branch or 'None/All'
                }
            )
        
        if errors:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Assignment Management",
                description=f"Hardware addition errors: {', '.join(errors[:3])}",
                target_user=request.user,
                target_model="HardwareAssignment",
                target_id=assignment.id
            )
        
        # ========== SUCCESS MESSAGE & EMAIL ==========
        if added_count > 0:
            messages.success(
                request,
                f'✅ Successfully added {added_count} hardware item(s) to assignment {assignment.assignment_id}!'
            )
            
            # ✅ Call the centralized helper function
            try:
                send_extra_hardware_email(assignment, added_hardware_details, add_notes)
                messages.info(request, f'📧 Notification email sent to {assignment.employee.email}')
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Assignment Management",
                    description=f"Extra hardware email failed: {str(e)}",
                    target_user=assignment.employee,
                    target_model="HardwareAssignment",
                    target_id=assignment.id
                )
                messages.warning(request, f'⚠️ Hardware added but email could not be sent: {str(e)}')
        
        if errors:
            for error in errors[:3]:
                messages.warning(request, error)
            if len(errors) > 3:
                messages.warning(request, f'...and {len(errors) - 3} more errors')
        
        return redirect('assignment_details', assignment_id=assignment_id)
    
    # ========== GET REQUEST ==========
    context = {
        'assignment': assignment,
        'existing_items': existing_items,
        'available_hardware': available_hardware,
        'existing_hardware_ids': existing_hardware_ids,
        'total_existing': existing_items.count(),
        'total_available': available_hardware.count(),
        'today': timezone.now().date(),
        'debug_branch_info': {
            'manager_branch': manager_branch,
            'assignment_exam_city': assignment_branch,
            'target_branch_used': target_branch,
            'is_showing_all_hardware': not target_branch
        }
    }
    return render(request, 'manager/add_extra_hardware.html', context)    
# ============================================================
# SEND EXTRA HARDWARE EMAIL (Helper Function)
# ============================================================

# views.py - Updated Assignment Return Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from hardware_management.utils.audit import create_audit_log, get_client_ip


# ============================================================
# RETURN ASSIGNMENT
# ============================================================

@login_required
def return_assignment(request, assignment_id):
    """
    Return an assignment with asset number verification - Supports partial returns
    Only items that are fully verified can be returned
    With comprehensive audit logging
    ✅ FIXED: Updates hardware branch_location to manager's branch on return
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Unauthorized assignment return attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET ASSIGNMENT ==========
    assignment = get_object_or_404(
        HardwareAssignment,
        assignment_id=assignment_id,
        assigned_by=request.user
    )
    
    # Check if already returned
    if assignment.actual_return_date:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Return attempt on already returned assignment {assignment.assignment_id}",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id
        )
        messages.warning(request, 'This assignment has already been returned.')
        return redirect('view_assignments')
    
    items = HardwareAssignmentItem.objects.filter(
        assignment=assignment
    ).select_related('hardware__hardware_type')
    
    if not items.exists():
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Return attempt on assignment {assignment.assignment_id} with no items",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id
        )
        messages.warning(request, 'This assignment has no hardware items to return.')
        return redirect('view_assignments')
    
    # Add asset number to each item and check verification status
    for item in items:
        item.asset_number = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
        item.serial_number = item.hardware.serial_number
        
        # Check if item is verified
        try:
            asset_entry = item.asset_entry
            item.is_verified = asset_entry.verified
            item.entered_asset = asset_entry.entered_asset_number
        except HardwareAssetEntry.DoesNotExist:
            item.is_verified = False
            item.entered_asset = None
    
    # Check if any items are already returned (partial return)
    already_returned_items = []
    for item in items:
        if hasattr(item, 'returned_at') and item.returned_at:
            already_returned_items.append(item)
    
    # Check for unverified items
    unverified_items = [item for item in items if not item.is_verified and not (hasattr(item, 'returned_at') and item.returned_at)]
    
    # ========== POST REQUEST - PROCESS RETURN ==========
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        verification_status = []
        all_verified = True
        mismatch_count = 0
        returned_assets = []
        returned_item_ids = []
        items_to_return = []
        
        # First pass: Collect all items with asset numbers entered
        for item in items:
            # Skip if item is already returned
            if hasattr(item, 'returned_at') and item.returned_at:
                continue
                
            # Skip if item is not verified (cannot return unverified items)
            if not item.is_verified:
                continue
                
            returned_asset = request.POST.get(f'returned_asset_{item.id}', '').strip()
            
            # Skip if no asset number entered (item not selected for return)
            if not returned_asset:
                continue
            
            items_to_return.append({
                'item': item,
                'returned_asset': returned_asset,
                'condition_notes': request.POST.get(f'condition_notes_{item.id}', '').strip()
            })
        
        # ========== NO ITEMS SELECTED FOR RETURN ==========
        if not items_to_return:
            messages.warning(request, 'No verified items selected for return. Please enter Asset Numbers for verified items you want to return.')
            return redirect('return_assignment', assignment_id=assignment.id)
        
        # Second pass: Verify each selected item
        for return_data in items_to_return:
            item = return_data['item']
            returned_asset = return_data['returned_asset']
            condition_notes = return_data['condition_notes']
            
            # Verify the asset number matches
            is_match = (returned_asset.upper() == item.asset_number.upper())
            returned_assets.append({
                'hardware_type': item.hardware.hardware_type.name,
                'expected_asset': item.asset_number,
                'returned_asset': returned_asset,
                'is_match': is_match,
                'condition': condition_notes
            })
            
            if not is_match:
                mismatch_count += 1
                all_verified = False
                verification_status.append({
                    'item': item,
                    'status': 'mismatch',
                    'message': f'Returned Asset "{returned_asset}" does not match expected Asset "{item.asset_number}" for {item.hardware.hardware_type.name}'
                })
                continue
            
            # Mark item as returned
            item.returned_asset_number = returned_asset
            item.condition_at_return = condition_notes
            item.returned_at = timezone.now()
            item.save()
            returned_item_ids.append(item.id)
        
        # ========== HANDLE VERIFICATION FAILURE ==========
        if not all_verified:
            error_messages = []
            if mismatch_count > 0:
                error_messages.append(f'{mismatch_count} item(s) have mismatched Asset Numbers')
            
            # ========== AUDIT LOG - FAILURE ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Assignment Management",
                description=f"Assignment return verification failed for {assignment.assignment_id}: {', '.join(error_messages)}",
                target_user=assignment.employee,
                target_model="HardwareAssignment",
                target_id=assignment.id,
                old_value={
                    'assignment_id': str(assignment.assignment_id),
                    'items_count': items.count(),
                    'mismatch_count': mismatch_count,
                    'returned_assets': returned_assets
                }
            )
            
            messages.error(request, 'Return verification failed: ' + '; '.join(error_messages))
            request.session['verification_status'] = verification_status
            return redirect('return_assignment', assignment_id=assignment.id)
        
        # ========== PROCESS SUCCESSFUL RETURN ==========
        try:
            # Update hardware status to available for returned items
            hardware_updates = []
            manager_branch = request.user.branch_location or assignment.exam_city or "Not Assigned"
            
            for item in items:
                if item.id in returned_item_ids:
                    hardware_updates.append({
                        'asset_number': item.hardware.asset_number,
                        'serial_number': item.hardware.serial_number,
                        'old_status': item.hardware.status,
                        'old_branch': item.hardware.branch_location
                    })
                    
                    # ✅ FIX: Update hardware status and branch_location
                    item.hardware.status = 'available'
                    item.hardware.branch_location = manager_branch  # Set to manager's branch
                    item.hardware.save(update_fields=['status', 'branch_location', 'updated_at'])
            
            # Check if all items are returned
            all_items_returned = True
            for item in items:
                if not hasattr(item, 'returned_at') or not item.returned_at:
                    all_items_returned = False
                    break
            
            if all_items_returned:
                assignment.actual_return_date = timezone.now().date()
                assignment.save()
                return_type = "Full Return"
            else:
                # Partial return - keep assignment active
                return_type = "Partial Return"
                remaining = items.count() - len(returned_item_ids)
                messages.info(request, f'Partial return completed. {len(returned_item_ids)} item(s) returned. {remaining} item(s) remaining.')
            
            # ========== AUDIT LOG - SUCCESS ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="assignment_return",
                module="Assignment Management",
                description=f"{return_type} processed by {request.user.username} for assignment {assignment.assignment_id} ({len(returned_item_ids)} items returned to {manager_branch} branch)",
                target_user=assignment.employee,
                target_model="HardwareAssignment",
                target_id=assignment.id,
                old_value={
                    'assignment_id': str(assignment.assignment_id),
                    'employee': assignment.employee.username,
                    'project': assignment.project.project_name,
                    'expected_return_date': assignment.expected_return_date.isoformat() if assignment.expected_return_date else None,
                    'hardware_items': hardware_updates
                },
                new_value={
                    'return_date': timezone.now().date().isoformat(),
                    'items_returned': len(returned_item_ids),
                    'total_items': items.count(),
                    'return_type': return_type,
                    'returned_assets': returned_assets,
                    'ip': client_ip,
                    'new_branch_location': manager_branch
                }
            )
            
            # ========== SEND EMAIL ==========
            email_sent = False
            try:
                if all_items_returned:
                    send_return_confirmation_email(assignment, items)
                else:
                    send_partial_return_email(assignment, items, returned_item_ids)
                email_sent = True
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Assignment Management",
                    description=f"Return confirmation email failed for {assignment.employee.email}: {str(e)}",
                    target_user=assignment.employee,
                    target_model="HardwareAssignment",
                    target_id=assignment.id
                )
            
            # ========== SUCCESS MESSAGE ==========
            success_msg = f'{return_type} completed successfully! {len(returned_item_ids)} hardware item(s) verified, marked as available, and relocated to {manager_branch} branch.'
            if not all_items_returned:
                remaining = items.count() - len(returned_item_ids)
                success_msg += f' {remaining} item(s) remaining in the assignment.'
            if email_sent:
                success_msg += f' Email sent to {assignment.employee.email}'
            else:
                success_msg += ' (Email could not be sent)'
            messages.success(request, success_msg)
            
            # Force refresh the page to show updated status
            return redirect('view_assignments')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Assignment Management",
                description=f"Assignment return failed: {str(e)}",
                target_user=request.user,
                target_model="HardwareAssignment",
                target_id=assignment.id,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Error processing return: {str(e)}')
            return redirect('return_assignment', assignment_id=assignment.id)
    
    # ========== GET REQUEST - SHOW RETURN FORM ==========
    verification_status = request.session.pop('verification_status', [])
    
    # Count unverified items
    unverified_items_count = len([item for item in items if not item.is_verified and not (hasattr(item, 'returned_at') and item.returned_at)])
    verified_items_count = len([item for item in items if item.is_verified and not (hasattr(item, 'returned_at') and item.returned_at)])
    
    context = {
        'assignment': assignment,
        'items': items,
        'verification_status': verification_status,
        'today': timezone.now().date(),
        'already_returned_items': already_returned_items,
        'unverified_items_count': unverified_items_count,
        'verified_items_count': verified_items_count,
    }
    return render(request, 'manager/return_assignment.html', context)
    
def send_partial_return_email(assignment, items, returned_item_ids):
    """
    Send partial return confirmation email to employee
    """
    from django.core.mail import send_mail
    from django.conf import settings
    
    employee = assignment.employee
    employee_name = employee.get_full_name() or employee.username
    manager_name = assignment.assigned_by.get_full_name() or assignment.assigned_by.username
    
    returned_items = [item for item in items if item.id in returned_item_ids]
    remaining_items = [item for item in items if item.id not in returned_item_ids]
    
    # Build hardware list for returned items
    returned_list_html = ''
    returned_list_text = ''
    for idx, item in enumerate(returned_items, 1):
        asset_number = item.returned_asset_number or 'N/A'
        hw_type = item.hardware.hardware_type.name
        condition = item.condition_at_return or 'Good condition'
        
        returned_list_html += f"""
            <tr>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{idx}</td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><strong>{hw_type}</strong></td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{asset_number}</code></td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{condition}</td>
            </tr>
        """
        returned_list_text += f"{idx}. {hw_type} - Asset: {asset_number} | Condition: {condition}\n"
    
    # Build hardware list for remaining items
    remaining_list_html = ''
    remaining_list_text = ''
    for idx, item in enumerate(remaining_items, 1):
        asset_number = item.hardware.asset_number or 'N/A'
        hw_type = item.hardware.hardware_type.name
        
        remaining_list_html += f"""
            <tr>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{idx}</td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><strong>{hw_type}</strong></td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{asset_number}</code></td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><span class="badge badge-warning">Pending Return</span></td>
            </tr>
        """
        remaining_list_text += f"{idx}. {hw_type} - Asset: {asset_number} (Pending Return)\n"
    
    subject = f'📋 Partial Return Confirmed - Assignment {assignment.assignment_id}'
    
    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(90deg, #fd7e14 0%, #ffc107 100%); color: white; padding: 25px; text-align: center; border-radius: 8px 8px 0 0; }}
            .header h2 {{ margin: 0; font-weight: 300; }}
            .content {{ background: #ffffff; padding: 30px; border: 1px solid #e9ecef; border-top: none; border-radius: 0 0 8px 8px; }}
            .info-box {{ background: #f8f9fa; padding: 15px 20px; margin: 15px 0; border-radius: 6px; border-left: 4px solid #fd7e14; }}
            .info-box h6 {{ margin: 0 0 5px 0; color: #495057; }}
            .table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 14px; }}
            .table th {{ background: #fd7e14; color: white; padding: 10px 12px; text-align: left; }}
            .table td {{ padding: 10px 12px; border-bottom: 1px solid #e9ecef; }}
            .table tr:hover {{ background: #f8f9fa; }}
            .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
            .badge-success {{ background: #28a745; color: white; }}
            .badge-warning {{ background: #ffc107; color: #212529; }}
            .badge-info {{ background: #17a2b8; color: white; }}
            .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px; text-align: center; }}
            .btn {{ display: inline-block; padding: 10px 24px; background: linear-gradient(90deg, #fd7e14 0%, #ffc107 100%); color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
            .btn:hover {{ opacity: 0.9; }}
            .alert {{ padding: 12px 16px; border-radius: 6px; margin: 10px 0; }}
            .alert-success {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
            .alert-warning {{ background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }}
            code {{ background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; }}
            @media (max-width: 600px) {{
                .table {{ font-size: 12px; }}
                .table th, .table td {{ padding: 6px 8px; }}
                .content {{ padding: 15px; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>📋 Partial Return Confirmation</h2>
            </div>
            <div class="content">
                <p>Dear <strong>{employee_name}</strong>,</p>
                
                <div class="alert alert-warning">
                    <strong>📋 Partial Return Completed!</strong>
                    <br>
                    {len(returned_items)} hardware item(s) have been returned and verified by <strong>{manager_name}</strong>.
                    {len(remaining_items)} item(s) still pending return.
                </div>
                
                <div class="info-box">
                    <h6>📌 Assignment Information</h6>
                    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                        <tr>
                            <td style="padding: 4px 0; width: 35%;"><strong>Assignment ID:</strong></td>
                            <td style="padding: 4px 0;"><code>{assignment.assignment_id}</code></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Project:</strong></td>
                            <td style="padding: 4px 0;">{assignment.project.project_name}</td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Exam City:</strong></td>
                            <td style="padding: 4px 0;"><span class="badge badge-info">{assignment.exam_city}</span></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Return Date:</strong></td>
                            <td style="padding: 4px 0;"><span class="badge badge-success">{timezone.now().date().strftime('%d %B %Y')}</span></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Verified By:</strong></td>
                            <td style="padding: 4px 0;">{manager_name}</td>
                        </tr>
                    </table>
                </div>
                
                <h6 style="margin-top: 20px; margin-bottom: 10px;">✅ Returned Hardware Items</h6>
                <div style="overflow-x: auto;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th style="width: 40px;">#</th>
                                <th>Hardware Type</th>
                                <th>Asset Number</th>
                                <th>Condition at Return</th>
                            </tr>
                        </thead>
                        <tbody>
                            {returned_list_html}
                        </tbody>
                    </table>
                </div>
                <p style="margin: 10px 0;"><span class="badge badge-success">Returned: {len(returned_items)} item(s)</span></p>
                
                <h6 style="margin-top: 20px; margin-bottom: 10px;">⏳ Pending Return Items</h6>
                <div style="overflow-x: auto;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th style="width: 40px;">#</th>
                                <th>Hardware Type</th>
                                <th>Asset Number</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {remaining_list_html}
                        </tbody>
                    </table>
                </div>
                <p style="margin: 10px 0;"><span class="badge badge-warning">Pending: {len(remaining_items)} item(s)</span></p>
                
                <div class="alert alert-warning">
                    <strong>📌 Next Steps for Pending Items:</strong>
                    <ul style="margin: 8px 0 0 20px;">
                        <li>Return the remaining {len(remaining_items)} hardware item(s) as soon as possible</li>
                        <li>Contact your manager if you need assistance</li>
                        <li>Thank you for returning the items so far</li>
                    </ul>
                </div>
                
                <p style="margin-top: 20px;">
                    <a href="http://eduquityinventory.co.in/" class="btn">🚀 Go to Hardware Portal</a>
                </p>
                
                <div class="footer">
                    <p><strong>Eduquity Hardware Management Team</strong><br>
                    Established in 2000 - Thought-leader in the Indian assessment industry</p>
                    <p><em>This is an automated email. Please do not reply to this message.</em></p>
                    <p style="font-size: 11px;">For any questions, please contact your manager: {manager_name}</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    plain_message = f"""
    PARTIAL RETURN CONFIRMATION
    ===========================
    
    Dear {employee_name},
    
    📋 Partial Return Completed!
    
    {len(returned_items)} hardware item(s) have been returned and verified by {manager_name}.
    {len(remaining_items)} item(s) still pending return.
    
    Assignment Information:
    -----------------------
    Assignment ID: {assignment.assignment_id}
    Project: {assignment.project.project_name}
    Exam City: {assignment.exam_city}
    Return Date: {timezone.now().date().strftime('%d %B %Y')}
    Verified By: {manager_name}
    
    Returned Hardware Items:
    -----------------------
    {returned_list_text}
    
    Pending Return Items:
    --------------------
    {remaining_list_text}
    
    Next Steps for Pending Items:
    ----------------------------
    - Return the remaining {len(remaining_items)} hardware item(s) as soon as possible
    - Contact your manager if you need assistance
    - Thank you for returning the items so far
    
    For any questions, please contact your manager: {manager_name}
    
    ---
    Eduquity Hardware Management Team
    """
    
    send_mail(
        subject=subject,
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[employee.email],
        html_message=html_message,
        fail_silently=False,
    )

# ============================================================
# SEND RETURN CONFIRMATION EMAIL (Helper Function)
# ============================================================

def send_return_confirmation_email(assignment, items):
    """
    Send return confirmation email to employee
    With logging
    """
    from django.core.mail import send_mail
    from django.conf import settings
    
    employee = assignment.employee
    employee_name = employee.get_full_name() or employee.username
    manager_name = assignment.assigned_by.get_full_name() or assignment.assigned_by.username
    
    # Build hardware list for email
    hardware_list_html = ''
    hardware_list_text = ''
    for idx, item in enumerate(items, 1):
        asset_number = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
        hw_type = item.hardware.hardware_type.name
        condition = item.condition_at_return or 'Good condition'
        
        hardware_list_html += f"""
            <tr>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{idx}</td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><strong>{hw_type}</strong></td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{asset_number}</code></td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{condition}</td>
            </tr>
        """
        hardware_list_text += f"{idx}. {hw_type} - Asset: {asset_number} | Condition: {condition}\n"
    
    subject = f'Hardware Return Confirmation - {assignment.project.project_name}'
    
    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(90deg, #28a745 0%, #20c997 100%); color: white; padding: 25px; text-align: center; border-radius: 8px 8px 0 0; }}
            .header h2 {{ margin: 0; font-weight: 300; }}
            .content {{ background: #ffffff; padding: 30px; border: 1px solid #e9ecef; border-top: none; border-radius: 0 0 8px 8px; }}
            .info-box {{ background: #f8f9fa; padding: 15px 20px; margin: 15px 0; border-radius: 6px; border-left: 4px solid #28a745; }}
            .info-box h6 {{ margin: 0 0 5px 0; color: #495057; }}
            .table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 14px; }}
            .table th {{ background: #28a745; color: white; padding: 10px 12px; text-align: left; }}
            .table td {{ padding: 10px 12px; border-bottom: 1px solid #e9ecef; }}
            .table tr:hover {{ background: #f8f9fa; }}
            .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
            .badge-success {{ background: #28a745; color: white; }}
            .badge-info {{ background: #17a2b8; color: white; }}
            .badge-warning {{ background: #ffc107; color: #212529; }}
            .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px; text-align: center; }}
            .btn {{ display: inline-block; padding: 10px 24px; background: linear-gradient(90deg, #28a745 0%, #20c997 100%); color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
            .btn:hover {{ opacity: 0.9; }}
            .alert {{ padding: 12px 16px; border-radius: 6px; margin: 10px 0; }}
            .alert-success {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
            .alert-info {{ background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }}
            code {{ background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; }}
            @media (max-width: 600px) {{
                .table {{ font-size: 12px; }}
                .table th, .table td {{ padding: 6px 8px; }}
                .content {{ padding: 15px; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>✅ Hardware Return Confirmation</h2>
            </div>
            <div class="content">
                <p>Dear <strong>{employee_name}</strong>,</p>
                
                <div class="alert alert-success">
                    <strong>✅ Assignment Returned Successfully!</strong>
                    <br>
                    All hardware items have been returned and verified by <strong>{manager_name}</strong>.
                </div>
                
                <div class="info-box">
                    <h6>📌 Assignment Information</h6>
                    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                        <tr>
                            <td style="padding: 4px 0; width: 35%;"><strong>Assignment ID:</strong></td>
                            <td style="padding: 4px 0;"><code>{assignment.assignment_id}</code></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Project:</strong></td>
                            <td style="padding: 4px 0;">{assignment.project.project_name} ({assignment.project.project_id})</td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Exam City:</strong></td>
                            <td style="padding: 4px 0;"><span class="badge badge-info">{assignment.exam_city}</span></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Return Date:</strong></td>
                            <td style="padding: 4px 0;"><span class="badge badge-success">{assignment.actual_return_date.strftime('%d %B %Y')}</span></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Verified By:</strong></td>
                            <td style="padding: 4px 0;">{manager_name}</td>
                        </tr>
                    </table>
                </div>
                
                <h6 style="margin-top: 20px; margin-bottom: 10px;">🖥️ Returned Hardware Items</h6>
                <div style="overflow-x: auto;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th style="width: 40px;">#</th>
                                <th>Hardware Type</th>
                                <th>Asset Number</th>
                                <th>Condition at Return</th>
                            </tr>
                        </thead>
                        <tbody>
                            {hardware_list_html}
                        </tbody>
                    </table>
                </div>
                <p style="margin: 10px 0;"><span class="badge badge-success">Total Items Returned: {len(items)}</span></p>
                
                <div class="alert alert-info">
                    <strong>📌 What's Next:</strong>
                    <ul style="margin: 8px 0 0 20px;">
                        <li>You have successfully completed this assignment</li>
                        <li>All hardware has been returned and marked as <strong>Available</strong></li>
                        <li>You can view your completed assignments in the portal</li>
                        <li>Thank you for taking care of the hardware</li>
                    </ul>
                </div>
                
                <p style="margin-top: 20px;">
                    <a href="http://eduquityinventory.co.in/" class="btn">🚀 Go to Hardware Portal</a>
                </p>
                
                <div class="footer">
                    <p><strong>Eduquity Hardware Management Team</strong><br>
                    Established in 2000 - Thought-leader in the Indian assessment industry</p>
                    <p><em>This is an automated email. Please do not reply to this message.</em></p>
                    <p style="font-size: 11px;">For any questions, please contact your manager: {manager_name}</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    plain_message = f"""
    HARDWARE RETURN CONFIRMATION
    ============================
    
    Dear {employee_name},
    
    ✅ Assignment Returned Successfully!
    
    All hardware items have been returned and verified by {manager_name}.
    
    Assignment Information:
    -----------------------
    Assignment ID: {assignment.assignment_id}
    Project: {assignment.project.project_name} ({assignment.project.project_id})
    Exam City: {assignment.exam_city}
    Return Date: {assignment.actual_return_date.strftime('%d %B %Y')}
    Verified By: {manager_name}
    
    Returned Hardware Items:
    -----------------------
    {hardware_list_text}
    
    Total Items Returned: {len(items)}
    
    What's Next:
    -----------
    - You have successfully completed this assignment
    - All hardware has been returned and marked as Available
    - You can view your completed assignments in the portal
    - Thank you for taking care of the hardware
    
    For any questions, please contact your manager: {manager_name}
    
    ---
    Eduquity Hardware Management Team
    """
    
    send_mail(
        subject=subject,
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[employee.email],
        html_message=html_message,
        fail_silently=False,
    )

# ============== SERIAL NUMBER VIEWS ==============
# views.py - Updated Asset Verification Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse
from datetime import datetime
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from hardware_management.utils.audit import create_audit_log, get_client_ip


# ============================================================
# VIEW ASSET ENTRIES
# ============================================================

@login_required
def view_serial_entries(request):
    """
    Manager view all asset entries for verification
    With audit logging and partial return tracking
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Verification",
            description=f"Unauthorized access to asset entries by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET ASSIGNMENTS ==========
    assignments = HardwareAssignment.objects.filter(
        assigned_by=request.user,
        actual_return_date__isnull=True
    ).prefetch_related(
        'hardwareassignmentitem_set__hardware__hardware_type',
        'hardwareassignmentitem_set__asset_entry__entered_by',
        'hardwareassignmentitem_set__asset_entry__verified_by'
    ).order_by('-assigned_date')
    
    total_verified = 0
    total_matched = 0
    total_mismatch = 0
    total_pending = 0
    total_returned = 0
    
    for assignment in assignments:
        items = assignment.hardwareassignmentitem_set.all()
        assignment.total_items = items.count()
        assignment.verified_count = 0
        assignment.matched_count = 0
        assignment.mismatch_count = 0
        assignment.pending_count = 0
        assignment.returned_count = 0
        assignment.asset_entries = []
        
        for item in items:
            expected_asset = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
            
            # Check if item is returned (partial return)
            is_returned = hasattr(item, 'returned_at') and item.returned_at is not None
            
            if is_returned:
                assignment.returned_count += 1
                total_returned += 1
            
            try:
                asset_entry = item.asset_entry
                is_match = (asset_entry.entered_asset_number == expected_asset)
                
                entry_data = {
                    'id': asset_entry.id,
                    'item_id': item.id,
                    'entered_asset_number': asset_entry.entered_asset_number,
                    'expected_asset': expected_asset,
                    'hardware_type': item.hardware.hardware_type.name,
                    'model': item.hardware.model_name,
                    'asset_number': expected_asset,
                    'entered_by': asset_entry.entered_by,
                    'entered_at': asset_entry.entered_at,
                    'verified': asset_entry.verified,
                    'verified_by': asset_entry.verified_by,
                    'verified_at': asset_entry.verified_at,
                    'is_match': is_match,
                    'match_status': 'verified' if asset_entry.verified else ('matched' if is_match else 'mismatch'),
                    'returned_at': item.returned_at if is_returned else None,
                    'return_status': 'Returned' if is_returned else 'Pending Return'
                }
                assignment.asset_entries.append(entry_data)
                
                if asset_entry.verified:
                    assignment.verified_count += 1
                    total_verified += 1
                else:
                    if is_match:
                        assignment.matched_count += 1
                        total_matched += 1
                    else:
                        assignment.mismatch_count += 1
                        total_mismatch += 1
                        
            except HardwareAssetEntry.DoesNotExist:
                entry_data = {
                    'id': None,
                    'item_id': item.id,
                    'entered_asset_number': None,
                    'expected_asset': expected_asset,
                    'hardware_type': item.hardware.hardware_type.name,
                    'model': item.hardware.model_name,
                    'asset_number': expected_asset,
                    'entered_by': None,
                    'entered_at': None,
                    'verified': False,
                    'verified_by': None,
                    'verified_at': None,
                    'is_match': False,
                    'match_status': 'pending',
                    'returned_at': item.returned_at if is_returned else None,
                    'return_status': 'Returned' if is_returned else 'Pending Return'
                }
                assignment.asset_entries.append(entry_data)
                assignment.pending_count += 1
                total_pending += 1
    
    total_assignments = assignments.count()
    total_hardware_items = sum(assignment.total_items for assignment in assignments)
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_asset_entries_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Asset Verification",
            description=f"Manager {request.user.username} viewed asset entries ({total_assignments} assignments, {total_verified} verified, {total_pending} pending, {total_returned} returned)",
            target_user=request.user,
            new_value={
                'total_assignments': total_assignments,
                'total_verified': total_verified,
                'total_matched': total_matched,
                'total_mismatch': total_mismatch,
                'total_pending': total_pending,
                'total_returned': total_returned,
                'completion_rate': round((total_verified / (total_verified + total_pending + total_matched + total_mismatch) * 100) if (total_verified + total_pending + total_matched + total_mismatch) > 0 else 0, 2)
            }
        )
        request.session['last_asset_entries_view'] = timezone.now().timestamp()
    
    context = {
        'assignments': assignments,
        'total_assignments': total_assignments,
        'total_verified': total_verified,
        'total_matched': total_matched,
        'total_mismatch': total_mismatch,
        'total_pending': total_pending,
        'total_returned': total_returned,
        'total_hardware_items': total_hardware_items,
    }
    return render(request, 'manager/view_asset_entries.html', context)

# ============================================================
# EXPORT ALL EMPLOYEES HARDWARE
# ============================================================

@login_required
def export_all_employees_hardware(request):
    """
    Export current active hardware data for all employees to Excel
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Unauthorized export attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET ASSIGNMENTS ==========
    assignments = HardwareAssignment.objects.filter(
        assigned_by=request.user,
        actual_return_date__isnull=True
    ).order_by('-assigned_date')
    
    if not assignments.exists():
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Export attempt by {request.user.username} - No active assignments found",
            target_user=request.user
        )
        messages.warning(request, 'No active assignments found to export.')
        return redirect('view_serial_entries')
    
    try:
        # ========== CREATE WORKBOOK ==========
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Current Active Hardware"
        
        # ========== DEFINE STYLES ==========
        header_font = Font(bold=True, color="FFFFFF", size=11)
        header_fill = PatternFill(start_color="2C3E50", end_color="2C3E50", fill_type="solid")
        subheader_font = Font(bold=True, color="FFFFFF", size=10)
        subheader_fill = PatternFill(start_color="3498DB", end_color="3498DB", fill_type="solid")
        success_fill = PatternFill(start_color="DFF0D8", end_color="DFF0D8", fill_type="solid")
        warning_fill = PatternFill(start_color="FCF8E3", end_color="FCF8E3", fill_type="solid")
        danger_fill = PatternFill(start_color="F2DEDE", end_color="F2DEDE", fill_type="solid")
        info_fill = PatternFill(start_color="D9EDF7", end_color="D9EDF7", fill_type="solid")
        
        border = Border(
            left=Side(style='thin'), right=Side(style='thin'),
            top=Side(style='thin'), bottom=Side(style='thin')
        )
        center_alignment = Alignment(horizontal="center", vertical="center")
        
        # ========== TITLE ==========
        ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=12)
        title_cell = ws.cell(row=1, column=1, value="EDUQUITY HARDWARE MANAGEMENT SYSTEM")
        title_cell.font = Font(bold=True, size=16)
        title_cell.alignment = center_alignment
        
        ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=12)
        subtitle_cell = ws.cell(row=2, column=1, value=f"CURRENT ACTIVE HARDWARE REPORT - Generated on {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        subtitle_cell.font = Font(size=11, italic=True)
        subtitle_cell.alignment = center_alignment
        
        ws.merge_cells(start_row=3, start_column=1, end_row=3, end_column=6)
        summary_title = ws.cell(row=3, column=1, value="▶ CURRENT ACTIVE HARDWARE SUMMARY")
        summary_title.font = Font(bold=True, size=12)
        summary_title.fill = PatternFill(start_color="F0F0F0", end_color="F0F0F0", fill_type="solid")
        
        # ========== PREPARE DATA ==========
        employee_data = {}
        total_hardware = 0
        total_verified = 0
        total_matched = 0
        total_mismatch = 0
        total_pending = 0
        total_overdue = 0
        total_due_soon = 0
        
        today = timezone.now().date()
        due_soon_date = today + timezone.timedelta(days=3)
        
        for assignment in assignments:
            employee = assignment.employee
            emp_id = employee.id
            if emp_id not in employee_data:
                employee_data[emp_id] = {
                    'employee_name': employee.get_full_name() or employee.username,
                    'email': employee.email,
                    'phone': employee.phone or '-',
                    'created_at': employee.date_joined.strftime("%d/%m/%Y") if employee.date_joined else '-',
                    'hardware_items': []
                }
            
            items = HardwareAssignmentItem.objects.filter(assignment=assignment)
            
            for item in items:
                total_hardware += 1
                
                is_overdue = assignment.expected_return_date < today
                is_due_soon = assignment.expected_return_date <= due_soon_date and assignment.expected_return_date >= today
                
                if is_overdue:
                    total_overdue += 1
                elif is_due_soon:
                    total_due_soon += 1
                
                hardware_info = {
                    'assignment_id': str(assignment.assignment_id)[:8],
                    'exam_city': assignment.exam_city or 'Not Specified',
                    'assigned_date': assignment.assigned_date.strftime("%d/%m/%Y"),
                    'expected_return': assignment.expected_return_date.strftime("%d/%m/%Y"),
                    'is_overdue': is_overdue,
                    'is_due_soon': is_due_soon,
                    'hardware_type': item.hardware.hardware_type.name,
                    'model': item.hardware.model_name,
                    'brand': item.hardware.brand or '-',
                    'assigned_serial': item.hardware.serial_number,
                    'status': item.hardware.get_status_display(),
                    'entered_serial': '-',
                    'verification_status': 'Pending',
                    'verified_by': '-',
                    'verified_at': '-',
                    'condition': item.condition_at_assignment or '-'
                }
                
                try:
                    serial_entry = HardwareSerialEntry.objects.get(assignment_item=item)
                    hardware_info['entered_serial'] = serial_entry.serial_number
                    
                    if serial_entry.verified:
                        hardware_info['verification_status'] = 'Verified'
                        hardware_info['verified_by'] = serial_entry.verified_by.get_full_name() or serial_entry.verified_by.username if serial_entry.verified_by else '-'
                        hardware_info['verified_at'] = serial_entry.verified_at.strftime("%d/%m/%Y %H:%M") if serial_entry.verified_at else '-'
                        total_verified += 1
                        
                        if serial_entry.serial_number == item.hardware.serial_number:
                            hardware_info['match_status'] = 'Verified - Correct'
                        else:
                            hardware_info['match_status'] = 'Verified - Mismatch'
                    else:
                        if serial_entry.serial_number == item.hardware.serial_number:
                            hardware_info['verification_status'] = 'Matched - Pending'
                            total_matched += 1
                        else:
                            hardware_info['verification_status'] = 'Mismatch'
                            total_mismatch += 1
                            
                except HardwareSerialEntry.DoesNotExist:
                    total_pending += 1
                    hardware_info['verification_status'] = 'Not Entered'
                
                employee_data[emp_id]['hardware_items'].append(hardware_info)
        
        # ========== WRITE MAIN REPORT ==========
        current_row = 5
        
        for emp_id, emp_data in employee_data.items():
            if not emp_data['hardware_items']:
                continue
                
            # Employee Header
            ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=12)
            emp_header = ws.cell(row=current_row, column=1, value=f"EMPLOYEE: {emp_data['employee_name']} - {emp_data['email']}")
            emp_header.font = Font(bold=True, size=12, color="FFFFFF")
            emp_header.fill = PatternFill(start_color="2C3E50", end_color="2C3E50", fill_type="solid")
            emp_header.alignment = center_alignment
            current_row += 1
            
            # Employee Details
            details = [
                ["📧 Email", emp_data['email']],
                ["📞 Phone", emp_data['phone']],
                ["📅 Employee Since", emp_data['created_at']],
                ["🖥️ Active Hardware", len(emp_data['hardware_items'])]
            ]
            
            for i, (label, value) in enumerate(details):
                ws.cell(row=current_row, column=1, value=label).font = Font(bold=True)
                ws.cell(row=current_row, column=2, value=value)
                current_row += 1
            
            current_row += 1
            
            # Hardware Table Header
            headers = ['S.No', 'Assignment ID', 'Exam City', 'Assigned Date', 'Expected Return', 'Return Status',
                       'Hardware Type', 'Model', 'Brand', 'Assigned Serial', 'Entered Serial', 
                       'Verification Status', 'Condition']
            
            for col_num, header in enumerate(headers, 1):
                cell = ws.cell(row=current_row, column=col_num, value=header)
                cell.font = subheader_font
                cell.fill = subheader_fill
                cell.alignment = center_alignment
                cell.border = border
            
            current_row += 1
            
            # Write Hardware Items
            sno = 1
            for item in emp_data['hardware_items']:
                return_status = "Normal"
                row_fill = None
                
                if item['is_overdue']:
                    return_status = "⚠️ OVERDUE"
                    row_fill = danger_fill
                elif item['is_due_soon']:
                    return_status = "⚡ DUE SOON"
                    row_fill = warning_fill
                
                row_data = [
                    sno, item['assignment_id'], item['exam_city'], item['assigned_date'],
                    item['expected_return'], return_status, item['hardware_type'],
                    item['model'], item['brand'], item['assigned_serial'], item['entered_serial'],
                    item['verification_status'], item['condition']
                ]
                
                for col_num, value in enumerate(row_data, 1):
                    cell = ws.cell(row=current_row, column=col_num, value=value)
                    cell.border = border
                    
                    if row_fill:
                        cell.fill = row_fill
                    elif item['verification_status'] == 'Verified':
                        cell.fill = success_fill
                    elif item['verification_status'] == 'Matched - Pending':
                        cell.fill = info_fill
                    elif item['verification_status'] == 'Mismatch':
                        cell.fill = danger_fill
                    elif item['verification_status'] == 'Not Entered':
                        cell.fill = warning_fill
                    
                    if col_num in [4, 5, 6, 12]:
                        cell.alignment = center_alignment
                
                sno += 1
                current_row += 1
            
            current_row += 2
        
        # ========== GRAND SUMMARY ==========
        current_row += 1
        ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=12)
        summary_cell = ws.cell(row=current_row, column=1, value="▶ GRAND SUMMARY - CURRENT ACTIVE HARDWARE")
        summary_cell.font = Font(bold=True, size=14, color="FFFFFF")
        summary_cell.fill = PatternFill(start_color="2C3E50", end_color="2C3E50", fill_type="solid")
        summary_cell.alignment = center_alignment
        current_row += 1
        
        summary_data = [
            ["Total Active Employees", len([e for e in employee_data.values() if e['hardware_items']])],
            ["Total Active Hardware Items", total_hardware],
            ["✅ Verified Items", total_verified],
            ["🟦 Matched Items (Pending)", total_matched],
            ["❌ Mismatched Items", total_mismatch],
            ["⏳ Pending Entry Items", total_pending],
            ["⚠️ Overdue Items", total_overdue],
            ["⚡ Due Soon Items", total_due_soon],
            ["📈 Completion Rate", f"{round((total_verified / total_hardware * 100) if total_hardware > 0 else 0, 2)}%"],
            ["👤 Generated By", request.user.get_full_name() or request.user.username],
            ["📅 Generated On", datetime.now().strftime("%d/%m/%Y %H:%M:%S")]
        ]
        
        for label, value in summary_data:
            label_cell = ws.cell(row=current_row, column=1, value=label)
            label_cell.font = Font(bold=True)
            value_cell = ws.cell(row=current_row, column=2, value=value)
            current_row += 1
        
        # ========== AUTO-ADJUST COLUMN WIDTHS ==========
        for col in range(1, len(headers) + 1):
            column_letter = get_column_letter(col)
            max_length = 0
            
            for row in range(1, current_row):
                cell_value = ws.cell(row=row, column=col).value
                if cell_value:
                    max_length = max(max_length, len(str(cell_value)))
            
            adjusted_width = min(max_length + 4, 45)
            ws.column_dimensions[column_letter].width = adjusted_width
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="export_report",
            module="Export Reports",
            description=f"Manager {request.user.username} exported active hardware report ({total_hardware} items, {len(employee_data)} employees)",
            target_user=request.user,
            new_value={
                'total_hardware': total_hardware,
                'total_employees': len(employee_data),
                'verified': total_verified,
                'matched': total_matched,
                'mismatch': total_mismatch,
                'pending': total_pending,
                'overdue': total_overdue,
                'due_soon': total_due_soon,
                'completion_rate': round((total_verified / total_hardware * 100) if total_hardware > 0 else 0, 2)
            }
        )
        
        # ========== PREPARE RESPONSE ==========
        filename = f"active_hardware_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        response = HttpResponse(
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        wb.save(response)
        messages.success(request, f'✅ Active hardware report exported successfully! ({total_hardware} items)')
        return response
        
    except Exception as e:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_error",
            module="Export Reports",
            description=f"Export failed for {request.user.username}: {str(e)}",
            target_user=request.user,
            new_value={'error': str(e)}
        )
        messages.error(request, f'Error exporting report: {str(e)}')
        return redirect('view_serial_entries')


# ============================================================
# VERIFY SINGLE ASSET ENTRY
# ============================================================

@login_required
def verify_asset_entry(request, entry_id):
    """
    Verify a single asset entry and send confirmation email
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Verification",
            description=f"Unauthorized verification attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    asset_entry = get_object_or_404(HardwareAssetEntry, id=entry_id)
    
    # Check authorization
    if asset_entry.hardware_item.assignment.assigned_by != request.user:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Verification",
            description=f"Unauthorized verification attempt on asset entry {entry_id} by {request.user.username}",
            target_user=request.user,
            target_model="HardwareAssetEntry",
            target_id=entry_id
        )
        messages.error(request, 'Unauthorized access!')
        return redirect('view_serial_entries')
    
    # ========== CHECK MATCH ==========
    hardware = asset_entry.hardware_item.hardware
    expected_asset = hardware.asset_number
    entered_asset = asset_entry.entered_asset_number
    is_match = entered_asset == expected_asset
    
    if is_match:
        # ========== VERIFY ==========
        asset_entry.verified = True
        asset_entry.verified_by = request.user
        asset_entry.verified_at = timezone.now()
        asset_entry.save()
        
        # Update hardware status
        hardware.status = 'in_use'
        hardware.save()
        
        # ========== AUDIT LOG - SUCCESS ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="asset_verify",
            module="Asset Verification",
            description=f"Manager {request.user.username} verified asset '{entered_asset}' for {hardware.hardware_type.name} assigned to {asset_entry.hardware_item.assignment.employee.get_full_name() or asset_entry.hardware_item.assignment.employee.username}",
            target_user=asset_entry.hardware_item.assignment.employee,
            target_model="HardwareAssetEntry",
            target_id=asset_entry.id,
            old_value={
                'asset': entered_asset,
                'status': 'pending',
                'hardware': hardware.serial_number
            },
            new_value={
                'asset': entered_asset,
                'status': 'verified',
                'verified_by': request.user.username,
                'verified_at': timezone.now().isoformat()
            }
        )
        
        # ========== SEND EMAIL ==========
        try:
            send_verification_confirmation_email(asset_entry)
            messages.success(
                request,
                f'✅ Asset entry verified successfully! Asset {entered_asset} is now marked as in use. Email sent to {asset_entry.hardware_item.assignment.employee.email}'
            )
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Asset Verification",
                description=f"Verification email failed for {asset_entry.hardware_item.assignment.employee.email}: {str(e)}",
                target_user=asset_entry.hardware_item.assignment.employee,
                target_model="HardwareAssetEntry",
                target_id=asset_entry.id
            )
            messages.success(
                request,
                f'✅ Asset entry verified successfully! Asset {entered_asset} is now marked as in use. But email could not be sent: {str(e)}'
            )
    else:
        # ========== AUDIT LOG - MISMATCH ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Verification",
            description=f"Verification failed for manager {request.user.username}: Entered asset '{entered_asset}' does not match expected '{expected_asset}' for {hardware.hardware_type.name}",
            target_user=asset_entry.hardware_item.assignment.employee,
            target_model="HardwareAssetEntry",
            target_id=asset_entry.id,
            old_value={
                'entered_asset': entered_asset,
                'expected_asset': expected_asset,
                'hardware': hardware.serial_number
            }
        )
        messages.error(
            request,
            f'❌ Cannot verify - Entered asset number "{entered_asset}" does not match expected asset number "{expected_asset}"!'
        )
    
    return redirect('view_serial_entries')


# ============================================================
# VERIFY ALL EMPLOYEE ENTRIES
# ============================================================

@login_required
def verify_all_employee_entries(request, assignment_id):
    """
    Single click verify all pending asset entries for an employee and send confirmation email
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Verification",
            description=f"Unauthorized bulk verification attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    assignment = get_object_or_404(
        HardwareAssignment,
        id=assignment_id,
        assigned_by=request.user,
        actual_return_date__isnull=True
    )
    
    items = HardwareAssignmentItem.objects.filter(assignment=assignment)
    verified_count = 0
    skipped_count = 0
    mismatch_count = 0
    no_entry_count = 0
    verified_entries = []
    mismatched_items = []
    
    for item in items:
        try:
            asset_entry = item.asset_entry
            expected_asset = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
            is_match = asset_entry.entered_asset_number == expected_asset
            
            if not asset_entry.verified and is_match:
                # Verify this entry
                asset_entry.verified = True
                asset_entry.verified_by = request.user
                asset_entry.verified_at = timezone.now()
                asset_entry.save()
                
                # Update hardware status
                item.hardware.status = 'in_use'
                item.hardware.save()
                verified_count += 1
                verified_entries.append(asset_entry)
                
            elif asset_entry.verified:
                skipped_count += 1
                
            elif not is_match and asset_entry.entered_asset_number:
                mismatch_count += 1
                mismatched_items.append({
                    'hardware_type': item.hardware.hardware_type.name,
                    'expected': expected_asset,
                    'entered': asset_entry.entered_asset_number
                })
                
        except HardwareAssetEntry.DoesNotExist:
            no_entry_count += 1
            continue
    
    employee_name = assignment.employee.get_full_name() or assignment.employee.username
    
    # ========== AUDIT LOG ==========
    if verified_count > 0:
        create_audit_log(
            request=request,
            user=request.user,
            action="asset_verify_all",
            module="Asset Verification",
            description=f"Manager {request.user.username} verified {verified_count} asset(s) for {employee_name}",
            target_user=assignment.employee,
            target_model="HardwareAssignment",
            target_id=assignment.id,
            old_value={
                'employee': employee_name,
                'assignment_id': str(assignment.assignment_id),
                'items_processed': items.count(),
                'verified_count': verified_count,
                'skipped_count': skipped_count,
                'mismatch_count': mismatch_count,
                'no_entry_count': no_entry_count
            },
            new_value={
                'verified_entries': [{
                    'asset': e.entered_asset_number,
                    'hardware': e.hardware_item.hardware.serial_number,
                    'verified_by': request.user.username,
                    'verified_at': timezone.now().isoformat()
                } for e in verified_entries]
            }
        )
    
    # ========== SEND EMAIL ==========
    if verified_count > 0:
        try:
            send_bulk_verification_confirmation_email(assignment, verified_entries, verified_count)
            messages.success(
                request,
                f'✅ Successfully verified {verified_count} asset(s) for {employee_name}! Email sent to {assignment.employee.email}'
            )
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Asset Verification",
                description=f"Bulk verification email failed for {assignment.employee.email}: {str(e)}",
                target_user=assignment.employee,
                target_model="HardwareAssignment",
                target_id=assignment.id
            )
            messages.success(
                request,
                f'✅ Successfully verified {verified_count} asset(s) for {employee_name}! But email could not be sent: {str(e)}'
            )
        
        if mismatch_count > 0:
            messages.warning(
                request,
                f'⚠️ Skipped {mismatch_count} item(s) with asset number mismatch for {employee_name}.'
            )
            
        if skipped_count > 0:
            messages.info(
                request,
                f'ℹ️ {skipped_count} item(s) were already verified.'
            )
            
        if no_entry_count > 0:
            messages.info(
                request,
                f'ℹ️ {no_entry_count} item(s) have no asset entry yet.'
            )
    else:
        if mismatch_count > 0 and no_entry_count == 0:
            messages.error(
                request,
                f'❌ No items verified. Found {mismatch_count} item(s) with asset number mismatch for {employee_name}.'
            )
        elif skipped_count > 0 and mismatch_count == 0 and no_entry_count == 0:
            messages.warning(
                request,
                f'ℹ️ All {skipped_count} item(s) are already verified for {employee_name}.'
            )
        elif no_entry_count > 0 and mismatch_count == 0 and skipped_count == 0:
            messages.warning(
                request,
                f'ℹ️ No asset entries found for {employee_name}. Employee needs to enter asset numbers first.'
            )
        else:
            messages.warning(
                request,
                f'⚠️ No eligible items found for verification for {employee_name}. Items must have matching asset numbers and not be already verified.'
            )
    
    return redirect('view_serial_entries')


# ============================================================
# VERIFY SERIAL ENTRY (Legacy - Keeping for compatibility)
# ============================================================

@login_required
def verify_serial_entry(request, entry_id):
    """
    Verify a serial entry (legacy method)
    With audit logging
    """
    
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Verification",
            description=f"Unauthorized serial verification attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    serial_entry = get_object_or_404(HardwareSerialEntry, id=entry_id)
    
    if serial_entry.assignment_item.assignment.assigned_by != request.user:
        messages.error(request, 'Unauthorized access!')
        return redirect('view_serial_entries')
    
    is_match = serial_entry.serial_number == serial_entry.assignment_item.hardware.serial_number
    
    if is_match:
        serial_entry.verified = True
        serial_entry.verified_by = request.user
        serial_entry.verified_at = timezone.now()
        serial_entry.save()
        
        hardware = serial_entry.assignment_item.hardware
        hardware.status = 'in_use'
        hardware.save()
        
        # Audit log for serial verification
        create_audit_log(
            request=request,
            user=request.user,
            action="asset_verify",
            module="Asset Verification",
            description=f"Manager {request.user.username} verified serial '{serial_entry.serial_number}' for {hardware.hardware_type.name}",
            target_user=serial_entry.assignment_item.assignment.employee,
            target_model="HardwareSerialEntry",
            target_id=serial_entry.id
        )
        
        messages.success(request, f'Serial entry verified successfully! Hardware is now marked as in use.')
    else:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Verification",
            description=f"Serial verification failed - Serial '{serial_entry.serial_number}' does not match expected",
            target_user=serial_entry.assignment_item.assignment.employee,
            target_model="HardwareSerialEntry",
            target_id=serial_entry.id
        )
        messages.error(request, 'Cannot verify - Serial number does not match the assigned hardware!')
    
    return redirect('view_serial_entries')


# ============================================================
# MANAGER VERIFICATION STATUS
# ============================================================
@login_required
def manager_verification_status(request):
    """
    Manager dashboard to see verification status across all assignments
    With audit logging and bulk reminder functionality
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Verification",
            description=f"Unauthorized verification status access by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    assignments = HardwareAssignment.objects.filter(
        assigned_by=request.user,
        actual_return_date__isnull=True
    ).order_by('-assigned_date')
    
    total_verified = 0
    total_matched = 0
    total_mismatch = 0
    total_pending = 0
    pending_assignments = []
    
    for assignment in assignments:
        items = HardwareAssignmentItem.objects.filter(assignment=assignment)
        total_items = items.count()
        verified_items = 0
        matched_items = 0
        mismatch_items = 0
        pending_items = 0
        
        for item in items:
            try:
                asset_entry = item.asset_entry
                expected_asset = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
                is_match = (asset_entry.entered_asset_number == expected_asset)
                
                if asset_entry.verified_at:
                    verified_items += 1
                else:
                    if is_match:
                        matched_items += 1
                    else:
                        mismatch_items += 1
            except HardwareAssetEntry.DoesNotExist:
                pending_items += 1
        
        verified_percentage = (verified_items / total_items * 100) if total_items > 0 else 0
        matched_percentage = (matched_items / total_items * 100) if total_items > 0 else 0
        mismatch_percentage = (mismatch_items / total_items * 100) if total_items > 0 else 0
        pending_percentage = (pending_items / total_items * 100) if total_items > 0 else 0
        
        assignment.verification_stats = {
            'total': total_items,
            'verified': verified_items,
            'matched': matched_items,
            'mismatch': mismatch_items,
            'pending': pending_items,
            'verified_percentage': verified_percentage,
            'matched_percentage': matched_percentage,
            'mismatch_percentage': mismatch_percentage,
            'pending_percentage': pending_percentage,
            'progress': verified_percentage
        }
        
        total_verified += verified_items
        total_matched += matched_items
        total_mismatch += mismatch_items
        total_pending += pending_items
        
        # Track assignments with pending or mismatch issues
        if pending_items > 0 or mismatch_items > 0:
            pending_assignments.append({
                'assignment': assignment,
                'pending': pending_items,
                'mismatch': mismatch_items
            })
    
    # ========== HANDLE BULK REMINDER EMAIL ==========
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'send_bulk_reminder':
            try:
                # Get all assignments with pending entries or mismatches
                pending_assignments_list = []
                for assignment in assignments:
                    items = HardwareAssignmentItem.objects.filter(assignment=assignment)
                    pending = 0
                    mismatch = 0
                    
                    for item in items:
                        try:
                            asset_entry = item.asset_entry
                            if not asset_entry.verified_at:
                                mismatch += 1
                        except HardwareAssetEntry.DoesNotExist:
                            pending += 1
                    
                    if pending > 0 or mismatch > 0:
                        pending_assignments_list.append({
                            'assignment': assignment,
                            'pending': pending,
                            'mismatch': mismatch
                        })
                
                if pending_assignments_list:
                    # Send emails
                    success_count = 0
                    failed_emails = []
                    
                    for pending_data in pending_assignments_list:
                        try:
                            send_bulk_reminder_email(
                                pending_data['assignment'], 
                                pending_data['pending'], 
                                pending_data['mismatch']
                            )
                            success_count += 1
                        except Exception as e:
                            failed_emails.append({
                                'email': pending_data['assignment'].employee.email,
                                'error': str(e)
                            })
                    
                    create_audit_log(
                        request=request,
                        user=request.user,
                        action="system_info",
                        module="Asset Verification",
                        description=f"Manager {request.user.username} sent bulk reminder emails to {success_count} employees",
                        target_user=request.user,
                        new_value={
                            'total_sent': success_count,
                            'total_employees': len(pending_assignments_list),
                            'failed': len(failed_emails)
                        }
                    )
                    
                    if success_count > 0:
                        messages.success(request, f'✅ Reminder emails sent to {success_count} employee(s)!')
                    if failed_emails:
                        messages.warning(request, f'⚠️ Failed to send to {len(failed_emails)} employee(s). Check logs for details.')
                    if not success_count and not failed_emails:
                        messages.info(request, 'All employees have completed their asset entries!')
                else:
                    messages.info(request, '✅ All employees have completed their asset entries!')
                
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Asset Verification",
                    description=f"Bulk reminder email failed: {str(e)}",
                    target_user=request.user
                )
                messages.error(request, f'Failed to send bulk reminder emails: {str(e)}')
            
            return redirect('manager_verification_status')
        
        elif action == 'send_reminder' and request.POST.get('assignment_id'):
            assignment_id = request.POST.get('assignment_id')
            try:
                assignment = HardwareAssignment.objects.get(
                    id=assignment_id,
                    assigned_by=request.user
                )
                
                # Calculate pending counts
                items = HardwareAssignmentItem.objects.filter(assignment=assignment)
                pending = 0
                mismatch = 0
                for item in items:
                    try:
                        asset_entry = item.asset_entry
                        if not asset_entry.verified_at:
                            mismatch += 1
                    except HardwareAssetEntry.DoesNotExist:
                        pending += 1
                
                send_bulk_reminder_email(assignment, pending, mismatch)
                
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_info",
                    module="Asset Verification",
                    description=f"Manager {request.user.username} sent reminder email to {assignment.employee.email}",
                    target_user=assignment.employee,
                    target_model="HardwareAssignment",
                    target_id=assignment.id
                )
                
                messages.success(request, f'Reminder email sent to {assignment.employee.email}')
            except Exception as e:
                messages.error(request, f'Failed to send email: {str(e)}')
            
            return redirect('manager_verification_status')
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_verification_status_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Asset Verification",
            description=f"Manager {request.user.username} viewed verification status ({assignments.count()} assignments, {total_verified} verified, {total_pending} pending)",
            target_user=request.user,
            new_value={
                'assignments': assignments.count(),
                'total_verified': total_verified,
                'total_matched': total_matched,
                'total_mismatch': total_mismatch,
                'total_pending': total_pending,
                'completion_rate': round((total_verified / (total_verified + total_pending + total_matched + total_mismatch) * 100) if (total_verified + total_pending + total_matched + total_mismatch) > 0 else 0, 2)
            }
        )
        request.session['last_verification_status_view'] = timezone.now().timestamp()
    
    context = {
        'assignments': assignments,
        'total_verified': total_verified,
        'total_matched': total_matched,
        'total_mismatch': total_mismatch,
        'total_pending': total_pending,
        'today': timezone.now().date(),
        'pending_assignments': pending_assignments,
        'has_pending': bool(pending_assignments),
    }
    return render(request, 'manager/verification_status.html', context)


def send_bulk_reminder_email(assignment, pending_count, mismatch_count):
    """
    Send reminder email to employee about pending asset entries with mismatch details
    """
    from django.core.mail import send_mail
    from django.conf import settings
    
    try:
        employee = assignment.employee
        employee_name = employee.get_full_name() or employee.username
        manager_name = assignment.assigned_by.get_full_name() or assignment.assigned_by.username
        
        expected_return_date = assignment.expected_return_date.strftime('%d %B %Y') if assignment.expected_return_date else 'N/A'
        
        # Determine subject based on issues
        if mismatch_count > 0 and pending_count > 0:
            subject = f'⚠️ Action Required: Asset Number Issues - Assignment {assignment.assignment_id}'
            status_icon = '⚠️'
            main_alert = f'You have {pending_count} item(s) with no entry and {mismatch_count} item(s) with mismatched asset numbers.'
            alert_type = 'danger'
        elif mismatch_count > 0:
            subject = f'⚠️ Asset Number Mismatch - Assignment {assignment.assignment_id}'
            status_icon = '⚠️'
            main_alert = f'You have {mismatch_count} item(s) with mismatched asset numbers.'
            alert_type = 'danger'
        else:
            subject = f'📋 Action Required: Enter Asset Numbers for Assignment {assignment.assignment_id}'
            status_icon = '📋'
            main_alert = f'You have {pending_count} hardware item(s) pending asset number entry.'
            alert_type = 'warning'
        
        # Build next steps based on conditions
        next_steps_html = []
        if pending_count > 0:
            next_steps_html.append('Click <strong>"Enter Asset"</strong> to input the Asset Numbers from your physical devices')
        if mismatch_count > 0:
            next_steps_html.append('Click <strong>"Edit"</strong> to correct the Asset Numbers')
        
        next_steps_html_str = ' or '.join(next_steps_html) if next_steps_html else 'Complete the asset verification process'
        
        # Build plain text next steps
        next_steps_plain = []
        if pending_count > 0:
            next_steps_plain.append('Click "Enter Asset" to input the Asset Numbers from your physical devices')
        if mismatch_count > 0:
            next_steps_plain.append('Click "Edit" to correct the Asset Numbers')
        
        next_steps_plain_str = ' or '.join(next_steps_plain) if next_steps_plain else 'Complete the asset verification process'
        
        html_message = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(90deg, #E04D00 0%, #FF6B1A 100%); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
                .header h2 {{ margin: 0; font-weight: 300; }}
                .content {{ background: #ffffff; padding: 30px; border: 1px solid #e9ecef; border-top: none; border-radius: 0 0 8px 8px; }}
                .info-box {{ background: #f8f9fa; padding: 15px 20px; margin: 15px 0; border-radius: 6px; border-left: 4px solid #E04D00; }}
                .info-box h6 {{ margin: 0 0 5px 0; color: #495057; }}
                .alert {{ padding: 12px 16px; border-radius: 6px; margin: 10px 0; }}
                .alert-warning {{ background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }}
                .alert-danger {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }}
                .btn {{ display: inline-block; padding: 10px 24px; background: #E04D00; color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
                .btn:hover {{ background: #c44500; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px; text-align: center; }}
                .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; color: white; }}
                .badge-danger {{ background: #dc3545; }}
                .badge-warning {{ background: #ffc107; color: #333; }}
                .badge-info {{ background: #17a2b8; }}
                code {{ background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; }}
                .summary-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 15px 0; }}
                .summary-item {{ background: #f8f9fa; padding: 10px; border-radius: 6px; text-align: center; }}
                .summary-item .number {{ font-size: 24px; font-weight: bold; display: block; }}
                .summary-item .label {{ font-size: 12px; color: #6c757d; }}
                @media (max-width: 600px) {{
                    .content {{ padding: 15px; }}
                    .summary-grid {{ grid-template-columns: 1fr; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>{status_icon} Asset Entry {'Reminder' if pending_count > 0 and mismatch_count == 0 else 'Action Required'}</h2>
                </div>
                <div class="content">
                    <p>Dear <strong>{employee_name}</strong>,</p>
                    
                    <div class="alert alert-{alert_type}">
                        <strong>{'❌' if mismatch_count > 0 else '⏳'} Action Required!</strong> {main_alert}
                    </div>
                    
                    <div class="info-box">
                        <h6>📌 Assignment Details</h6>
                        <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                            <tr>
                                <td style="padding: 4px 0; width: 35%;"><strong>Assignment ID:</strong></td>
                                <td style="padding: 4px 0;"><code>{assignment.assignment_id}</code></td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Project:</strong></td>
                                <td style="padding: 4px 0;">{assignment.project.project_name}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Exam City:</strong></td>
                                <td style="padding: 4px 0;">{assignment.exam_city or 'Not specified'}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Expected Return:</strong></td>
                                <td style="padding: 4px 0;">{expected_return_date}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Manager:</strong></td>
                                <td style="padding: 4px 0;">{manager_name}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <div class="summary-grid">
                        <div class="summary-item">
                            <span class="number" style="color: #17a2b8;">{pending_count}</span>
                            <span class="label">Pending Entry</span>
                        </div>
                        <div class="summary-item">
                            <span class="number" style="color: #dc3545;">{mismatch_count}</span>
                            <span class="label">Mismatches</span>
                        </div>
                    </div>
                    
                    <div style="background: #e8f4fc; padding: 15px; border-radius: 6px; margin: 15px 0;">
                        <h6 style="margin: 0 0 10px 0; color: #0c5460;">📌 Next Steps:</h6>
                        <ol style="margin: 0 0 0 20px; color: #0c5460;">
                            <li style="padding: 4px 0;">Go to the <a href="http://eduquityinventory.co.in/" style="color: #E04D00; text-decoration: none; font-weight: 600;">Eduquity Hardware Portal</a></li>
                            <li style="padding: 4px 0;">Navigate to <strong>"My Assignments"</strong> section</li>
                            <li style="padding: 4px 0;">{next_steps_html_str}</li>
                            <li style="padding: 4px 0;">Your manager will verify the entries</li>
                        </ol>
                    </div>
                    
                    <p style="margin-top: 20px;">
                        <a href="http://eduquityinventory.co.in/" class="btn">🚀 Go to Portal</a>
                    </p>
                    
                    <div class="footer">
                        <p><strong>Eduquity Hardware Management Team</strong><br>
                        Established in 2000 - Thought-leader in the Indian assessment industry</p>
                        <p style="font-size: 11px;">For any issues, please contact your manager: {manager_name}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        plain_message = f"""
        {status_icon} ASSET ENTRY {'REMINDER' if pending_count > 0 and mismatch_count == 0 else 'ACTION REQUIRED'}
        {'=' * 50}
        
        Dear {employee_name},
        
        Action Required! {main_alert}
        
        Assignment Details:
        -------------------
        Assignment ID: {assignment.assignment_id}
        Project: {assignment.project.project_name}
        Exam City: {assignment.exam_city or 'Not specified'}
        Expected Return: {expected_return_date}
        Manager: {manager_name}
        
        Summary:
        --------
        Pending Entry: {pending_count}
        Mismatches: {mismatch_count}
        
        Next Steps:
        -----------
        1. Go to the Eduquity Hardware Portal (http://eduquityinventory.co.in/)
        2. Navigate to "My Assignments" section
        3. {next_steps_plain_str}
        4. Your manager will verify the entries
        
        ---
        Eduquity Hardware Management Team
        """
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[employee.email],
            html_message=html_message,
            fail_silently=False,
        )
        
    except Exception as e:
        print(f"Bulk reminder email failed for {employee.email}: {str(e)}")
        raise
# ============================================================
# MANAGER VERIFICATION DETAILS
# ============================================================
@login_required
def manager_verification_details(request, assignment_id):
    """
    Manager view to see detailed verification status for an assignment
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Verification",
            description=f"Unauthorized verification details access by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    assignment = get_object_or_404(
        HardwareAssignment,
        assignment_id=assignment_id,
        assigned_by=request.user,
        actual_return_date__isnull=True
    )
    
    items = HardwareAssignmentItem.objects.filter(assignment=assignment).select_related('hardware__hardware_type')
    
    verification_details = []
    all_verified = True
    
    for item in items:
        expected_asset = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
        
        try:
            asset_entry = item.asset_entry
            is_match = (asset_entry.entered_asset_number == expected_asset)
            
            verification_details.append({
                'item': item,
                'asset_entry': asset_entry,
                'is_match': is_match,
                'entered_asset': asset_entry.entered_asset_number,
                'expected_asset': expected_asset,
                'hardware_type': item.hardware.hardware_type.name,
                'model': item.hardware.model_name,
                'entered_by': asset_entry.entered_by,
                'entered_at': asset_entry.entered_at,
                'verified_at': asset_entry.verified_at,
                'verified_by': asset_entry.verified_by
            })
            if not is_match:
                all_verified = False
        except HardwareAssetEntry.DoesNotExist:
            verification_details.append({
                'item': item,
                'asset_entry': None,
                'is_match': False,
                'entered_asset': None,
                'expected_asset': expected_asset,
                'hardware_type': item.hardware.hardware_type.name,
                'model': item.hardware.model_name,
                'entered_by': None,
                'entered_at': None,
                'verified_at': None,
                'verified_by': None
            })
            all_verified = False
    
    total_items = len(verification_details)
    verified_count = sum(1 for d in verification_details if d['verified_at'] is not None)
    mismatch_count = sum(1 for d in verification_details if d['entered_asset'] and not d['is_match'])
    pending_count = sum(1 for d in verification_details if not d['entered_asset'])
    
    # Get employee name for logging
    employee_name = assignment.employee.get_full_name() or assignment.employee.username
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="system_info",
        module="Asset Verification",
        description=f"Manager {request.user.username} viewed verification details for assignment {assignment.assignment_id} ({employee_name})",
        target_user=assignment.employee,
        target_model="HardwareAssignment",
        target_id=assignment.id,
        new_value={
            'assignment_id': str(assignment.assignment_id),
            'employee': assignment.employee.username,
            'total_items': total_items,
            'verified': verified_count,
            'mismatch': mismatch_count,
            'pending': pending_count
        }
    )
    
    # ========== HANDLE EMAIL SENDING ==========
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'remind_employee' and pending_count > 0:
            try:
                send_reminder_email(assignment, pending_count)
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_info",
                    module="Asset Verification",
                    description=f"Manager {request.user.username} sent reminder email to {assignment.employee.email} for pending asset entries",
                    target_user=assignment.employee,
                    target_model="HardwareAssignment",
                    target_id=assignment.id
                )
                messages.success(request, f'Reminder email sent to {assignment.employee.email}')
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Asset Verification",
                    description=f"Reminder email failed for {assignment.employee.email}: {str(e)}",
                    target_user=assignment.employee,
                    target_model="HardwareAssignment",
                    target_id=assignment.id
                )
                messages.error(request, f'Failed to send email: {str(e)}')
        
        elif action == 'contact_employee' and mismatch_count > 0:
            try:
                send_mismatch_email(assignment, mismatch_count)
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_info",
                    module="Asset Verification",
                    description=f"Manager {request.user.username} sent mismatch notification to {assignment.employee.email} ({mismatch_count} mismatches)",
                    target_user=assignment.employee,
                    target_model="HardwareAssignment",
                    target_id=assignment.id
                )
                messages.success(request, f'Contact email sent to {assignment.employee.email}')
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Asset Verification",
                    description=f"Mismatch email failed for {assignment.employee.email}: {str(e)}",
                    target_user=assignment.employee,
                    target_model="HardwareAssignment",
                    target_id=assignment.id
                )
                messages.error(request, f'Failed to send email: {str(e)}')
        
        return redirect('manager_verification_details', assignment_id=assignment_id)
    
    context = {
        'assignment': assignment,
        'verification_details': verification_details,
        'all_verified': all_verified,
        'total_items': total_items,
        'verified_count': verified_count,
        'mismatch_count': mismatch_count,
        'pending_count': pending_count,
        'verified_percentage': (verified_count / total_items * 100) if total_items > 0 else 0,
    }
    return render(request, 'manager/verification_details.html', context)

# ============================================================
# HELPER FUNCTIONS - EMAIL SENDING
# ============================================================

def send_verification_confirmation_email(asset_entry):
    """
    Send verification confirmation email to employee for a single asset
    With HTML and plain text versions
    """
    from django.core.mail import send_mail
    from django.conf import settings
    from django.utils import timezone
    
    try:
        assignment = asset_entry.hardware_item.assignment
        employee = assignment.employee
        hardware = asset_entry.hardware_item.hardware
        manager = assignment.assigned_by
        
        employee_name = employee.get_full_name() or employee.username
        manager_name = manager.get_full_name() or manager.username
        
        subject = f'✅ Hardware Asset Verified - {assignment.project.project_name}'
        
        # Get exam center name
        exam_center_name = getattr(assignment, 'exam_center_name', None)
        if not exam_center_name:
            exam_center_name = 'Not specified'
        
        # Format dates
        assigned_date = assignment.assigned_date.strftime('%d %B %Y') if assignment.assigned_date else 'N/A'
        expected_return_date = assignment.expected_return_date.strftime('%d %B %Y') if assignment.expected_return_date else 'N/A'
        verified_at = timezone.now().strftime('%d %B %Y %H:%M')
        
        # Build hardware list
        hardware_list_html = f"""
        <tr>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{hardware.hardware_type.name}</td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{asset_entry.entered_asset_number}</code></td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{hardware.serial_number}</code></td>
        </tr>
        """
        
        html_message = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(90deg, #28a745 0%, #20c997 100%); color: white; padding: 25px; text-align: center; border-radius: 8px 8px 0 0; }}
                .header h2 {{ margin: 0; font-weight: 300; }}
                .content {{ background: #ffffff; padding: 30px; border: 1px solid #e9ecef; border-top: none; border-radius: 0 0 8px 8px; }}
                .info-box {{ background: #f8f9fa; padding: 15px 20px; margin: 15px 0; border-radius: 6px; border-left: 4px solid #28a745; }}
                .info-box h6 {{ margin: 0 0 5px 0; color: #495057; }}
                .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
                .badge-success {{ background: #28a745; color: white; }}
                .badge-info {{ background: #17a2b8; color: white; }}
                .badge-warning {{ background: #ffc107; color: #212529; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px; text-align: center; }}
                .btn {{ display: inline-block; padding: 10px 24px; background: #E04D00; color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
                .btn:hover {{ background: #c44500; }}
                .alert-success {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 12px 16px; border-radius: 6px; }}
                .alert-info {{ background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 12px 16px; border-radius: 6px; }}
                code {{ background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; }}
                .table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 14px; }}
                .table th {{ background: #f8f9fa; padding: 8px 12px; text-align: left; border-bottom: 2px solid #e9ecef; }}
                .table td {{ padding: 8px 12px; border-bottom: 1px solid #e9ecef; }}
                .table tr:last-child td {{ border-bottom: none; }}
                @media (max-width: 600px) {{
                    .table {{ font-size: 12px; }}
                    .table th, .table td {{ padding: 6px 8px; }}
                    .content {{ padding: 15px; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>✅ Hardware Asset Verified!</h2>
                </div>
                <div class="content">
                    <p>Dear <strong>{employee_name}</strong>,</p>
                    
                    <div class="alert-success">
                        <strong>🎉 Congratulations!</strong> Your hardware asset has been successfully verified by your manager.
                    </div>
                    
                    <div class="info-box">
                        <h6>📌 Verified Asset Details</h6>
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Hardware Type</th>
                                    <th>Asset Number</th>
                                    <th>Serial Number</th>
                                </tr>
                            </thead>
                            <tbody>
                                {hardware_list_html}
                            </tbody>
                        </table>
                    </div>
                    
                    <div class="info-box" style="border-left-color: #17a2b8;">
                        <h6>📌 Assignment Information</h6>
                        <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                            <tr>
                                <td style="padding: 4px 0; width: 35%;"><strong>Assignment ID:</strong></td>
                                <td style="padding: 4px 0;"><code>{assignment.assignment_id}</code></td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Project:</strong></td>
                                <td style="padding: 4px 0;">{assignment.project.project_name}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Exam City:</strong></td>
                                <td style="padding: 4px 0;">{assignment.exam_city or 'Not specified'}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Exam Center:</strong></td>
                                <td style="padding: 4px 0;">{exam_center_name}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Assigned Date:</strong></td>
                                <td style="padding: 4px 0;">{assigned_date}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Expected Return:</strong></td>
                                <td style="padding: 4px 0;">{expected_return_date}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Verified By:</strong></td>
                                <td style="padding: 4px 0;">{manager_name}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Verified On:</strong></td>
                                <td style="padding: 4px 0;">{verified_at}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <div class="alert-info">
                        <strong>📌 What's Next:</strong>
                        <ul style="margin: 8px 0 0 20px;">
                            <li>This hardware is now marked as <strong>In Use</strong></li>
                            <li>You can continue using the hardware for your exam duties</li>
                            <li>Remember to return the hardware by the due date: <strong>{expected_return_date}</strong></li>
                            <li>Keep the hardware safe and in good condition</li>
                        </ul>
                    </div>
                    
                    <p style="margin-top: 20px;">
                        <a href="http://eduquityinventory.co.in/" class="btn">🚀 Go to Hardware Portal</a>
                    </p>
                    
                    <div class="footer">
                        <p><strong>Eduquity Hardware Management Team</strong><br>
                        Established in 2000 - Thought-leader in the Indian assessment industry</p>
                        <p style="font-size: 11px;">For any questions, please contact your manager: {manager_name}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        plain_message = f"""
        HARDWARE ASSET VERIFIED
        ======================
        
        Dear {employee_name},
        
        ✅ Your hardware asset has been successfully verified by your manager!
        
        Verified Asset Details:
        -----------------------
        Hardware Type: {hardware.hardware_type.name}
        Asset Number: {asset_entry.entered_asset_number}
        Serial Number: {hardware.serial_number}
        
        Assignment Information:
        -----------------------
        Assignment ID: {assignment.assignment_id}
        Project: {assignment.project.project_name}
        Exam City: {assignment.exam_city or 'Not specified'}
        Exam Center: {exam_center_name}
        Assigned Date: {assigned_date}
        Expected Return: {expected_return_date}
        Verified By: {manager_name}
        Verified On: {verified_at}
        
        Next Steps:
        -----------
        - This hardware is now marked as In Use
        - Continue using the hardware for your exam duties
        - Return the hardware by: {expected_return_date}
        - Keep the hardware safe and in good condition
        
        For any questions, please contact your manager: {manager_name}
        
        ---
        Eduquity Hardware Management Team
        """
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[employee.email],
            html_message=html_message,
            fail_silently=False,
        )
        
    except Exception as e:
        print(f"Verification confirmation email failed: {str(e)}")
        raise


def send_bulk_verification_confirmation_email(assignment, verified_entries, verified_count):
    """
    Send bulk verification confirmation email to employee for multiple assets
    With HTML and plain text versions
    """
    from django.core.mail import send_mail
    from django.conf import settings
    from django.utils import timezone
    
    try:
        employee = assignment.employee
        manager = assignment.assigned_by
        
        employee_name = employee.get_full_name() or employee.username
        manager_name = manager.get_full_name() or manager.username
        
        # Get exam center name
        exam_center_name = getattr(assignment, 'exam_center_name', None)
        if not exam_center_name:
            exam_center_name = 'Not specified'
        
        # Format dates
        assigned_date = assignment.assigned_date.strftime('%d %B %Y') if assignment.assigned_date else 'N/A'
        expected_return_date = assignment.expected_return_date.strftime('%d %B %Y') if assignment.expected_return_date else 'N/A'
        verified_at = timezone.now().strftime('%d %B %Y %H:%M')
        
        # Build hardware list
        hardware_list_html = ''
        hardware_list_text = ''
        
        for idx, asset_entry in enumerate(verified_entries, 1):
            hardware = asset_entry.hardware_item.hardware
            
            hardware_list_html += f"""
            <tr>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{idx}</td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{hardware.hardware_type.name}</td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{asset_entry.entered_asset_number}</code></td>
                <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{hardware.serial_number}</code></td>
            </tr>
            """
            hardware_list_text += f"{idx}. {hardware.hardware_type.name} - Asset: {asset_entry.entered_asset_number} | Serial: {hardware.serial_number}\n"
        
        subject = f'✅ Hardware Assets Verified - {assignment.project.project_name} ({verified_count} items)'
        
        html_message = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(90deg, #28a745 0%, #20c997 100%); color: white; padding: 25px; text-align: center; border-radius: 8px 8px 0 0; }}
                .header h2 {{ margin: 0; font-weight: 300; }}
                .content {{ background: #ffffff; padding: 30px; border: 1px solid #e9ecef; border-top: none; border-radius: 0 0 8px 8px; }}
                .info-box {{ background: #f8f9fa; padding: 15px 20px; margin: 15px 0; border-radius: 6px; border-left: 4px solid #28a745; }}
                .info-box h6 {{ margin: 0 0 5px 0; color: #495057; }}
                .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
                .badge-success {{ background: #28a745; color: white; }}
                .badge-info {{ background: #17a2b8; color: white; }}
                .badge-warning {{ background: #ffc107; color: #212529; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px; text-align: center; }}
                .btn {{ display: inline-block; padding: 10px 24px; background: #E04D00; color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
                .btn:hover {{ background: #c44500; }}
                .alert-success {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 12px 16px; border-radius: 6px; }}
                .alert-info {{ background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 12px 16px; border-radius: 6px; }}
                code {{ background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; }}
                .table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 14px; }}
                .table th {{ background: #f8f9fa; padding: 8px 12px; text-align: left; border-bottom: 2px solid #2c3e50; color: #2c3e50; }}
                .table td {{ padding: 8px 12px; border-bottom: 1px solid #e9ecef; }}
                .table tr:last-child td {{ border-bottom: none; }}
                @media (max-width: 600px) {{
                    .table {{ font-size: 12px; }}
                    .table th, .table td {{ padding: 6px 8px; }}
                    .content {{ padding: 15px; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>✅ Hardware Assets Verified!</h2>
                </div>
                <div class="content">
                    <p>Dear <strong>{employee_name}</strong>,</p>
                    
                    <div class="alert-success">
                        <strong>🎉 Congratulations!</strong> <strong>{verified_count}</strong> of your hardware assets have been successfully verified by your manager.
                    </div>
                    
                    <div class="info-box">
                        <h6>📌 Verified Assets List</h6>
                        <table class="table">
                            <thead>
                                <tr>
                                    <th style="width: 40px;">#</th>
                                    <th>Hardware Type</th>
                                    <th>Asset Number</th>
                                    <th>Serial Number</th>
                                </tr>
                            </thead>
                            <tbody>
                                {hardware_list_html}
                            </tbody>
                        </table>
                        <p style="margin-top: 10px;"><span class="badge badge-success">Total: {verified_count} items verified</span></p>
                    </div>
                    
                    <div class="info-box" style="border-left-color: #17a2b8;">
                        <h6>📌 Assignment Information</h6>
                        <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                            <tr>
                                <td style="padding: 4px 0; width: 35%;"><strong>Assignment ID:</strong></td>
                                <td style="padding: 4px 0;"><code>{assignment.assignment_id}</code></td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Project:</strong></td>
                                <td style="padding: 4px 0;">{assignment.project.project_name}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Exam City:</strong></td>
                                <td style="padding: 4px 0;">{assignment.exam_city or 'Not specified'}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Exam Center:</strong></td>
                                <td style="padding: 4px 0;">{exam_center_name}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Assigned Date:</strong></td>
                                <td style="padding: 4px 0;">{assigned_date}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Expected Return:</strong></td>
                                <td style="padding: 4px 0;">{expected_return_date}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Verified By:</strong></td>
                                <td style="padding: 4px 0;">{manager_name}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Verified On:</strong></td>
                                <td style="padding: 4px 0;">{verified_at}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <div class="alert-info">
                        <strong>📌 What's Next:</strong>
                        <ul style="margin: 8px 0 0 20px;">
                            <li>All verified hardware is now marked as <strong>In Use</strong></li>
                            <li>You can continue using the hardware for your exam duties</li>
                            <li>Remember to return all hardware by the due date: <strong>{expected_return_date}</strong></li>
                            <li>Keep the hardware safe and in good condition</li>
                            <li>You can generate an Excel report from your dashboard</li>
                        </ul>
                    </div>
                    
                    <p style="margin-top: 20px;">
                        <a href="http://eduquityinventory.co.in/" class="btn">🚀 Go to Hardware Portal</a>
                    </p>
                    
                    <div class="footer">
                        <p><strong>Eduquity Hardware Management Team</strong><br>
                        Established in 2000 - Thought-leader in the Indian assessment industry</p>
                        <p style="font-size: 11px;">For any questions, please contact your manager: {manager_name}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        plain_message = f"""
        HARDWARE ASSETS VERIFIED
        ========================
        
        Dear {employee_name},
        
        ✅ {verified_count} of your hardware assets have been successfully verified by your manager!
        
        Verified Assets:
        ---------------
        {hardware_list_text}
        
        Total: {verified_count} items verified
        
        Assignment Information:
        -----------------------
        Assignment ID: {assignment.assignment_id}
        Project: {assignment.project.project_name}
        Exam City: {assignment.exam_city or 'Not specified'}
        Exam Center: {exam_center_name}
        Assigned Date: {assigned_date}
        Expected Return: {expected_return_date}
        Verified By: {manager_name}
        Verified On: {verified_at}
        
        Next Steps:
        -----------
        - All verified hardware is now marked as In Use
        - You can generate an Excel report from your dashboard
        - Continue using the hardware for your exam duties
        - Return all hardware by: {expected_return_date}
        - Keep the hardware safe and in good condition
        
        For any questions, please contact your manager: {manager_name}
        
        ---
        Eduquity Hardware Management Team
        """
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[employee.email],
            html_message=html_message,
            fail_silently=False,
        )
        
    except Exception as e:
        print(f"Bulk verification confirmation email failed: {str(e)}")
        raise


def send_reminder_email(assignment, pending_count):
    """
    Send reminder email to employee about pending asset entries
    With HTML and plain text versions
    """
    from django.core.mail import send_mail
    from django.conf import settings
    
    try:
        employee = assignment.employee
        employee_name = employee.get_full_name() or employee.username
        manager_name = assignment.assigned_by.get_full_name() or assignment.assigned_by.username
        
        # Format dates
        expected_return_date = assignment.expected_return_date.strftime('%d %B %Y') if assignment.expected_return_date else 'N/A'
        
        subject = f'📋 Action Required: Enter Asset Numbers for Assignment {assignment.assignment_id}'
        
        html_message = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(90deg, #E04D00 0%, #FF6B1A 100%); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
                .header h2 {{ margin: 0; font-weight: 300; }}
                .content {{ background: #ffffff; padding: 30px; border: 1px solid #e9ecef; border-top: none; border-radius: 0 0 8px 8px; }}
                .info-box {{ background: #f8f9fa; padding: 15px 20px; margin: 15px 0; border-radius: 6px; border-left: 4px solid #E04D00; }}
                .info-box h6 {{ margin: 0 0 5px 0; color: #495057; }}
                .alert {{ padding: 12px 16px; border-radius: 6px; margin: 10px 0; }}
                .alert-warning {{ background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }}
                .btn {{ display: inline-block; padding: 10px 24px; background: #E04D00; color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
                .btn:hover {{ background: #c44500; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px; text-align: center; }}
                .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; background: #E04D00; color: white; }}
                code {{ background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; }}
                .step {{ padding: 8px 12px; margin: 5px 0; background: #f8f9fa; border-radius: 4px; }}
                @media (max-width: 600px) {{
                    .content {{ padding: 15px; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>📋 Asset Entry Reminder</h2>
                </div>
                <div class="content">
                    <p>Dear <strong>{employee_name}</strong>,</p>
                    
                    <div class="alert alert-warning">
                        <strong>⏳ Action Required!</strong> You have <strong>{pending_count}</strong> hardware item(s) pending asset number entry.
                    </div>
                    
                    <div class="info-box">
                        <h6>📌 Assignment Details</h6>
                        <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                            <tr>
                                <td style="padding: 4px 0; width: 35%;"><strong>Assignment ID:</strong></td>
                                <td style="padding: 4px 0;"><code>{assignment.assignment_id}</code></td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Project:</strong></td>
                                <td style="padding: 4px 0;">{assignment.project.project_name}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Exam City:</strong></td>
                                <td style="padding: 4px 0;">{assignment.exam_city or 'Not specified'}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Expected Return:</strong></td>
                                <td style="padding: 4px 0;">{expected_return_date}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Manager:</strong></td>
                                <td style="padding: 4px 0;">{manager_name}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <p style="margin: 15px 0;">
                        <strong>Pending Items:</strong> <span class="badge">{pending_count}</span>
                    </p>
                    
                    <div style="background: #e8f4fc; padding: 15px; border-radius: 6px; margin: 15px 0;">
                        <h6 style="margin: 0 0 10px 0; color: #0c5460;">📌 Next Steps:</h6>
                        <ol style="margin: 0 0 0 20px; color: #0c5460;">
                            <li style="padding: 4px 0;">Go to the <a href="http://eduquityinventory.co.in/" style="color: #E04D00; text-decoration: none; font-weight: 600;">Eduquity Hardware Portal</a></li>
                            <li style="padding: 4px 0;">Navigate to <strong>"My Assignments"</strong> section</li>
                            <li style="padding: 4px 0;">Click <strong>"Enter Asset"</strong> to input the Asset Numbers from your physical devices</li>
                            <li style="padding: 4px 0;">Your manager will verify the entries</li>
                        </ol>
                    </div>
                    
                    <p style="margin-top: 20px;">
                        <a href="http://eduquityinventory.co.in/" class="btn">🚀 Go to Portal</a>
                    </p>
                    
                    <div class="footer">
                        <p><strong>Eduquity Hardware Management Team</strong><br>
                        Established in 2000 - Thought-leader in the Indian assessment industry</p>
                        <p style="font-size: 11px;">For any issues, please contact your manager: {manager_name}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        plain_message = f"""
        ASSET ENTRY REMINDER
        ====================
        
        Dear {employee_name},
        
        Action Required! You have {pending_count} hardware item(s) pending asset number entry.
        
        Assignment Details:
        -------------------
        Assignment ID: {assignment.assignment_id}
        Project: {assignment.project.project_name}
        Exam City: {assignment.exam_city or 'Not specified'}
        Expected Return: {expected_return_date}
        Manager: {manager_name}
        
        Pending Items: {pending_count}
        
        Next Steps:
        ----------
        1. Go to the Eduquity Hardware Portal (http://eduquityinventory.co.in/)
        2. Navigate to "My Assignments" section
        3. Click "Enter Asset" to input the Asset Numbers from your physical devices
        4. Your manager will verify the entries
        
        ---
        Eduquity Hardware Management Team
        """
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[employee.email],
            html_message=html_message,
            fail_silently=False,
        )
        
    except Exception as e:
        print(f"Reminder email failed: {str(e)}")
        raise


def send_mismatch_email(assignment, mismatch_count):
    """
    Send email to employee about asset number mismatches
    With HTML and plain text versions
    """
    from django.core.mail import send_mail
    from django.conf import settings
    
    try:
        employee = assignment.employee
        employee_name = employee.get_full_name() or employee.username
        manager_name = assignment.assigned_by.get_full_name() or assignment.assigned_by.username
        
        # Format dates
        expected_return_date = assignment.expected_return_date.strftime('%d %B %Y') if assignment.expected_return_date else 'N/A'
        
        subject = f'⚠️ Asset Number Mismatch Detected - Assignment {assignment.assignment_id}'
        
        html_message = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(90deg, #dc3545 0%, #e74c3c 100%); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
                .header h2 {{ margin: 0; font-weight: 300; }}
                .content {{ background: #ffffff; padding: 30px; border: 1px solid #e9ecef; border-top: none; border-radius: 0 0 8px 8px; }}
                .info-box {{ background: #f8f9fa; padding: 15px 20px; margin: 15px 0; border-radius: 6px; border-left: 4px solid #dc3545; }}
                .info-box h6 {{ margin: 0 0 5px 0; color: #495057; }}
                .alert {{ padding: 12px 16px; border-radius: 6px; margin: 10px 0; }}
                .alert-danger {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }}
                .btn {{ display: inline-block; padding: 10px 24px; background: #E04D00; color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
                .btn:hover {{ background: #c44500; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px; text-align: center; }}
                .badge-danger {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: 600; background: #dc3545; color: white; }}
                code {{ background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; }}
                .step {{ padding: 8px 12px; margin: 5px 0; background: #f8f9fa; border-radius: 4px; }}
                @media (max-width: 600px) {{
                    .content {{ padding: 15px; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>⚠️ Asset Number Mismatch Detected</h2>
                </div>
                <div class="content">
                    <p>Dear <strong>{employee_name}</strong>,</p>
                    
                    <div class="alert alert-danger">
                        <strong>❌ Mismatch Detected!</strong> You have <strong>{mismatch_count}</strong> hardware item(s) with asset number mismatch.
                    </div>
                    
                    <div class="info-box">
                        <h6>📌 Assignment Details</h6>
                        <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                            <tr>
                                <td style="padding: 4px 0; width: 35%;"><strong>Assignment ID:</strong></td>
                                <td style="padding: 4px 0;"><code>{assignment.assignment_id}</code></td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Project:</strong></td>
                                <td style="padding: 4px 0;">{assignment.project.project_name}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Exam City:</strong></td>
                                <td style="padding: 4px 0;">{assignment.exam_city or 'Not specified'}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Expected Return:</strong></td>
                                <td style="padding: 4px 0;">{expected_return_date}</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Manager:</strong></td>
                                <td style="padding: 4px 0;">{manager_name}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <p style="margin: 15px 0;">
                        <strong>Mismatched Items:</strong> <span class="badge-danger">{mismatch_count}</span>
                    </p>
                    
                    <div style="background: #fff3cd; padding: 15px; border-radius: 6px; margin: 15px 0; border-left: 4px solid #ffc107;">
                        <h6 style="margin: 0 0 10px 0; color: #856404;">📌 What to Do:</h6>
                        <ol style="margin: 0 0 0 20px; color: #856404;">
                            <li style="padding: 4px 0;">Verify the physical devices you have</li>
                            <li style="padding: 4px 0;">Check the correct Asset Number on each device</li>
                            <li style="padding: 4px 0;">Go to <a href="http://eduquityinventory.co.in/" style="color: #E04D00; text-decoration: none; font-weight: 600;">Eduquity Hardware Portal</a></li>
                            <li style="padding: 4px 0;">Navigate to <strong>"My Assignments"</strong> section</li>
                            <li style="padding: 4px 0;">Click <strong>"Edit"</strong> to correct the entered Asset Numbers</li>
                            <li style="padding: 4px 0;">Your manager will verify the updated entries</li>
                        </ol>
                    </div>
                    
                    <p style="margin-top: 20px;">
                        <a href="http://eduquityinventory.co.in/" class="btn">🚀 Go to Portal</a>
                    </p>
                    
                    <div class="footer">
                        <p><strong>Eduquity Hardware Management Team</strong><br>
                        Established in 2000 - Thought-leader in the Indian assessment industry</p>
                        <p style="font-size: 11px;">For any issues, please contact your manager: {manager_name}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        plain_message = f"""
        ASSET NUMBER MISMATCH DETECTED
        ==============================
        
        Dear {employee_name},
        
        Mismatch Detected! You have {mismatch_count} hardware item(s) with asset number mismatch.
        
        Assignment Details:
        -------------------
        Assignment ID: {assignment.assignment_id}
        Project: {assignment.project.project_name}
        Exam City: {assignment.exam_city or 'Not specified'}
        Expected Return: {expected_return_date}
        Manager: {manager_name}
        
        Mismatched Items: {mismatch_count}
        
        What to Do:
        -----------
        1. Verify the physical devices you have
        2. Check the correct Asset Number on each device
        3. Go to the Eduquity Hardware Portal (http://eduquityinventory.co.in/)
        4. Navigate to "My Assignments" section
        5. Click "Edit" to correct the entered Asset Numbers
        6. Your manager will verify the updated entries
        
        ---
        Eduquity Hardware Management Team
        """
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[employee.email],
            html_message=html_message,
            fail_silently=False,
        )
        
    except Exception as e:
        print(f"Mismatch email failed: {str(e)}")
        raise


# ============== EMPLOYEE VIEWS ==============
# views.py - Updated Employee Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.http import HttpResponse
from datetime import datetime
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import (
    CustomUser, HardwareAssignment, HardwareAssignmentItem, 
    HardwareType, HardwareAssetEntry, Hardware
)


# ============================================================
# EMPLOYEE DASHBOARD
# ============================================================

@login_required
def employee_dashboard(request):
    """
    Employee dashboard view with comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Dashboard",
            description=f"Unauthorized dashboard access attempt by {request.user.username} (user_type: {request.user.user_type})",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to access the employee dashboard.')
        return redirect('manager_dashboard')
    
    # ========== GET BRANCH LOCATION ==========
    branch_location = getattr(request.user, 'branch_location', None)
    if not branch_location and request.user.manager:
        branch_location = getattr(request.user.manager, 'branch_location', None)
    if not branch_location:
        branch_location = 'Head Office'
    
    # ========== GET ASSIGNMENTS ==========
    current_assignments = HardwareAssignment.objects.filter(
        employee=request.user,
        actual_return_date__isnull=True
    ).order_by('-assigned_date')
    
    current_assignments_count = current_assignments.count()
    completed_assignments_count = HardwareAssignment.objects.filter(
        employee=request.user,
        actual_return_date__isnull=False
    ).count()
    
    # ========== GET EXAM DETAILS ==========
    current_exam_city = None
    current_exam_center_name = None
    if current_assignments.exists():
        first_assignment = current_assignments.first()
        current_exam_city = first_assignment.exam_city
        current_exam_center_name = getattr(first_assignment, 'exam_center_name', None)
    
    # ========== CALCULATE PENDING ASSETS ==========
    pending_asset_count = 0
    total_assets = 0
    verified_assets = 0
    
    for assignment in current_assignments:
        items = HardwareAssignmentItem.objects.filter(assignment=assignment)
        assignment.total_items = items.count()
        assignment.entered_asset_count = 0
        assignment.verified_asset_count = 0
        assignment.pending_asset_count = 0
        
        for item in items:
            total_assets += 1
            if hasattr(item, 'asset_entry'):
                assignment.entered_asset_count += 1
                if item.asset_entry.verified:
                    assignment.verified_asset_count += 1
                    verified_assets += 1
            else:
                assignment.pending_asset_count += 1
        
        pending_asset_count += assignment.pending_asset_count
    
    employee_name = request.user.get_full_name() or request.user.username
    
    # ========== AUDIT LOG ==========
    # Log dashboard access (rate limited)
    if request.session.get('last_employee_dashboard_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Employee Dashboard",
            description=f"Employee {request.user.username} viewed dashboard",
            target_user=request.user,
            new_value={
                'current_assignments': current_assignments_count,
                'completed_assignments': completed_assignments_count,
                'pending_assets': pending_asset_count,
                'total_assets': total_assets,
                'verified_assets': verified_assets,
                'branch': branch_location,
                'exam_city': current_exam_city
            }
        )
        request.session['last_employee_dashboard_view'] = timezone.now().timestamp()
    
    context = {
        'current_assignments': current_assignments,
        'current_assignments_count': current_assignments_count,
        'completed_assignments_count': completed_assignments_count,
        'pending_asset_count': pending_asset_count,
        'current_exam_city': current_exam_city,
        'current_exam_center_name': current_exam_center_name,
        'employee_name': employee_name,
        'today': timezone.now().date(),
        'current_time': timezone.now(),
        'branch_location': branch_location,
        'user': request.user,
    }
    return render(request, 'employee/dashboard.html', context)


# ============================================================
# VIEW MY ASSIGNMENTS
# ============================================================

@login_required
def view_my_assignments(request):
    """
    Employee view all their assignments
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Assignments",
            description=f"Unauthorized assignments view attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('manager_dashboard')
    
    # ========== GET ASSIGNMENTS ==========
    assignments = HardwareAssignment.objects.filter(
        employee=request.user
    ).order_by('-assigned_date')
    
    total_assignments = assignments.count()
    active_assignments = assignments.filter(actual_return_date__isnull=True).count()
    completed_assignments = assignments.filter(actual_return_date__isnull=False).count()
    total_items = 0
    
    for assignment in assignments:
        items = HardwareAssignmentItem.objects.filter(assignment=assignment)
        assignment.total_items = items.count()
        total_items += assignment.total_items
        assignment.pending_asset_count = 0
        assignment.entered_asset_count = 0
        assignment.verified_asset_count = 0
        
        for item in items:
            if hasattr(item, 'asset_entry'):
                assignment.entered_asset_count += 1
                if item.asset_entry.verified:
                    assignment.verified_asset_count += 1
            else:
                assignment.pending_asset_count += 1
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_my_assignments_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Employee Assignments",
            description=f"Employee {request.user.username} viewed assignments ({total_assignments} total, {active_assignments} active)",
            target_user=request.user,
            new_value={
                'total_assignments': total_assignments,
                'active_assignments': active_assignments,
                'completed_assignments': completed_assignments,
                'total_items': total_items
            }
        )
        request.session['last_my_assignments_view'] = timezone.now().timestamp()
    
    context = {
        'assignments': assignments,
    }
    return render(request, 'employee/view_my_assignments.html', context)


# ============================================================
# MY ASSIGNMENT DETAILS
# ============================================================

@login_required
def my_assignment_details(request, assignment_id):
    """
    Employee view detailed assignment information
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Assignments",
            description=f"Unauthorized assignment details view attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('manager_dashboard')
    
    assignment = get_object_or_404(
        HardwareAssignment,
        assignment_id=assignment_id,
        employee=request.user
    )
    
    items = HardwareAssignmentItem.objects.filter(
        assignment=assignment
    ).select_related('hardware__hardware_type')
    
    # ========== PROCESS ITEMS ==========
    for item in items:
        item.asset_number = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
        item.serial_number_display = item.hardware.serial_number
        
        item.has_asset_entry = hasattr(item, 'asset_entry')
        if item.has_asset_entry:
            item.entered_asset = item.asset_entry.entered_asset_number
            item.is_verified = item.asset_entry.verified
        else:
            item.entered_asset = None
            item.is_verified = False
    
    total_items = items.count()
    pending_count = sum(1 for item in items if not hasattr(item, 'asset_entry'))
    entered_count = total_items - pending_count
    verified_count = sum(1 for item in items if hasattr(item, 'asset_entry') and item.asset_entry.verified)
    
    exam_center_name = getattr(assignment, 'exam_center_name', None)
    is_returned = assignment.actual_return_date is not None
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="system_info",
        module="Employee Assignments",
        description=f"Employee {request.user.username} viewed assignment {assignment.assignment_id} details",
        target_user=request.user,
        target_model="HardwareAssignment",
        target_id=assignment.id,
        new_value={
            'assignment_id': str(assignment.assignment_id),
            'project': assignment.project.project_name,
            'exam_city': assignment.exam_city,
            'total_items': total_items,
            'verified': verified_count,
            'pending': pending_count,
            'is_returned': is_returned
        }
    )
    
    context = {
        'assignment': assignment,
        'items': items,
        'total_items': total_items,
        'pending_count': pending_count,
        'entered_count': entered_count,
        'verified_count': verified_count,
        'exam_center_name': exam_center_name,
        'is_returned': is_returned,
    }
    return render(request, 'employee/my_assignment_details.html', context)


# ============================================================
# EXPORT ASSIGNMENT EXCEL
# ============================================================

@login_required
def export_assignment_excel(request, assignment_id):
    """
    Export assignment details to Excel
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Unauthorized export attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('manager_dashboard')
    
    assignment = get_object_or_404(
        HardwareAssignment,
        assignment_id=assignment_id,
        employee=request.user
    )
    
    items = HardwareAssignmentItem.objects.filter(
        assignment=assignment
    ).select_related('hardware__hardware_type')
    
    # ========== CHECK ITEMS ==========
    if not items.exists():
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Export attempt by {request.user.username} - No hardware items in assignment {assignment.assignment_id}",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id
        )
        messages.warning(request, 'No hardware items found in this assignment to export.')
        return redirect('my_assignment_details', assignment_id=assignment_id)
    
    # ========== GET HARDWARE TYPES ==========
    hardware_type_ids = items.values_list('hardware__hardware_type', flat=True).distinct()
    hardware_types = HardwareType.objects.filter(id__in=hardware_type_ids).order_by('name')
    
    if not hardware_types.exists():
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Export attempt by {request.user.username} - No hardware types in assignment {assignment.assignment_id}",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id
        )
        messages.warning(request, 'No hardware types found in this assignment.')
        return redirect('my_assignment_details', assignment_id=assignment_id)
    
    try:
        # ========== GROUP ITEMS BY TYPE ==========
        items_by_type = {}
        max_items_per_type = 0
        
        for hw_type in hardware_types:
            type_items = [item for item in items if item.hardware.hardware_type and item.hardware.hardware_type.id == hw_type.id]
            items_by_type[hw_type.id] = type_items
            if len(type_items) > max_items_per_type:
                max_items_per_type = len(type_items)
        
        # ========== CREATE WORKBOOK ==========
        wb = openpyxl.Workbook()
        ws = wb.active
        
        # ========== FILENAME ==========
        exam_center_name = getattr(assignment, 'exam_center_name', 'Not Specified') or 'NoCenter'
        exam_city = assignment.exam_city or 'NoCity'
        project_name = assignment.project.project_name if assignment.project else 'NoProject'
        employee_name = assignment.employee.get_full_name() or assignment.employee.username
        
        import re
        def clean_filename(text):
            text = str(text).replace(' ', '_')
            text = re.sub(r'[^a-zA-Z0-9_\-]', '', text)
            return text
        
        filename = f"{clean_filename(exam_center_name)}_{clean_filename(exam_city)}_{clean_filename(project_name)}_{clean_filename(employee_name)}.xlsx"
        
        assignment_id_str = str(assignment.assignment_id).replace('-', '')[:8]
        ws.title = f"Assign_{assignment_id_str}"
        
        # ========== STYLES ==========
        header_font = Font(bold=True, color="FFFFFF", size=11)
        header_fill = PatternFill(start_color="E04D00", end_color="E04D00", fill_type="solid")
        subheader_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
        border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )
        center_alignment = Alignment(horizontal="center", vertical="center")
        
        total_hw_types = hardware_types.count()
        total_columns = total_hw_types * 4
        
        # ========== TITLE ==========
        ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=total_columns)
        ws['A1'] = f"ASSIGNMENT DETAILS - {assignment.assignment_id}"
        ws['A1'].font = Font(bold=True, size=14)
        ws['A1'].alignment = center_alignment
        
        # ========== ASSIGNMENT INFO ==========
        info_start = 3
        info_data = [
            ['Project:', assignment.project.project_name if assignment.project else 'N/A'],
            ['Exam City:', assignment.exam_city or 'Not specified'],
            ['Exam Center:', getattr(assignment, 'exam_center_name', 'Not specified') or 'Not specified'],
            ['Employee:', assignment.employee.get_full_name() or assignment.employee.username],
            ['Assigned Date:', assignment.assigned_date.strftime('%d %b %Y') if assignment.assigned_date else 'N/A'],
            ['Expected Return:', assignment.expected_return_date.strftime('%d %b %Y') if assignment.expected_return_date else 'N/A'],
        ]
        
        for i, (label, value) in enumerate(info_data, start=info_start):
            ws.cell(row=i, column=1, value=label).font = Font(bold=True)
            ws.cell(row=i, column=2, value=value)
        
        # ========== HEADERS ==========
        header_row = info_start + len(info_data) + 2
        
        current_col = 1
        for hw_type in hardware_types:
            end_col = current_col + 3
            ws.merge_cells(start_row=header_row, start_column=current_col, end_row=header_row, end_column=end_col)
            hw_cell = ws.cell(row=header_row, column=current_col, value=f"{hw_type.name}")
            hw_cell.font = header_font
            hw_cell.fill = header_fill
            hw_cell.alignment = center_alignment
            hw_cell.border = border
            current_col = end_col + 1
        
        # ========== SUB-HEADERS ==========
        sub_header_row = header_row + 1
        current_col = 1
        for hw_type in hardware_types:
            ws.merge_cells(start_row=sub_header_row, start_column=current_col, end_row=sub_header_row, end_column=current_col + 3)
            type_label = ws.cell(row=sub_header_row, column=current_col, value=f"{hw_type.name} Details")
            type_label.font = Font(bold=True, color="FFFFFF", size=9)
            type_label.fill = subheader_fill
            type_label.alignment = center_alignment
            type_label.border = border
            current_col += 4
        
        # ========== DATA HEADERS ==========
        data_header_row = sub_header_row + 1
        current_col = 1
        for hw_type in hardware_types:
            headers = ['Asset Number', 'Entered Asset', 'Status', 'Verified By']
            for idx, header in enumerate(headers):
                cell = ws.cell(row=data_header_row, column=current_col + idx, value=header)
                cell.font = Font(bold=True, color="FFFFFF", size=8)
                cell.fill = PatternFill(start_color="2C3E50", end_color="2C3E50", fill_type="solid")
                cell.alignment = center_alignment
                cell.border = border
            current_col += 4
        
        # ========== DATA ROWS ==========
        data_start_row = data_header_row + 1
        
        total_items = items.count()
        verified_count = 0
        pending_count = 0
        not_entered_count = 0
        mismatch_count = 0
        
        for row_offset in range(max_items_per_type):
            current_row = data_start_row + row_offset
            current_col = 1
            
            for hw_type in hardware_types:
                type_items = items_by_type.get(hw_type.id, [])
                
                if row_offset < len(type_items):
                    item = type_items[row_offset]
                    
                    asset_number = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
                    entered_asset = 'Not Entered'
                    verification_status = 'Not Entered'
                    verified_by = '—'
                    is_verified = False
                    is_match = False
                    
                    try:
                        asset_entry = item.asset_entry
                        entered_asset = asset_entry.entered_asset_number
                        is_verified = asset_entry.verified
                        is_match = (entered_asset == asset_number)
                        
                        if is_verified:
                            verification_status = 'Verified ✓'
                            verified_count += 1
                            if asset_entry.verified_by:
                                verified_by = asset_entry.verified_by.get_full_name() or asset_entry.verified_by.username
                        elif is_match:
                            verification_status = 'Matched - Pending'
                            pending_count += 1
                        else:
                            verification_status = 'Mismatch ✗'
                            mismatch_count += 1
                    except HardwareAssetEntry.DoesNotExist:
                        not_entered_count += 1
                    
                    # Asset Number
                    asset_cell = ws.cell(row=current_row, column=current_col, value=asset_number)
                    asset_cell.border = border
                    asset_cell.alignment = center_alignment
                    asset_cell.fill = PatternFill(start_color="E7F1FF", end_color="E7F1FF", fill_type="solid")
                    asset_cell.font = Font(color="0d6efd", bold=True)
                    
                    # Entered Asset
                    entered_cell = ws.cell(row=current_row, column=current_col + 1, value=entered_asset)
                    entered_cell.border = border
                    entered_cell.alignment = center_alignment
                    
                    if is_verified:
                        entered_cell.fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
                        entered_cell.font = Font(color="006100", bold=True)
                    elif entered_asset != 'Not Entered' and is_match:
                        entered_cell.fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
                        entered_cell.font = Font(color="9C5700", bold=True)
                    elif entered_asset != 'Not Entered' and not is_match:
                        entered_cell.fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
                        entered_cell.font = Font(color="9C0006", bold=True)
                    else:
                        entered_cell.fill = PatternFill(start_color="D9D9D9", end_color="D9D9D9", fill_type="solid")
                        entered_cell.font = Font(color="666666", italic=True)
                    
                    # Status
                    status_cell = ws.cell(row=current_row, column=current_col + 2, value=verification_status)
                    status_cell.border = border
                    status_cell.alignment = center_alignment
                    status_cell.font = Font(bold=True)
                    
                    if verification_status == 'Verified ✓':
                        status_cell.fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
                        status_cell.font = Font(color="006100", bold=True)
                    elif verification_status == 'Matched - Pending':
                        status_cell.fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
                        status_cell.font = Font(color="9C5700", bold=True)
                    elif verification_status == 'Mismatch ✗':
                        status_cell.fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
                        status_cell.font = Font(color="9C0006", bold=True)
                    else:
                        status_cell.fill = PatternFill(start_color="D9D9D9", end_color="D9D9D9", fill_type="solid")
                        status_cell.font = Font(color="666666", italic=True)
                    
                    # Verified By
                    verified_by_cell = ws.cell(row=current_row, column=current_col + 3, value=verified_by)
                    verified_by_cell.border = border
                    verified_by_cell.alignment = center_alignment
                    
                    if is_verified:
                        verified_by_cell.fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
                        verified_by_cell.font = Font(color="006100")
                else:
                    for i in range(4):
                        empty_cell = ws.cell(row=current_row, column=current_col + i, value="—")
                        empty_cell.border = border
                        empty_cell.alignment = center_alignment
                        empty_cell.font = Font(color="999999", italic=True)
                
                current_col += 4
        
        # ========== SUMMARY ==========
        summary_row = data_start_row + max_items_per_type + 3
        
        ws.merge_cells(start_row=summary_row, start_column=1, end_row=summary_row, end_column=total_columns)
        summary_header = ws.cell(row=summary_row, column=1, value="📊 ASSIGNMENT SUMMARY")
        summary_header.font = Font(bold=True, size=12, color="FFFFFF")
        summary_header.fill = PatternFill(start_color="2C3E50", end_color="2C3E50", fill_type="solid")
        summary_header.alignment = center_alignment
        
        summary_start = summary_row + 2
        
        stats_data = [
            ['Total Hardware Items:', str(total_items)],
            ['✅ Verified:', str(verified_count)],
            ['⏳ Matched - Pending:', str(pending_count)],
            ['❌ Mismatch:', str(mismatch_count)],
            ['📝 Not Entered:', str(not_entered_count)],
            ['', ''],
            ['📈 Completion Rate:', f"{round((verified_count / total_items * 100) if total_items > 0 else 0, 1)}%"],
        ]
        
        for idx, (label, value) in enumerate(stats_data):
            row = summary_start + idx
            label_cell = ws.cell(row=row, column=1, value=label)
            label_cell.font = Font(bold=True)
            label_cell.border = border
            
            value_cell = ws.cell(row=row, column=2, value=value)
            value_cell.border = border
            
            if 'Verified' in label and verified_count > 0:
                value_cell.fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
                value_cell.font = Font(color="006100", bold=True)
            elif 'Matched' in label and pending_count > 0:
                value_cell.fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
                value_cell.font = Font(color="9C5700", bold=True)
            elif 'Mismatch' in label and mismatch_count > 0:
                value_cell.fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
                value_cell.font = Font(color="9C0006", bold=True)
            elif 'Not Entered' in label and not_entered_count > 0:
                value_cell.fill = PatternFill(start_color="D9D9D9", end_color="D9D9D9", fill_type="solid")
                value_cell.font = Font(color="666666", bold=True)
        
        # ========== ASSET SUMMARY ==========
        asset_summary_row = summary_start + len(stats_data) + 2
        ws.merge_cells(start_row=asset_summary_row, start_column=1, end_row=asset_summary_row, end_column=2)
        asset_summary_header = ws.cell(row=asset_summary_row, column=1, value="📋 ASSET NUMBER SUMMARY")
        asset_summary_header.font = Font(bold=True, size=11, color="FFFFFF")
        asset_summary_header.fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
        asset_summary_header.alignment = center_alignment
        
        asset_summary = []
        for item in items:
            asset_number = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
            status = "Not Entered"
            try:
                asset_entry = item.asset_entry
                if asset_entry.verified:
                    status = "Verified ✓"
                elif asset_entry.entered_asset_number == asset_number:
                    status = "Matched - Pending"
                else:
                    status = "Mismatch ✗"
            except HardwareAssetEntry.DoesNotExist:
                pass
            
            asset_summary.append({
                'asset': asset_number,
                'hardware_type': item.hardware.hardware_type.name if item.hardware.hardware_type else 'Unknown',
                'status': status
            })
        
        row = asset_summary_row + 2
        for idx, asset_info in enumerate(asset_summary, 1):
            ws.cell(row=row, column=1, value=f"{idx}. {asset_info['asset']}").border = border
            ws.cell(row=row, column=2, value=f"{asset_info['hardware_type']} - {asset_info['status']}").border = border
            
            status_cell = ws.cell(row=row, column=2)
            if 'Verified' in asset_info['status']:
                status_cell.fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
                status_cell.font = Font(color="006100", bold=True)
            elif 'Matched' in asset_info['status']:
                status_cell.fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
                status_cell.font = Font(color="9C5700", bold=True)
            elif 'Mismatch' in asset_info['status']:
                status_cell.fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
                status_cell.font = Font(color="9C0006", bold=True)
            else:
                status_cell.fill = PatternFill(start_color="D9D9D9", end_color="D9D9D9", fill_type="solid")
                status_cell.font = Font(color="666666", italic=True)
            
            row += 1
        
        # ========== SET COLUMN WIDTHS ==========
        for col in range(1, total_columns + 1):
            column_letter = get_column_letter(col)
            if col % 4 == 1:
                ws.column_dimensions[column_letter].width = 16
            elif col % 4 == 2:
                ws.column_dimensions[column_letter].width = 16
            elif col % 4 == 3:
                ws.column_dimensions[column_letter].width = 18
            else:
                ws.column_dimensions[column_letter].width = 18
        
        ws.column_dimensions['A'].width = 25
        ws.column_dimensions['B'].width = 35
        
        # ========== SET ROW HEIGHTS ==========
        ws.row_dimensions[header_row].height = 30
        ws.row_dimensions[sub_header_row].height = 25
        ws.row_dimensions[data_header_row].height = 25
        
        for row in range(data_start_row, data_start_row + max_items_per_type):
            ws.row_dimensions[row].height = 24
        
        ws.freeze_panes = ws.cell(row=data_header_row + 1, column=1)
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="export_report",
            module="Export Reports",
            description=f"Employee {request.user.username} exported assignment {assignment.assignment_id} to Excel ({total_items} items)",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id,
            new_value={
                'assignment_id': str(assignment.assignment_id),
                'project': assignment.project.project_name,
                'total_items': total_items,
                'verified': verified_count,
                'pending': pending_count,
                'mismatch': mismatch_count,
                'not_entered': not_entered_count,
                'completion_rate': round((verified_count / total_items * 100) if total_items > 0 else 0, 1)
            }
        )
        
        # ========== PREPARE RESPONSE ==========
        response = HttpResponse(
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        wb.save(response)
        messages.success(request, f'✅ Assignment exported successfully! ({total_items} items)')
        return response
        
    except Exception as e:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_error",
            module="Export Reports",
            description=f"Export failed for {request.user.username}: {str(e)}",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id,
            new_value={'error': str(e)}
        )
        messages.error(request, f'Error exporting assignment: {str(e)}')
        return redirect('my_assignment_details', assignment_id=assignment_id)


# ============== EMPLOYEE SERIAL NUMBER ENTRY ==============
# views.py - Updated Employee Asset Entry and API Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import (
    CustomUser, HardwareAssignment, HardwareAssignmentItem, 
    HardwareAssetEntry, HardwareSerialEntry, Hardware, HardwareType
)


# ============================================================
# ENTER SERIAL NUMBERS (ASSET NUMBERS)
# ============================================================

@login_required
def enter_serial_numbers(request, assignment_id):
    """
    Employee enters asset numbers for assigned hardware
    With comprehensive audit logging and auto-save/draft support
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Entry",
            description=f"Unauthorized asset entry attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('manager_dashboard')
    
    # ========== GET ASSIGNMENT ==========
    assignment = get_object_or_404(
        HardwareAssignment,
        assignment_id=assignment_id,
        employee=request.user
    )
    
    # ========== CHECK IF RETURNED ==========
    if assignment.actual_return_date:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Entry",
            description=f"Asset entry attempt on returned assignment {assignment.assignment_id} by {request.user.username}",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id
        )
        messages.error(request, 'This assignment has already been returned!')
        return redirect('employee_dashboard')
    
    # ========== GET ITEMS ==========
    items = HardwareAssignmentItem.objects.filter(
        assignment=assignment
    ).select_related('hardware__hardware_type')
    
    if not items.exists():
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Entry",
            description=f"Asset entry attempt on assignment {assignment.assignment_id} with no items",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id
        )
        messages.warning(request, 'No hardware items found in this assignment.')
        return redirect('my_assignment_details', assignment_id=assignment_id)
    
    verified_items = []
    pending_items = []
    
    # ========== CHECK FOR DRAFTS ==========
    # Get or create draft for this assignment
    draft, created = HardwareAssetDraft.objects.get_or_create(
        assignment=assignment,
        user=request.user,
        defaults={
            'data': {},
            'last_saved': timezone.now()
        }
    )
    
    draft_data = draft.data if draft.data else {}
    
    for item in items:
        item.asset_number = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
        item.serial_number = item.hardware.serial_number
        
        # Check if this item has been entered in the draft
        if str(item.id) in draft_data and draft_data[str(item.id)]:
            item.existing_asset = draft_data[str(item.id)]
            verified_items.append(item)
        elif hasattr(item, 'asset_entry') and item.asset_entry.entered_asset_number:
            # Check if already submitted
            item.existing_asset = item.asset_entry.entered_asset_number
            verified_items.append(item)
        else:
            item.existing_asset = ''
            pending_items.append(item)
    
    # ========== POST REQUEST ==========
    if request.method == 'POST':
        # Check if this is an AJAX request for auto-save
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            try:
                data = json.loads(request.body)
                item_id = str(data.get('item_id'))
                asset_number = data.get('asset_number', '').strip()
                is_undo = data.get('undo', False)
                
                # Update draft
                if not draft_data:
                    draft_data = {}
                
                if is_undo:
                    # Remove from draft
                    if item_id in draft_data:
                        del draft_data[item_id]
                else:
                    # Save to draft
                    draft_data[item_id] = asset_number
                
                draft.data = draft_data
                draft.last_saved = timezone.now()
                draft.save()
                
                # Log draft save
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="draft_save",
                    module="Asset Entry",
                    description=f"Employee {request.user.username} saved draft for assignment {assignment.assignment_id}",
                    target_user=request.user,
                    target_model="HardwareAssignment",
                    target_id=assignment.id,
                    new_value={
                        'item_id': item_id,
                        'asset_number': asset_number,
                        'is_undo': is_undo
                    }
                )
                
                return JsonResponse({
                    'success': True,
                    'message': 'Draft saved successfully',
                    'saved_at': draft.last_saved.strftime('%H:%M:%S')
                })
                
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'error': str(e)
                }, status=400)
        
        # Regular form submission
        client_ip = get_client_ip(request)
        success_count = 0
        error_count = 0
        entered_assets = []
        submitted_items = {}
        
        # Process all items from the form
        for item in items:
            asset_number = request.POST.get(f'asset_{item.id}', '').strip()
            
            if asset_number:
                try:
                    # Check if this item exists in draft and match
                    if str(item.id) in draft_data and draft_data[str(item.id)] == asset_number:
                        submitted_items[str(item.id)] = True
                    
                    # Save to database
                    if hasattr(item, 'asset_entry'):
                        asset_entry = item.asset_entry
                        old_value = asset_entry.entered_asset_number
                        asset_entry.entered_asset_number = asset_number
                        asset_entry.entered_by = request.user
                        asset_entry.save()
                        
                        create_audit_log(
                            request=request,
                            user=request.user,
                            action="asset_entry_update",
                            module="Asset Entry",
                            description=f"Employee {request.user.username} updated asset number for {item.hardware.hardware_type.name} from '{old_value}' to '{asset_number}'",
                            target_user=request.user,
                            target_model="HardwareAssetEntry",
                            target_id=asset_entry.id,
                            old_value=old_value,
                            new_value=asset_number
                        )
                    else:
                        asset_entry = HardwareAssetEntry.objects.create(
                            hardware_item=item,
                            entered_asset_number=asset_number,
                            entered_by=request.user
                        )
                        
                        create_audit_log(
                            request=request,
                            user=request.user,
                            action="asset_entry",
                            module="Asset Entry",
                            description=f"Employee {request.user.username} entered asset number '{asset_number}' for {item.hardware.hardware_type.name}",
                            target_user=request.user,
                            target_model="HardwareAssetEntry",
                            target_id=asset_entry.id,
                            new_value=asset_number
                        )
                    
                    success_count += 1
                    entered_assets.append({
                        'hardware_type': item.hardware.hardware_type.name,
                        'asset_number': asset_number
                    })
                    
                except Exception as e:
                    create_audit_log(
                        request=request,
                        user=request.user,
                        action="system_error",
                        module="Asset Entry",
                        description=f"Asset entry failed for {item.hardware.hardware_type.name}: {str(e)}",
                        target_user=request.user,
                        target_model="HardwareAssignment",
                        target_id=assignment.id,
                        new_value={'error': str(e)}
                    )
                    error_count += 1
                    messages.error(request, f'Error saving asset for {item.hardware.hardware_type.name}: {str(e)}')
        
        # ========== CLEAR DRAFT AFTER SUBMISSION ==========
        if success_count > 0:
            # Clear the draft
            draft.data = {}
            draft.save()
            
            create_audit_log(
                request=request,
                user=request.user,
                action="draft_cleared",
                module="Asset Entry",
                description=f"Draft cleared for assignment {assignment.assignment_id} after submission",
                target_user=request.user,
                target_model="HardwareAssignment",
                target_id=assignment.id
            )
        
        # ========== BULK AUDIT LOG ==========
        if success_count > 0:
            create_audit_log(
                request=request,
                user=request.user,
                action="asset_entry",
                module="Asset Entry",
                description=f"Employee {request.user.username} entered {success_count} asset number(s) for assignment {assignment.assignment_id}",
                target_user=request.user,
                target_model="HardwareAssignment",
                target_id=assignment.id,
                new_value={
                    'assignment_id': str(assignment.assignment_id),
                    'success_count': success_count,
                    'error_count': error_count,
                    'entered_assets': entered_assets,
                    'ip': client_ip
                }
            )
        
        # ========== MESSAGES ==========
        if success_count > 0:
            messages.success(request, f'Successfully submitted {success_count} asset number(s)!')
        if error_count > 0:
            messages.warning(request, f'{error_count} item(s) were not submitted (empty asset number or error)')
        
        return redirect('my_assignment_details', assignment_id=assignment_id)
    
    # ========== GET REQUEST ==========
    context = {
        'assignment': assignment,
        'items': items,
        'verified_items': verified_items,
        'pending_items': pending_items,
        'total_items': items.count(),
        'editing': bool(verified_items),
        'draft_data': draft_data,
        'draft_last_saved': draft.last_saved if draft.last_saved else None,
        'has_draft': bool(draft_data)
    }
    return render(request, 'employee/enter_serial_numbers.html', context)


# ============================================================
# EDIT SERIAL NUMBERS (Legacy - kept for compatibility)
# ============================================================

@login_required
def edit_serial_numbers(request, assignment_id):
    """
    Edit serial numbers (legacy method - kept for compatibility)
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Entry",
            description=f"Unauthorized serial edit attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('manager_dashboard')
    
    # ========== GET ASSIGNMENT ==========
    assignment = get_object_or_404(
        HardwareAssignment,
        assignment_id=assignment_id,
        employee=request.user
    )
    
    if assignment.actual_return_date:
        messages.error(request, 'This assignment has already been returned!')
        return redirect('employee_dashboard')
    
    items = HardwareAssignmentItem.objects.filter(
        assignment=assignment
    ).select_related('hardware__hardware_type')
    
    # ========== CHECK FOR VERIFIED SERIALS ==========
    has_verified_serials = False
    for item in items:
        if hasattr(item, 'serial_entry') and item.serial_entry.verified:
            has_verified_serials = True
            break
    
    if has_verified_serials:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Asset Entry",
            description=f"Serial edit blocked - Assignment {assignment.assignment_id} has verified serials",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id
        )
        messages.error(request, 'Cannot edit serial numbers that have been verified by manager!')
        return redirect('my_assignment_details', assignment_id=assignment_id)
    
    # ========== POST REQUEST ==========
    if request.method == 'POST':
        success_count = 0
        error_count = 0
        
        for item in items:
            serial_number = request.POST.get(f'serial_{item.id}', '').strip()
            if serial_number:
                try:
                    if hasattr(item, 'serial_entry'):
                        serial_entry = item.serial_entry
                        old_value = serial_entry.serial_number
                        serial_entry.serial_number = serial_number
                        serial_entry.save()
                        
                        create_audit_log(
                            request=request,
                            user=request.user,
                            action="asset_entry_update",
                            module="Asset Entry",
                            description=f"Employee {request.user.username} updated serial number from '{old_value}' to '{serial_number}'",
                            target_user=request.user,
                            target_model="HardwareSerialEntry",
                            target_id=serial_entry.id,
                            old_value=old_value,
                            new_value=serial_number
                        )
                    else:
                        serial_entry = HardwareSerialEntry.objects.create(
                            assignment_item=item,
                            serial_number=serial_number,
                            entered_by=request.user
                        )
                        
                        create_audit_log(
                            request=request,
                            user=request.user,
                            action="asset_entry",
                            module="Asset Entry",
                            description=f"Employee {request.user.username} entered serial number '{serial_number}'",
                            target_user=request.user,
                            target_model="HardwareSerialEntry",
                            target_id=serial_entry.id,
                            new_value=serial_number
                        )
                    
                    success_count += 1
                except Exception as e:
                    messages.error(request, f'Error saving serial: {str(e)}')
                    error_count += 1
            else:
                error_count += 1
        
        if success_count > 0:
            messages.success(request, f'Successfully updated {success_count} serial number(s)!')
        if error_count > 0:
            messages.warning(request, f'{error_count} item(s) were not updated (empty serial number or error)')
        
        return redirect('my_assignment_details', assignment_id=assignment_id)
    
    # ========== GET REQUEST ==========
    for item in items:
        if hasattr(item, 'serial_entry'):
            item.existing_serial = item.serial_entry.serial_number
        else:
            item.existing_serial = ''
    
    context = {
        'assignment': assignment,
        'items': items,
        'editing': True,
    }
    return render(request, 'employee/enter_serial_numbers.html', context)


# ============================================================
# API VIEWS
# ============================================================

@csrf_exempt
@login_required
def api_get_hardware_by_type(request):
    """
    API endpoint to get hardware items by type
    With audit logging
    """
    
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    hardware_type_id = request.GET.get('type_id')
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="API",
            description=f"Unauthorized API access by {request.user.username}",
            target_user=request.user
        )
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if not hardware_type_id:
        return JsonResponse({'error': 'type_id parameter required'}, status=400)
    
    try:
        hardware_items = Hardware.objects.filter(
            hardware_type_id=hardware_type_id,
            status='available',
            created_by=request.user
        ).values('id', 'serial_number', 'model_name', 'brand', 'asset_number')
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="API",
            description=f"Manager {request.user.username} fetched hardware by type {hardware_type_id} ({hardware_items.count()} items)",
            target_user=request.user,
            new_value={
                'hardware_type_id': hardware_type_id,
                'count': hardware_items.count()
            }
        )
        
        return JsonResponse(list(hardware_items), safe=False)
        
    except Exception as e:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_error",
            module="API",
            description=f"API error: {str(e)}",
            target_user=request.user,
            new_value={'error': str(e)}
        )
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@login_required
def api_get_assignment_details(request, assignment_id):
    """
    API endpoint to get assignment details
    With audit logging
    """
    
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    # ========== GET ASSIGNMENT ==========
    assignment = get_object_or_404(HardwareAssignment, id=assignment_id)
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type == 'employee' and assignment.employee != request.user:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="API",
            description=f"Unauthorized API access to assignment {assignment_id} by {request.user.username}",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id
        )
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if request.user.user_type == 'manager' and assignment.assigned_by != request.user:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="API",
            description=f"Unauthorized API access to assignment {assignment_id} by manager {request.user.username}",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id
        )
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    try:
        items = HardwareAssignmentItem.objects.filter(
            assignment=assignment
        ).select_related('hardware__hardware_type')
        
        data = {
            'assignment_id': str(assignment.assignment_id),
            'project': {
                'id': assignment.project.id,
                'name': assignment.project.project_name,
                'location': assignment.project.location,
            },
            'employee': assignment.employee.username,
            'assigned_by': assignment.assigned_by.username,
            'assigned_date': assignment.assigned_date.strftime('%Y-%m-%d') if assignment.assigned_date else None,
            'expected_return_date': assignment.expected_return_date.strftime('%Y-%m-%d') if assignment.expected_return_date else None,
            'actual_return_date': assignment.actual_return_date.strftime('%Y-%m-%d') if assignment.actual_return_date else None,
            'notes': assignment.notes,
            'hardware_items': [
                {
                    'id': item.id,
                    'hardware_id': item.hardware.id,
                    'type': item.hardware.hardware_type.name,
                    'model': item.hardware.model_name,
                    'serial_number': item.hardware.serial_number,
                    'brand': item.hardware.brand,
                    'asset_number': item.hardware.asset_number,
                    'has_asset_entry': hasattr(item, 'asset_entry'),
                    'entered_asset': item.asset_entry.entered_asset_number if hasattr(item, 'asset_entry') else None,
                    'verified': item.asset_entry.verified if hasattr(item, 'asset_entry') else False,
                }
                for item in items
            ]
        }
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="API",
            description=f"User {request.user.username} fetched assignment {assignment.assignment_id} details via API",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id,
            new_value={
                'assignment_id': str(assignment.assignment_id),
                'items_count': items.count()
            }
        )
        
        return JsonResponse(data)
        
    except Exception as e:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_error",
            module="API",
            description=f"API error fetching assignment {assignment_id}: {str(e)}",
            target_user=request.user,
            target_model="HardwareAssignment",
            target_id=assignment.id,
            new_value={'error': str(e)}
        )
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@login_required
def api_check_serial_exists(request):
    """
    API endpoint to check if a serial number exists
    With audit logging
    """
    
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    serial_number = request.GET.get('serial_number', '').strip()
    
    if not serial_number:
        return JsonResponse({'exists': False, 'error': 'serial_number required'}, status=400)
    
    try:
        exists = HardwareSerialEntry.objects.filter(
            serial_number=serial_number
        ).exists()
        
        # Only log if serial exists (to avoid spam)
        if exists:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_info",
                module="API",
                description=f"User {request.user.username} checked serial number '{serial_number}' - Found",
                target_user=request.user,
                new_value={'serial': serial_number, 'exists': True}
            )
        
        return JsonResponse({'exists': exists})
        
    except Exception as e:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_error",
            module="API",
            description=f"API error checking serial '{serial_number}': {str(e)}",
            target_user=request.user,
            new_value={'serial': serial_number, 'error': str(e)}
        )
        return JsonResponse({'exists': False, 'error': str(e)}, status=500)


# ============================================================
# UTILITY VIEWS
# ============================================================

@login_required
def profile(request):
    """
    User profile view
    With audit logging
    """
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_profile_view', 0) < timezone.now().timestamp() - 600:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Profile",
            description=f"User {request.user.username} viewed profile",
            target_user=request.user
        )
        request.session['last_profile_view'] = timezone.now().timestamp()
    
    # ✅ NEW: Determine if the user can edit their profile
    can_edit = request.user.user_type in ['super_admin', 'manager']
    
    context = {
        'user': request.user,
        'can_edit': can_edit,  # Pass this to the template
    }
    return render(request, 'profile.html', context)

@login_required
def update_profile(request):
    """
    Update user profile
    With audit logging
    ✅ FIXED: Employees cannot update their profile.
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type == 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Profile",
            description=f"Employee {request.user.username} attempted to update profile (Read-only mode)",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to update your profile. Please contact your Manager or Super Admin.')
        return redirect('profile')
    # ==========================================
    
    if request.method == 'POST':
        user = request.user
        
        # Get old values for audit
        old_values = {
            'email': user.email,
            'phone': user.phone,
            'first_name': user.first_name,
            'last_name': user.last_name
        }
        
        # Update fields
        new_email = request.POST.get('email', '').strip()
        new_phone = request.POST.get('phone', '').strip()
        new_first_name = request.POST.get('first_name', '').strip()
        new_last_name = request.POST.get('last_name', '').strip()
        
        # Validate email
        if new_email and new_email != user.email:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            if User.objects.filter(email=new_email).exclude(id=user.id).exists():
                messages.error(request, 'Email already exists!')
                return redirect('profile')
            user.email = new_email
        
        # Update other fields
        user.phone = new_phone or ''
        user.first_name = new_first_name or ''
        user.last_name = new_last_name or ''
        user.save()
        
        # ========== AUDIT LOG ==========
        changes = []
        if old_values['email'] != user.email:
            changes.append(f"email: '{old_values['email']}' → '{user.email}'")
        if old_values['phone'] != user.phone:
            changes.append(f"phone: '{old_values['phone']}' → '{user.phone}'")
        if old_values['first_name'] != user.first_name:
            changes.append(f"first_name: '{old_values['first_name']}' → '{user.first_name}'")
        if old_values['last_name'] != user.last_name:
            changes.append(f"last_name: '{old_values['last_name']}' → '{user.last_name}'")
        
        if changes:
            create_audit_log(
                request=request,
                user=request.user,
                action="user_update",
                module="Profile",
                description=f"User {request.user.username} updated profile: {', '.join(changes)}",
                target_user=request.user,
                target_model="User",
                target_id=user.id,
                old_value=old_values,
                new_value={
                    'email': user.email,
                    'phone': user.phone,
                    'first_name': user.first_name,
                    'last_name': user.last_name
                }
            )
        
        messages.success(request, 'Profile updated successfully!')
        return redirect('profile')
    
    # ========== GET REQUEST ==========
    context = {'user': request.user}
    return render(request, 'update_profile.html', context)

# views.py - Updated Password Reset Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.template import TemplateDoesNotExist
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import PasswordResetOTP
import uuid
import re

User = get_user_model()


# ============================================================
# FORGOT PASSWORD
# ============================================================

def forgot_password(request):
    """
    Request password reset OTP
    With comprehensive audit logging
    """
    
    # Get client IP
    client_ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        
        # ========== VALIDATE INPUT ==========
        if not username:
            create_audit_log(
                request=request,
                user=None,
                role='system',
                action="system_warning",
                module="Password Reset",
                description=f"Password reset attempt with empty username from IP {client_ip}",
                target_model="User",
                target_id=username or 'empty'
            )
            messages.error(request, 'Please enter your username/Employee ID.')
            return render(request, 'auth/forgot_password.html')
        
        try:
            user = User.objects.get(username=username)
            
            # ========== CHECK IF USER IS ACTIVE ==========
            if not user.is_active:
                create_audit_log(
                    request=request,
                    user=None,
                    role='system',
                    action="system_warning",
                    module="Password Reset",
                    description=f"Password reset attempt for inactive user '{username}' from IP {client_ip}",
                    target_user=user,
                    target_model="User",
                    target_id=user.id,
                    old_value="inactive_account"
                )
                messages.error(request, 'Your account is inactive. Please contact administrator.')
                return render(request, 'auth/forgot_password.html')
            
            # ========== CHECK FOR EXISTING OTP ==========
            # Invalidate any existing unused OTPs for this user
            PasswordResetOTP.objects.filter(
                user=user,
                is_used=False,
                expires_at__gt=timezone.now()
            ).update(is_used=True)
            
            # ========== GENERATE NEW OTP ==========
            otp_obj = PasswordResetOTP.generate_otp(user)
            
            # ========== SEND EMAIL ==========
            email_sent = False
            try:
                subject = 'Password Reset OTP - Eduquity Hardware Management'
                html_message = render_to_string('auth/password_reset_email.html', {
                    'user': user,
                    'otp': otp_obj.otp,
                    'expiry_minutes': 5,
                    'token': otp_obj.token,
                })
                
                send_mail(
                    subject=subject,
                    message=f'Your OTP for password reset is: {otp_obj.otp}. This OTP is valid for 5 minutes.',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    html_message=html_message,
                    fail_silently=False,
                )
                email_sent = True
                
            except Exception as e:
                # Log email failure but continue
                create_audit_log(
                    request=request,
                    user=None,
                    role='system',
                    action="system_warning",
                    module="Password Reset",
                    description=f"OTP email failed for {user.email}: {str(e)}",
                    target_user=user,
                    target_model="User",
                    target_id=user.id,
                    new_value={'error': str(e)}
                )
            
            # ========== AUDIT LOG ==========
            create_audit_log(
                request=request,
                user=None,
                role='system',
                action="password_reset_request",
                module="Password Reset",
                description=f"Password reset OTP requested for user '{username}' from IP {client_ip}" + (f" - Email sent to {user.email}" if email_sent else " - Email failed"),
                target_user=user,
                target_model="User",
                target_id=user.id,
                new_value={
                    'username': username,
                    'email': user.email,
                    'user_type': user.user_type,
                    'ip': client_ip,
                    'email_sent': email_sent,
                    'user_agent': user_agent[:200]
                }
            )
            
            if email_sent:
                messages.success(
                    request,
                    f'OTP has been sent to your registered email address ({user.email}). Please check your inbox.'
                )
            else:
                messages.warning(
                    request,
                    'OTP was generated but could not be sent via email. Please contact administrator.'
                )
            
            return redirect('verify_otp', token=otp_obj.token)
            
        except User.DoesNotExist:
            # ========== LOG USER NOT FOUND ==========
            create_audit_log(
                request=request,
                user=None,
                role='system',
                action="system_warning",
                module="Password Reset",
                description=f"Password reset attempt for non-existent username '{username}' from IP {client_ip}",
                target_model="User",
                target_id=username,
                old_value="user_not_found"
            )
            messages.error(request, 'No account found with this Employee ID.')
            
        except Exception as e:
            # ========== LOG ERROR ==========
            create_audit_log(
                request=request,
                user=None,
                role='system',
                action="system_error",
                module="Password Reset",
                description=f"Password reset error for '{username}': {str(e)}",
                target_model="User",
                target_id=username,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Failed to send OTP. Error: {str(e)}')
    
    return render(request, 'auth/forgot_password.html')


# ============================================================
# VERIFY OTP
# ============================================================

def verify_otp(request, token):
    """
    Verify OTP for password reset
    With comprehensive audit logging
    """
    
    # Get client IP
    client_ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
    
    try:
        otp_obj = PasswordResetOTP.objects.get(token=token, is_used=False)
        user = otp_obj.user
        
        # ========== CHECK IF OTP IS EXPIRED ==========
        if otp_obj.is_expired():
            create_audit_log(
                request=request,
                user=None,
                role='system',
                action="system_warning",
                module="Password Reset",
                description=f"Expired OTP verification attempt for user '{user.username}' from IP {client_ip}",
                target_user=user,
                target_model="PasswordResetOTP",
                target_id=otp_obj.id,
                old_value="expired"
            )
            messages.error(request, 'OTP has expired. Please request a new one.')
            return redirect('forgot_password')
        
        if request.method == 'POST':
            entered_otp = request.POST.get('otp', '').strip()
            
            # ========== VALIDATE OTP ==========
            if not entered_otp:
                messages.error(request, 'Please enter the OTP.')
                return render(request, 'auth/verify_otp.html', {
                    'token': token,
                    'email': otp_obj.user.email[:3] + '*****' + otp_obj.user.email[otp_obj.user.email.find('@'):]
                })
            
            if entered_otp == otp_obj.otp:
                # ========== OTP VERIFIED ==========
                otp_obj.is_used = True
                otp_obj.save()
                
                create_audit_log(
                    request=request,
                    user=None,
                    role='system',
                    action="password_reset_request",
                    module="Password Reset",
                    description=f"OTP verified successfully for user '{user.username}' from IP {client_ip}",
                    target_user=user,
                    target_model="PasswordResetOTP",
                    target_id=otp_obj.id,
                    old_value="pending",
                    new_value="verified"
                )
                
                messages.success(request, 'OTP verified successfully. Please set your new password.')
                return redirect('reset_password', token=token)
            else:
                # ========== INVALID OTP ==========
                create_audit_log(
                    request=request,
                    user=None,
                    role='system',
                    action="system_warning",
                    module="Password Reset",
                    description=f"Invalid OTP attempt for user '{user.username}' from IP {client_ip}",
                    target_user=user,
                    target_model="PasswordResetOTP",
                    target_id=otp_obj.id,
                    old_value="invalid_otp_attempt"
                )
                messages.error(request, 'Invalid OTP. Please try again.')
        
        # ========== GET REQUEST ==========
        email_display = otp_obj.user.email[:3] + '*****' + otp_obj.user.email[otp_obj.user.email.find('@'):]
        
        return render(request, 'auth/verify_otp.html', {
            'token': token,
            'email': email_display,
            'expiry_minutes': 5
        })
    
    except PasswordResetOTP.DoesNotExist:
        # ========== INVALID TOKEN ==========
        create_audit_log(
            request=request,
            user=None,
            role='system',
            action="system_warning",
            module="Password Reset",
            description=f"Invalid OTP token attempt from IP {client_ip}",
            target_model="PasswordResetOTP",
            target_id=token
        )
        messages.error(request, 'Invalid or expired OTP link.')
        return redirect('forgot_password')


# ============================================================
# RESET PASSWORD
# ============================================================

def reset_password(request, token):
    """
    Reset password using verified OTP
    With comprehensive audit logging
    """
    
    # Get client IP
    client_ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
    
    try:
        otp_obj = PasswordResetOTP.objects.get(token=token)
        user = otp_obj.user
        
        # ========== CHECK OTP STATUS ==========
        if not otp_obj.is_used:
            create_audit_log(
                request=request,
                user=None,
                role='system',
                action="system_warning",
                module="Password Reset",
                description=f"Reset password attempt without verified OTP for user '{user.username}' from IP {client_ip}",
                target_user=user,
                target_model="PasswordResetOTP",
                target_id=otp_obj.id,
                old_value="otp_not_verified"
            )
            messages.error(request, 'Please verify OTP first.')
            return redirect('verify_otp', token=token)
        
        # ========== CHECK IF OTP IS STILL VALID ==========
        if otp_obj.is_expired():
            create_audit_log(
                request=request,
                user=None,
                role='system',
                action="system_warning",
                module="Password Reset",
                description=f"Expired OTP used for password reset for user '{user.username}' from IP {client_ip}",
                target_user=user,
                target_model="PasswordResetOTP",
                target_id=otp_obj.id,
                old_value="expired"
            )
            messages.error(request, 'OTP has expired. Please request a new one.')
            return redirect('forgot_password')
        
        if request.method == 'POST':
            password = request.POST.get('password', '')
            confirm_password = request.POST.get('confirm_password', '')
            
            # ========== VALIDATE PASSWORD ==========
            if not password or not confirm_password:
                messages.error(request, 'Please fill in all fields.')
                return render(request, 'auth/reset_password.html', {'token': token})
            
            if password != confirm_password:
                create_audit_log(
                    request=request,
                    user=None,
                    role='system',
                    action="system_warning",
                    module="Password Reset",
                    description=f"Password reset failed for user '{user.username}' - Passwords do not match",
                    target_user=user,
                    target_model="PasswordResetOTP",
                    target_id=otp_obj.id,
                    old_value="password_mismatch"
                )
                messages.error(request, 'Passwords do not match!')
                return render(request, 'auth/reset_password.html', {'token': token})
            
            if len(password) < 8:
                create_audit_log(
                    request=request,
                    user=None,
                    role='system',
                    action="system_warning",
                    module="Password Reset",
                    description=f"Password reset failed for user '{user.username}' - Password too short",
                    target_user=user,
                    target_model="PasswordResetOTP",
                    target_id=otp_obj.id,
                    old_value="password_too_short"
                )
                messages.error(request, 'Password must be at least 8 characters long.')
                return render(request, 'auth/reset_password.html', {'token': token})
            
            # ========== VALIDATE PASSWORD STRENGTH ==========
            try:
                validate_password(password, user)
            except ValidationError as e:
                for error in e.messages:
                    messages.error(request, error)
                create_audit_log(
                    request=request,
                    user=None,
                    role='system',
                    action="system_warning",
                    module="Password Reset",
                    description=f"Password reset validation failed for user '{user.username}': {', '.join(e.messages)}",
                    target_user=user,
                    target_model="PasswordResetOTP",
                    target_id=otp_obj.id,
                    old_value="validation_failed"
                )
                return render(request, 'auth/reset_password.html', {'token': token})
            
            # ========== UPDATE PASSWORD ==========
            try:
                was_first_login = user.is_first_login
                user.set_password(password)
                
                # If employee and was first login, mark as completed
                if user.user_type == 'employee' and user.is_first_login:
                    user.is_first_login = False
                
                user.save()
                
                # ========== AUDIT LOG - SUCCESS ==========
                create_audit_log(
                    request=request,
                    user=None,
                    role='system',
                    action="password_reset",
                    module="Password Reset",
                    description=f"Password reset successful for user '{user.username}' ({user.user_type}) from IP {client_ip}",
                    target_user=user,
                    target_model="User",
                    target_id=user.id,
                    old_value={
                        'username': user.username,
                        'user_type': user.user_type,
                        'was_first_login': was_first_login,
                        'reset_via': 'OTP'
                    },
                    new_value={
                        'reset_time': timezone.now().isoformat(),
                        'ip': client_ip,
                        'user_agent': user_agent[:200]
                    }
                )
                
                # ========== SEND SUCCESS EMAIL ==========
                try:
                    subject = 'Password Reset Successful - Eduquity Hardware Management'
                    
                    try:
                        html_message = render_to_string('auth/password_reset_success_email.html', {
                            'user': user,
                            'now': timezone.now(),
                        })
                    except TemplateDoesNotExist:
                        html_message = f'''
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <style>
                                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                                .header {{ background: #28a745; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
                                .content {{ background: #f9f9f9; padding: 30px; border: 1px solid #ddd; border-top: none; border-radius: 0 0 5px 5px; }}
                                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                <div class="header">
                                    <h2>Password Reset Successful</h2>
                                </div>
                                <div class="content">
                                    <p>Hello <strong>{user.get_full_name() or user.username}</strong>,</p>
                                    <p>Your password has been successfully reset for the <strong>Eduquity Hardware Management System</strong>.</p>
                                    <p>If you did not request this password reset, please contact your system administrator immediately.</p>
                                    <p><strong>Security Tip:</strong> For your security, please do not share your password with anyone.</p>
                                    <p style="margin-top: 20px;">
                                        <a href="http://eduquityinventory.co.in/login/" style="display: inline-block; padding: 10px 20px; background: #E04D00; color: white; text-decoration: none; border-radius: 5px;">Login Now</a>
                                    </p>
                                    <div class="footer">
                                        <p><strong>Eduquity Hardware Management Team</strong><br>
                                        Established in 2000 - Thought-leader in the Indian assessment industry</p>
                                        <p><em>This is an automated email. Please do not reply.</em></p>
                                    </div>
                                </div>
                            </div>
                        </body>
                        </html>
                        '''
                    
                    send_mail(
                        subject=subject,
                        message=f'Your password has been reset successfully on {timezone.now().strftime("%B %d, %Y at %I:%M %p")}. If you did not request this, please contact your system administrator.',
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],
                        html_message=html_message,
                        fail_silently=False,
                    )
                    
                    create_audit_log(
                        request=request,
                        user=None,
                        role='system',
                        action="system_info",
                        module="Password Reset",
                        description=f"Password reset success email sent to {user.email}",
                        target_user=user,
                        target_model="User",
                        target_id=user.id
                    )
                    
                except Exception as e:
                    create_audit_log(
                        request=request,
                        user=None,
                        role='system',
                        action="system_warning",
                        module="Password Reset",
                        description=f"Password reset success email failed for {user.email}: {str(e)}",
                        target_user=user,
                        target_model="User",
                        target_id=user.id,
                        new_value={'error': str(e)}
                    )
                    print(f"Failed to send password reset email: {str(e)}")
                
                messages.success(request, 'Password reset successfully! You can now login with your new password.')
                return redirect('login')
                
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=None,
                    role='system',
                    action="system_error",
                    module="Password Reset",
                    description=f"Password reset failed for user '{user.username}': {str(e)}",
                    target_user=user,
                    target_model="PasswordResetOTP",
                    target_id=otp_obj.id,
                    new_value={'error': str(e)}
                )
                messages.error(request, f'Error resetting password: {str(e)}')
                return render(request, 'auth/reset_password.html', {'token': token})
        
        # ========== GET REQUEST ==========
        return render(request, 'auth/reset_password.html', {'token': token})
    
    except PasswordResetOTP.DoesNotExist:
        # ========== INVALID TOKEN ==========
        create_audit_log(
            request=request,
            user=None,
            role='system',
            action="system_warning",
            module="Password Reset",
            description=f"Invalid reset token attempt from IP {client_ip}",
            target_model="PasswordResetOTP",
            target_id=token
        )
        messages.error(request, 'Invalid reset link.')
        return redirect('forgot_password')


# ============================================================
# HELPER: Validate Password Strength
# ============================================================

def validate_password_strength(password, user=None):
    """
    Validate password strength with custom rules
    Returns tuple (is_valid, error_message)
    """
    import re
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    
    # Check for at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    
    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    
    # Check for at least one digit
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    
    # Check for at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    
    return True, ""

# views.py - Updated Employee Hardware Views with Audit Logging

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.http import HttpResponse
from datetime import datetime
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import (
    CustomUser, HardwareAssignment, HardwareAssignmentItem, 
    HardwareAssetEntry, HardwareSerialEntry, HardwareType
)


# ============================================================
# MY HARDWARE
# ============================================================

@login_required
def my_hardware(request):
    """
    Employee view all their hardware assignments
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Hardware",
            description=f"Unauthorized hardware view attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('manager_dashboard')
    
    # ========== GET ASSIGNMENTS ==========
    active_assignments = HardwareAssignment.objects.filter(
        employee=request.user,
        actual_return_date__isnull=True
    ).order_by('-assigned_date')
    
    completed_assignments = HardwareAssignment.objects.filter(
        employee=request.user,
        actual_return_date__isnull=False
    ).order_by('-assigned_date')[:5]
    
    # ========== PROCESS ACTIVE ASSIGNMENTS ==========
    total_items = 0
    verified_count = 0
    pending_count = 0
    matched_count = 0
    mismatch_count = 0
    active_count = active_assignments.count()
    
    for assignment in active_assignments:
        items = HardwareAssignmentItem.objects.filter(assignment=assignment)
        assignment.hardware_count = items.count()
        total_items += assignment.hardware_count
        
        assignment.verified_count = 0
        assignment.matched_count = 0
        assignment.mismatch_count = 0
        assignment.pending_count = 0
        assignment.items_list = []
        
        for item in items:
            expected_asset = item.hardware.asset_number if item.hardware.asset_number else 'N/A'
            
            hardware_data = {
                'id': item.id,
                'hardware_type': item.hardware.hardware_type.name,
                'model': item.hardware.model_name,
                'brand': item.hardware.brand,
                'expected_asset': expected_asset,
                'serial_number': item.hardware.serial_number,
                'status': item.hardware.status,
            }
            
            try:
                asset_entry = item.asset_entry
                hardware_data['entered_asset'] = asset_entry.entered_asset_number
                hardware_data['verified'] = asset_entry.verified
                hardware_data['verified_by'] = asset_entry.verified_by
                hardware_data['verified_at'] = asset_entry.verified_at
                hardware_data['entered_at'] = asset_entry.entered_at
                
                if asset_entry.verified:
                    assignment.verified_count += 1
                    verified_count += 1
                else:
                    if asset_entry.entered_asset_number == expected_asset:
                        assignment.matched_count += 1
                        matched_count += 1
                    else:
                        assignment.mismatch_count += 1
                        mismatch_count += 1
                        
            except HardwareAssetEntry.DoesNotExist:
                hardware_data['entered_asset'] = None
                hardware_data['verified'] = False
                assignment.pending_count += 1
                pending_count += 1
            
            assignment.items_list.append(hardware_data)
    
    # ========== PROCESS COMPLETED ASSIGNMENTS ==========
    for assignment in completed_assignments:
        assignment.hardware_count = HardwareAssignmentItem.objects.filter(
            assignment=assignment
        ).count()
    
    # ========== CALCULATE STATISTICS ==========
    completion_rate = 0
    if total_items > 0:
        completion_rate = round((verified_count / total_items * 100), 1)
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_my_hardware_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Employee Hardware",
            description=f"Employee {request.user.username} viewed hardware inventory ({active_count} active assignments, {total_items} items)",
            target_user=request.user,
            new_value={
                'active_assignments': active_count,
                'completed_assignments': completed_assignments.count(),
                'total_items': total_items,
                'verified_count': verified_count,
                'pending_count': pending_count,
                'matched_count': matched_count,
                'mismatch_count': mismatch_count,
                'completion_rate': completion_rate
            }
        )
        request.session['last_my_hardware_view'] = timezone.now().timestamp()
    
    context = {
        'assignments': active_assignments,
        'completed_assignments': completed_assignments,
        'total_items': total_items,
        'verified_count': verified_count,
        'pending_count': pending_count,
        'matched_count': matched_count,
        'mismatch_count': mismatch_count,
        'active_assignments': active_count,
        'completion_rate': completion_rate,
    }
    return render(request, 'employee/my_hardware.html', context)


# ============================================================
# EXPORT MY HARDWARE EXCEL
# ============================================================

@login_required
def export_my_hardware_excel(request):
    """
    Export employee's hardware data to Excel
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Unauthorized export attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('manager_dashboard')
    
    # ========== GET ASSIGNMENTS ==========
    active_assignments = HardwareAssignment.objects.filter(
        employee=request.user,
        actual_return_date__isnull=True
    ).order_by('-assigned_date')
    
    if not active_assignments.exists():
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Export attempt by {request.user.username} - No active assignments found",
            target_user=request.user
        )
        messages.warning(request, 'No active hardware assignments found to export.')
        return redirect('my_hardware')
    
    # ========== BUILD FILENAME ==========
    exam_city = "NoCity"
    if active_assignments.exists():
        exam_city = active_assignments.first().exam_city.replace(" ", "_") if active_assignments.first().exam_city else "NoCity"
    
    employee_name = request.user.get_full_name() or request.user.username
    employee_name = employee_name.replace(" ", "_")
    current_date = datetime.now().strftime("%Y%m%d")
    
    filename = f"{exam_city}_{employee_name}_{current_date}.xlsx"
    
    try:
        # ========== CREATE WORKBOOK ==========
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "My Hardware Report"
        
        # ========== DEFINE STYLES ==========
        header_font = Font(bold=True, color="FFFFFF", size=12)
        header_fill = PatternFill(start_color="2C3E50", end_color="2C3E50", fill_type="solid")
        header_alignment = Alignment(horizontal="center", vertical="center")
        
        success_fill = PatternFill(start_color="DFF0D8", end_color="DFF0D8", fill_type="solid")
        info_fill = PatternFill(start_color="D9EDF7", end_color="D9EDF7", fill_type="solid")
        warning_fill = PatternFill(start_color="FCF8E3", end_color="FCF8E3", fill_type="solid")
        danger_fill = PatternFill(start_color="F2DEDE", end_color="F2DEDE", fill_type="solid")
        
        border = Border(
            left=Side(style='thin'), right=Side(style='thin'),
            top=Side(style='thin'), bottom=Side(style='thin')
        )
        
        # ========== TITLE ==========
        ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=14)
        title_cell = ws.cell(row=1, column=1, value="EDUQUITY HARDWARE MANAGEMENT SYSTEM")
        title_cell.font = Font(bold=True, size=16)
        title_cell.alignment = header_alignment
        
        ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=14)
        subtitle_cell = ws.cell(row=2, column=1, value=f"MY HARDWARE REPORT - {request.user.get_full_name() or request.user.username}")
        subtitle_cell.font = Font(size=12, italic=True)
        subtitle_cell.alignment = header_alignment
        
        ws.merge_cells(start_row=3, start_column=1, end_row=3, end_column=14)
        date_cell = ws.cell(row=3, column=1, value=f"Generated on: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        date_cell.font = Font(size=10, italic=True)
        date_cell.alignment = header_alignment
        
        # ========== HEADERS ==========
        headers = [
            'Assignment ID', 'Project', 'Exam City', 'Assigned Date', 'Expected Return',
            'Hardware Type', 'Model', 'Brand', 'Assigned Serial', 'Entered Serial',
            'Entry Status', 'Verification Status', 'Verified By', 'Verified On'
        ]
        
        for col_num, header in enumerate(headers, 1):
            cell = ws.cell(row=5, column=col_num, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_alignment
            cell.border = border
        
        # ========== DATA ROWS ==========
        row_num = 6
        total_items = 0
        verified_count = 0
        matched_count = 0
        mismatch_count = 0
        pending_count = 0
        
        for assignment in active_assignments:
            items = HardwareAssignmentItem.objects.filter(assignment=assignment)
            
            for item in items:
                total_items += 1
                
                serial_entry = None
                entered_serial = "Not entered"
                entry_status = "Pending"
                verification_status = "Pending"
                verified_by = "-"
                verified_on = "-"
                
                try:
                    serial_entry = HardwareSerialEntry.objects.get(assignment_item=item)
                    entered_serial = serial_entry.serial_number
                    
                    if serial_entry.verified:
                        verification_status = "Verified"
                        verified_count += 1
                        verified_by = serial_entry.verified_by.get_full_name() or serial_entry.verified_by.username if serial_entry.verified_by else "-"
                        verified_on = serial_entry.verified_at.strftime("%d/%m/%Y %H:%M") if serial_entry.verified_at else "-"
                        
                        if serial_entry.serial_number == item.hardware.serial_number:
                            entry_status = "Verified - Correct"
                        else:
                            entry_status = "Verified - Mismatch"
                    else:
                        if serial_entry.serial_number == item.hardware.serial_number:
                            entry_status = "Matched - Pending"
                            matched_count += 1
                            verification_status = "Pending Verification"
                        else:
                            entry_status = "Mismatch"
                            mismatch_count += 1
                            verification_status = "Not Verified"
                            
                except HardwareSerialEntry.DoesNotExist:
                    entry_status = "Not Entered"
                    pending_count += 1
                    verification_status = "Pending"
                
                # Determine row fill color
                if serial_entry and serial_entry.verified:
                    row_fill = success_fill
                elif serial_entry and serial_entry.serial_number == item.hardware.serial_number:
                    row_fill = info_fill
                elif serial_entry and serial_entry.serial_number != item.hardware.serial_number:
                    row_fill = danger_fill
                else:
                    row_fill = warning_fill
                
                row_data = [
                    str(assignment.assignment_id)[:8],
                    assignment.project.project_name,
                    assignment.exam_city or 'Not specified',
                    assignment.assigned_date.strftime("%d/%m/%Y") if assignment.assigned_date else 'N/A',
                    assignment.expected_return_date.strftime("%d/%m/%Y") if assignment.expected_return_date else 'N/A',
                    item.hardware.hardware_type.name,
                    item.hardware.model_name or '-',
                    item.hardware.brand or '-',
                    item.hardware.serial_number,
                    entered_serial,
                    entry_status,
                    verification_status,
                    verified_by,
                    verified_on
                ]
                
                for col_num, value in enumerate(row_data, 1):
                    cell = ws.cell(row=row_num, column=col_num, value=value)
                    cell.border = border
                    cell.fill = row_fill
                    cell.alignment = Alignment(vertical="center")
                    
                    if col_num in [4, 5, 14]:
                        cell.alignment = Alignment(horizontal="center", vertical="center")
                
                row_num += 1
        
        # ========== SUMMARY SECTION ==========
        row_num += 2
        summary_row = row_num
        
        # Summary header
        ws.merge_cells(start_row=summary_row, start_column=1, end_row=summary_row, end_column=14)
        summary_header = ws.cell(row=summary_row, column=1, value="📊 SUMMARY STATISTICS")
        summary_header.font = Font(bold=True, size=14, color="FFFFFF")
        summary_header.fill = PatternFill(start_color="2C3E50", end_color="2C3E50", fill_type="solid")
        summary_header.alignment = header_alignment
        
        summary_row += 1
        
        summary_headers = ['Summary Statistics', 'Value']
        for col_num, header in enumerate(summary_headers, 1):
            cell = ws.cell(row=summary_row, column=col_num, value=header)
            cell.font = Font(bold=True, color="FFFFFF", size=11)
            cell.fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
            cell.alignment = header_alignment
            cell.border = border
        
        summary_data = [
            ['Total Items', total_items],
            ['✅ Verified Items', verified_count],
            ['🟦 Matched Items (Pending)', matched_count],
            ['❌ Mismatched Items', mismatch_count],
            ['⏳ Pending Entry', pending_count],
            ['📈 Completion Rate', f"{round((verified_count / total_items * 100) if total_items > 0 else 0, 1)}%"],
            ['', ''],
            ['Employee Name', request.user.get_full_name() or request.user.username],
            ['Employee Email', request.user.email],
            ['Branch', getattr(request.user, 'branch_location', 'Not Assigned')],
            ['Exam City', active_assignments.first().exam_city if active_assignments.exists() else 'Not Assigned'],
            ['Generated On', datetime.now().strftime("%d/%m/%Y %H:%M:%S")],
            ['IP Address', get_client_ip(request)],
        ]
        
        for i, (label, value) in enumerate(summary_data, summary_row + 1):
            label_cell = ws.cell(row=i, column=1, value=label)
            label_cell.border = border
            label_cell.font = Font(bold=True)
            label_cell.fill = PatternFill(start_color="F8F9FA", end_color="F8F9FA", fill_type="solid")
            
            value_cell = ws.cell(row=i, column=2, value=value)
            value_cell.border = border
            value_cell.alignment = Alignment(horizontal="center")
            
            # Color code completion rate
            if label == '📈 Completion Rate':
                rate = float(value.rstrip('%')) if value != '0%' else 0
                if rate >= 80:
                    value_cell.fill = success_fill
                    value_cell.font = Font(color="006100", bold=True)
                elif rate >= 50:
                    value_cell.fill = warning_fill
                    value_cell.font = Font(color="9C5700", bold=True)
                else:
                    value_cell.fill = danger_fill
                    value_cell.font = Font(color="9C0006", bold=True)
        
        # ========== AUTO-ADJUST COLUMN WIDTHS ==========
        for col in range(1, len(headers) + 1):
            column_letter = get_column_letter(col)
            max_length = len(headers[col-1])
            
            for row in range(5, row_num + 1):
                cell_value = ws.cell(row=row, column=col).value
                if cell_value:
                    max_length = max(max_length, len(str(cell_value)))
            
            adjusted_width = min(max_length + 4, 50)
            ws.column_dimensions[column_letter].width = adjusted_width
        
        # ========== FREEZE HEADER ROW ==========
        ws.freeze_panes = 'A6'
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="export_report",
            module="Export Reports",
            description=f"Employee {request.user.username} exported hardware report ({total_items} items, {verified_count} verified)",
            target_user=request.user,
            new_value={
                'total_items': total_items,
                'verified_count': verified_count,
                'matched_count': matched_count,
                'mismatch_count': mismatch_count,
                'pending_count': pending_count,
                'completion_rate': round((verified_count / total_items * 100) if total_items > 0 else 0, 1),
                'exam_city': active_assignments.first().exam_city if active_assignments.exists() else 'None'
            }
        )
        
        # ========== PREPARE RESPONSE ==========
        response = HttpResponse(
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        wb.save(response)
        messages.success(request, f'✅ Hardware report exported successfully! ({total_items} items)')
        return response
        
    except Exception as e:
        # ========== ERROR LOGGING ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="system_error",
            module="Export Reports",
            description=f"Export failed for {request.user.username}: {str(e)}",
            target_user=request.user,
            new_value={'error': str(e)}
        )
        messages.error(request, f'Error exporting hardware report: {str(e)}')
        return redirect('my_hardware')

# views.py - Updated Hardware Transfer Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q
from datetime import datetime, timedelta
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import (
    CustomUser, HardwareAssignment, HardwareAssignmentItem, 
    HardwareAssetEntry, Hardware, Project, EmployeeHardwareTransfer,
    TransferItem, TransferHistory, TransferNotification
)


# ============================================================
# REQUEST HARDWARE TRANSFER
# ============================================================
# views.py - Updated request_hardware_transfer

@login_required
def request_hardware_transfer(request):
    """
    Employee requests hardware transfer from another employee (multiple items)
    Supports same-branch (manager approval) and cross-branch (super admin approval)
    With comprehensive audit logging
    ✅ FIXED: Added safe fallback for transfer_type to prevent null errors.
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized transfer request attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('manager_dashboard')
    
    # ========== GET ALL EMPLOYEES (All Branches) ==========
    employees = CustomUser.objects.filter(
        user_type='employee',
        is_active=True
    ).exclude(id=request.user.id).select_related('manager')
    
    current_user_branch = request.user.branch_location or 'Not Assigned'
    
    for emp in employees:
        active_assignment = HardwareAssignment.objects.filter(
            employee=emp,
            actual_return_date__isnull=True
        ).first()
        
        emp.current_exam_city = active_assignment.exam_city if active_assignment else 'Not Assigned'
        emp.current_exam_center = getattr(active_assignment, 'exam_center_name', None) if active_assignment else None
        emp.current_project = active_assignment.project if active_assignment else None
        emp.has_assignment = active_assignment is not None
        
        emp.branch_display = emp.branch_location or 'Not Assigned'
        emp.is_same_branch = (emp.branch_location == current_user_branch)
        emp.branch = emp.branch_location or 'Not Assigned'
    
    # ========== GET EMPLOYEE'S HARDWARE ==========
    active_assignments = HardwareAssignment.objects.filter(
        employee=request.user,
        actual_return_date__isnull=True
    ).prefetch_related('hardwareassignmentitem_set__hardware__hardware_type')
    
    my_hardware = []
    for assignment in active_assignments:
        for item in assignment.hardwareassignmentitem_set.all():
            hardware = item.hardware
            if hardware.status == 'in_use':
                my_hardware.append({
                    'id': hardware.id,
                    'hardware_type': hardware.hardware_type.name,
                    'asset_number': hardware.asset_number if hardware.asset_number else 'N/A',
                    'serial_number': hardware.serial_number,
                    'model_name': hardware.model_name,
                    'brand': hardware.brand,
                    'current_exam_city': assignment.exam_city or 'Unknown',
                    'current_project': assignment.project,
                    'assignment_id': assignment.id
                })
    
    # ========== GET PROJECTS ==========
    manager = request.user.manager
    projects = Project.objects.filter(
        Q(assigned_manager__isnull=True) |
        Q(assigned_manager=manager) |
        Q(created_by=manager)
    ).distinct().order_by('-created_at')
    
    # ========== AUDIT LOG - VIEW ==========
    if request.session.get('last_transfer_request_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Hardware Transfer",
            description=f"Employee {request.user.username} viewed transfer request form ({len(my_hardware)} hardware items available)",
            target_user=request.user,
            new_value={
                'available_hardware': len(my_hardware),
                'available_employees': employees.count()
            }
        )
        request.session['last_transfer_request_view'] = timezone.now().timestamp()
    
    # ========== POST REQUEST ==========
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        hardware_ids = request.POST.getlist('hardware_ids')
        to_employee_id = request.POST.get('to_employee_id')
        to_project_id = request.POST.get('to_project_id')
        receiver_city = request.POST.get('receiver_city', '').strip()
        receiver_exam_center = request.POST.get('receiver_exam_center', '').strip()
        
        # ✅ CRITICAL FIX: Ensure transfer_type is never null/empty
        transfer_type = request.POST.get('transfer_type')
        if not transfer_type:
            transfer_type = 'permanent'  # Default fallback
        
        reason = request.POST.get('reason', '').strip()
        
        # ========== VALIDATE ==========
        if not hardware_ids:
            messages.error(request, 'Please select at least one hardware item to transfer!')
            return redirect('request_hardware_transfer')
        
        if not to_employee_id:
            messages.error(request, 'Please select an employee to transfer to.')
            return redirect('request_hardware_transfer')
        
        if not reason:
            messages.error(request, 'Please provide a reason for the transfer.')
            return redirect('request_hardware_transfer')
        
        # Handle dates
        expected_arrival_date = None
        expected_return_date = None
        
        if request.POST.get('expected_arrival_date'):
            try:
                arrival_date_str = request.POST.get('expected_arrival_date')
                if '-' in arrival_date_str:
                    parts = arrival_date_str.split('-')
                    if len(parts) == 3 and len(parts[0]) == 2 and len(parts[1]) == 2 and len(parts[2]) == 4:
                        expected_arrival_date = datetime.strptime(arrival_date_str, '%d-%m-%Y').date()
                    else:
                        expected_arrival_date = datetime.strptime(arrival_date_str, '%Y-%m-%d').date()
                else:
                    expected_arrival_date = datetime.strptime(arrival_date_str, '%Y-%m-%d').date()
            except (ValueError, TypeError):
                expected_arrival_date = None
        
        if transfer_type == 'temporary' and request.POST.get('expected_return_date'):
            try:
                return_date_str = request.POST.get('expected_return_date')
                if '-' in return_date_str:
                    parts = return_date_str.split('-')
                    if len(parts) == 3 and len(parts[0]) == 2 and len(parts[1]) == 2 and len(parts[2]) == 4:
                        expected_return_date = datetime.strptime(return_date_str, '%d-%m-%Y').date()
                    else:
                        expected_return_date = datetime.strptime(return_date_str, '%Y-%m-%d').date()
                else:
                    expected_return_date = datetime.strptime(return_date_str, '%Y-%m-%d').date()
            except (ValueError, TypeError):
                expected_return_date = None
        
        requester_notes = request.POST.get('requester_notes', '').strip()
        delivery_method = request.POST.get('delivery_method', '').strip()
        
        try:
            to_employee = CustomUser.objects.get(id=to_employee_id, user_type='employee')
            
            # ========== DETERMINE IF CROSS-BRANCH ==========
            current_branch = request.user.branch_location or 'Not Assigned'
            target_branch = to_employee.branch_location or 'Not Assigned'
            is_cross_branch = (current_branch != target_branch)
            
            # ========== CHECK RECEIVER'S ASSIGNMENT ==========
            to_employee_assignment = HardwareAssignment.objects.filter(
                employee=to_employee,
                actual_return_date__isnull=True
            ).first()
            
            if not to_employee_assignment:
                if not receiver_city:
                    messages.error(request, 'Please enter the receiver\'s city! (Receiver has no active assignment)')
                    return redirect('request_hardware_transfer')
                if not receiver_exam_center:
                    messages.error(request, 'Please enter the receiver\'s exam center! (Receiver has no active assignment)')
                    return redirect('request_hardware_transfer')
            
            # ========== GET PROJECT ==========
            to_project = None
            if to_project_id:
                try:
                    to_project = Project.objects.get(
                        Q(id=to_project_id) &
                        (Q(assigned_manager__isnull=True) |
                         Q(assigned_manager=manager) |
                         Q(created_by=manager))
                    )
                except Project.DoesNotExist:
                    messages.warning(request, 'Selected project not found. Using employee\'s current project.')
            
            # ========== VALIDATE HARDWARE ==========
            valid_hardware = []
            errors = []
            
            for hw_id in hardware_ids:
                try:
                    hardware = Hardware.objects.get(id=hw_id)
                    is_assigned = HardwareAssignmentItem.objects.filter(
                        hardware=hardware,
                        assignment__employee=request.user,
                        assignment__actual_return_date__isnull=True
                    ).exists()
                    
                    if not is_assigned:
                        errors.append(f"Hardware '{hardware.serial_number}' is not assigned to you!")
                    elif hardware.status != 'in_use':
                        errors.append(f"Hardware '{hardware.serial_number}' is not currently in use!")
                    else:
                        valid_hardware.append(hardware)
                except Hardware.DoesNotExist:
                    errors.append(f"Hardware with ID {hw_id} not found!")
            
            if errors:
                for error in errors[:3]:
                    messages.error(request, error)
                if len(errors) > 3:
                    messages.error(request, f'...and {len(errors) - 3} more errors')
                return redirect('request_hardware_transfer')
            
            if not valid_hardware:
                messages.error(request, 'No valid hardware items selected!')
                return redirect('request_hardware_transfer')
            
            # ========== GET SOURCE DETAILS ==========
            first_hardware = valid_hardware[0]
            assignment_item = HardwareAssignmentItem.objects.filter(
                hardware=first_hardware,
                assignment__employee=request.user,
                assignment__actual_return_date__isnull=True
            ).first()
            
            from_exam_city = assignment_item.assignment.exam_city or 'Unknown'
            from_project = assignment_item.assignment.project
            
            # ========== DETERMINE RECEIVER DETAILS ==========
            if to_employee_assignment:
                to_exam_city = to_employee_assignment.exam_city
                to_exam_center = getattr(to_employee_assignment, 'exam_center_name', None)
                if not to_project:
                    to_project = to_employee_assignment.project
            else:
                to_exam_city = receiver_city
                to_exam_center = receiver_exam_center
                if not to_project:
                    to_project = None
            
            # ========== CREATE TRANSFER ==========
            transfer = EmployeeHardwareTransfer.objects.create(
                from_employee=request.user,
                to_employee=to_employee,
                from_exam_city=from_exam_city,
                to_exam_city=to_exam_city,
                to_exam_center=to_exam_center,
                from_project=from_project,
                to_project=to_project,
                transfer_type=transfer_type,  # ✅ Now guaranteed to be valid
                reason=reason,
                expected_arrival_date=expected_arrival_date,
                expected_return_date=expected_return_date,
                requester_notes=requester_notes,
                delivery_method=delivery_method,
                from_branch=current_branch,
                to_branch=target_branch,
                is_cross_branch=is_cross_branch,
                status='requested',
                created_by=request.user
            )
            
            # Create transfer items
            for hardware in valid_hardware:
                TransferItem.objects.create(
                    transfer=transfer,
                    hardware=hardware,
                    status='pending'
                )
            
            # Create history entry
            TransferHistory.objects.create(
                transfer=transfer,
                action=f"Transfer request created with {len(valid_hardware)} item(s)",
                status='requested',
                notes=f"Reason: {reason}",
                updated_by=request.user
            )
            
            # ========== AUDIT LOG ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="transfer_request",
                module="Hardware Transfer",
                description=f"Employee {request.user.username} requested transfer of {len(valid_hardware)} hardware item(s) to {to_employee.get_full_name() or to_employee.username} ({'Cross-Branch' if is_cross_branch else 'Same Branch'})",
                target_user=to_employee,
                target_model="EmployeeHardwareTransfer",
                target_id=transfer.id,
                new_value={
                    'transfer_id': transfer.transfer_id,
                    'from_employee': request.user.username,
                    'to_employee': to_employee.username,
                    'item_count': len(valid_hardware),
                    'transfer_type': transfer_type,
                    'from_city': from_exam_city,
                    'to_city': to_exam_city,
                    'from_branch': current_branch,
                    'to_branch': target_branch,
                    'is_cross_branch': is_cross_branch,
                    'reason': reason[:100],
                    'ip': client_ip
                }
            )
            
            # ========== DETERMINE APPROVAL PATH ==========
            if is_cross_branch:
                super_admins = CustomUser.objects.filter(user_type='super_admin', is_active=True)
                
                for sa in super_admins:
                    TransferNotification.objects.create(
                        transfer=transfer,
                        recipient=sa,
                        message=f"⚠️ CROSS-BRANCH Transfer Request #{transfer.transfer_id} from {request.user.get_full_name() or request.user.username} ({current_branch}) to {to_employee.get_full_name() or to_employee.username} ({target_branch}) with {len(valid_hardware)} item(s)"
                    )
                
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_info",
                    module="Hardware Transfer",
                    description=f"Cross-branch transfer #{transfer.transfer_id} requires Super Admin approval",
                    target_user=request.user,
                    target_model="EmployeeHardwareTransfer",
                    target_id=transfer.id
                )
                
                messages.success(
                    request,
                    f'✅ Cross-branch transfer request #{transfer.transfer_id} created successfully! It requires Super Admin approval.'
                )
                
                try:
                    send_transfer_notification_email(transfer, 'super_admin')
                except Exception as e:
                    print(f"Email notification failed: {str(e)}")
                
            else:
                if manager:
                    TransferNotification.objects.create(
                        transfer=transfer,
                        recipient=manager,
                        message=f"Transfer request #{transfer.transfer_id} from {request.user.get_full_name() or request.user.username} to {to_employee.get_full_name() or to_employee.username} with {len(valid_hardware)} item(s)"
                    )
                    
                    create_audit_log(
                        request=request,
                        user=request.user,
                        action="system_info",
                        module="Hardware Transfer",
                        description=f"Manager {manager.username} notified of transfer request #{transfer.transfer_id}",
                        target_user=manager,
                        target_model="EmployeeHardwareTransfer",
                        target_id=transfer.id
                    )
                
                messages.success(
                    request,
                    f'✅ Transfer request #{transfer.transfer_id} created successfully! It requires Manager approval.'
                )
                
                try:
                    send_transfer_notification_email(transfer, 'manager')
                except Exception as e:
                    print(f"Email notification failed: {str(e)}")
            
            return redirect('my_transfers')
            
        except CustomUser.DoesNotExist:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Transfer",
                description=f"Transfer request failed - Selected employee {to_employee_id} not found",
                target_user=request.user
            )
            messages.error(request, 'Selected employee not found!')
            return redirect('request_hardware_transfer')
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Hardware Transfer",
                description=f"Transfer request failed: {str(e)}",
                target_user=request.user,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Error creating transfer: {str(e)}')
            return redirect('request_hardware_transfer')
    
    # ========== GET REQUEST ==========
    context = {
        'employees': employees,
        'my_hardware': my_hardware,
        'projects': projects,
        'today': timezone.now().date(),
        'max_date': timezone.now().date() + timedelta(days=30),
        'current_user_branch': current_user_branch,
    }
    return render(request, 'employee/request_transfer.html', context)


def send_transfer_notification_email(transfer, recipient_type):
    """Send email notification for transfer request"""
    from django.core.mail import send_mail
    from django.conf import settings
    from django.template.loader import render_to_string
    
    subject = f'Hardware Transfer Request #{transfer.transfer_id}'
    
    if recipient_type == 'super_admin':
        super_admins = CustomUser.objects.filter(user_type='super_admin', is_active=True)
        recipient_emails = [sa.email for sa in super_admins if sa.email]
        
        html_message = render_to_string('email/transfer_cross_branch_notification.html', {
            'transfer': transfer,
            'from_employee': transfer.from_employee.get_full_name() or transfer.from_employee.username,
            'to_employee': transfer.to_employee.get_full_name() or transfer.to_employee.username,
            'from_branch': transfer.from_branch or 'Unknown',
            'to_branch': transfer.to_branch or 'Unknown',
            'item_count': transfer.transfer_items.count(),
            'reason': transfer.reason,
            'transfer_id': transfer.transfer_id,
            'is_cross_branch': transfer.is_cross_branch
        })
    else:
        # Manager notification
        manager = transfer.from_employee.manager
        if manager and manager.email:
            recipient_emails = [manager.email]
            
            html_message = render_to_string('email/transfer_notification.html', {
                'transfer': transfer,
                'from_employee': transfer.from_employee.get_full_name() or transfer.from_employee.username,
                'to_employee': transfer.to_employee.get_full_name() or transfer.to_employee.username,
                'item_count': transfer.transfer_items.count(),
                'reason': transfer.reason,
                'transfer_id': transfer.transfer_id
            })
        else:
            return
    
    if recipient_emails:
        send_mail(
            subject=subject,
            message=f'Transfer request #{transfer.transfer_id} has been created.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipient_emails,
            html_message=html_message,
            fail_silently=False,
        )
@login_required
def super_admin_transfer_requests(request):
    """
    Super Admin views ALL cross-branch transfer requests
    With comprehensive audit logging
    ✅ FIX: Shows all transfers, not just pending
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized access to transfer requests by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ✅ FIX: Get ALL cross-branch transfers, not just 'requested'
    transfers = EmployeeHardwareTransfer.objects.filter(
        is_cross_branch=True
    ).order_by('-requested_date')
    
    # ========== APPLY FILTERS ==========
    status_filter = request.GET.get('status', '')
    if status_filter:
        transfers = transfers.filter(status=status_filter)
    
    # Branch filters
    from_branch_filter = request.GET.get('from_branch', '')
    if from_branch_filter:
        transfers = transfers.filter(from_branch__icontains=from_branch_filter)
    
    to_branch_filter = request.GET.get('to_branch', '')
    if to_branch_filter:
        transfers = transfers.filter(to_branch__icontains=to_branch_filter)
    
    # Date filter
    date_filter = request.GET.get('date', '')
    if date_filter:
        try:
            date_obj = datetime.strptime(date_filter, '%Y-%m-%d')
            transfers = transfers.filter(requested_date__date=date_obj)
        except ValueError:
            pass
    
    # ========== CALCULATE STATISTICS ==========
    total = transfers.count()
    pending = transfers.filter(status='requested').count()
    approved = transfers.filter(status='approved_by_super_admin').count()
    in_transit = transfers.filter(status='in_transit').count()
    received = transfers.filter(status='received_by_receiver').count()
    completed = transfers.filter(status='completed').count()
    rejected = transfers.filter(status='rejected').count()
    cancelled = transfers.filter(status='cancelled').count()
    
    # ========== ENRICH TRANSFER DATA ==========
    enriched_transfers = []
    for transfer in transfers:
        transfer_items = transfer.transfer_items.all()
        total_count = transfer_items.count()
        pending_count = transfer_items.filter(status='pending').count()
        in_transit_count = transfer_items.filter(status='in_transit').count()
        received_count = transfer_items.filter(status='received').count()
        returned_count = transfer_items.filter(status='returned').count()
        
        enriched_transfers.append({
            'transfer': transfer,
            'total_items': total_count,
            'pending_items': pending_count,
            'in_transit_items': in_transit_count,
            'received_items': received_count,
            'returned_items': returned_count,
            'can_approve': transfer.status == 'requested',
            'can_reject': transfer.status == 'requested',
        })
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_transfer_requests_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Hardware Transfer",
            description=f"Super Admin {request.user.username} viewed cross-branch transfer requests ({total} total, {pending} pending)",
            target_user=request.user,
            new_value={
                'total': total,
                'pending': pending,
                'approved': approved,
                'in_transit': in_transit,
                'received': received,
                'completed': completed,
                'rejected': rejected,
                'cancelled': cancelled
            }
        )
        request.session['last_transfer_requests_view'] = timezone.now().timestamp()
    
    # ========== GET DISTINCT BRANCHES FOR FILTER ==========
    from_branches = EmployeeHardwareTransfer.objects.filter(
        is_cross_branch=True
    ).values_list('from_branch', flat=True).distinct()
    from_branches = [b for b in from_branches if b]
    
    to_branches = EmployeeHardwareTransfer.objects.filter(
        is_cross_branch=True
    ).values_list('to_branch', flat=True).distinct()
    to_branches = [b for b in to_branches if b]
    
    context = {
        'enriched_transfers': enriched_transfers,
        'total': total,
        'pending': pending,
        'approved': approved,
        'in_transit': in_transit,
        'received': received,
        'completed': completed,
        'rejected': rejected,
        'cancelled': cancelled,
        'status_filter': status_filter,
        'from_branch_filter': from_branch_filter,
        'to_branch_filter': to_branch_filter,
        'date_filter': date_filter,
        'from_branches': sorted(set(from_branches)),
        'to_branches': sorted(set(to_branches)),
    }
    return render(request, 'super_admin/transfer_requests.html', context)
@login_required
def super_admin_approve_transfer(request, transfer_id):
    """
    Super Admin approves cross-branch transfer request
    Sends email notifications to both sender and receiver
    ✅ FIXED: Uses transfer_id (UUID) for lookup and redirects
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized transfer approval attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ✅ FIXED: Lookup by transfer_id (UUID) instead of id (Integer)
    transfer = get_object_or_404(
        EmployeeHardwareTransfer,
        transfer_id=transfer_id,
        is_cross_branch=True
    )
    
    if transfer.status != 'requested':
        messages.error(request, f'This transfer request is already {transfer.get_status_display()}.')
        return redirect('super_admin_transfer_requests')
    
    if request.method == 'POST':
        notes = request.POST.get('notes', '').strip()
        client_ip = get_client_ip(request)
        
        # Set status to approved_sa (Super Admin approved)
        transfer.status = 'approved_sa'
        transfer.approved_by_super_admin = request.user
        transfer.super_admin_approved_date = timezone.now()
        transfer.manager_notes = notes
        transfer.save()
        
        # Create history entry
        TransferHistory.objects.create(
            transfer=transfer,
            action="Transfer Approved by Super Admin",
            status='approved_sa',
            notes=f"Approved by Super Admin {request.user.get_full_name()}. Notes: {notes}",
            updated_by=request.user,
            approval_type='super_admin',
            is_cross_branch=True
        )
        
        # Create audit log
        create_audit_log(
            request=request,
            user=request.user,
            action="transfer_approve",
            module="Hardware Transfer",
            description=f"Super Admin {request.user.username} approved cross-branch transfer #{transfer.transfer_id}",
            target_user=transfer.from_employee,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer.id,
            old_value={'status': 'requested', 'is_cross_branch': True},
            new_value={'status': 'approved_sa', 'approved_by': request.user.username}
        )
        
        # Create notifications for both employees
        TransferNotification.objects.create(
            transfer=transfer,
            recipient=transfer.from_employee,
            message=f"✅ Cross-branch transfer #{transfer.transfer_id} has been approved by Super Admin. You can now initiate the transfer.",
            notification_type='approved',
            is_cross_branch=True
        )
        
        TransferNotification.objects.create(
            transfer=transfer,
            recipient=transfer.to_employee,
            message=f"✅ Cross-branch transfer #{transfer.transfer_id} has been approved by Super Admin. Please prepare to receive the hardware.",
            notification_type='approved',
            is_cross_branch=True
        )
        
        # ========== SEND EMAIL TO SENDER ==========
        try:
            send_transfer_approval_email_to_sender(transfer, request.user)
            messages.info(request, f'📧 Email sent to {transfer.from_employee.email} to initiate transfer.')
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Transfer",
                description=f"Sender email failed: {str(e)}",
                target_user=transfer.from_employee,
                target_model="EmployeeHardwareTransfer",
                target_id=transfer.id
            )
            messages.warning(request, f'Transfer approved but sender email failed: {str(e)}')
        
        # ========== SEND EMAIL TO RECEIVER ==========
        try:
            send_transfer_approval_email_to_receiver(transfer, request.user)
            messages.info(request, f'📧 Email sent to {transfer.to_employee.email} about incoming hardware.')
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Transfer",
                description=f"Receiver email failed: {str(e)}",
                target_user=transfer.to_employee,
                target_model="EmployeeHardwareTransfer",
                target_id=transfer.id
            )
            messages.warning(request, f'Transfer approved but receiver email failed: {str(e)}')
        
        messages.success(request, f'✅ Cross-branch transfer #{transfer.transfer_id} approved successfully!')
        # ✅ FIXED: Redirect uses transfer.transfer_id (UUID)
        return redirect('super_admin_transfer_requests')
    
    context = {'transfer': transfer}
    return render(request, 'super_admin/approve_transfer.html', context)


@login_required
def super_admin_reject_transfer(request, transfer_id):
    """
    Super Admin rejects cross-branch transfer request
    With comprehensive audit logging and email notification
    ✅ FIXED: Uses transfer_id (UUID) for lookup and redirects
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized transfer rejection attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ✅ FIXED: Lookup by transfer_id (UUID) instead of id (Integer)
    transfer = get_object_or_404(
        EmployeeHardwareTransfer,
        transfer_id=transfer_id,
        is_cross_branch=True
    )
    
    # ========== CHECK STATUS ==========
    if transfer.status != 'requested':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Transfer rejection failed - Transfer {transfer.transfer_id} is already {transfer.get_status_display()}",
            target_user=request.user,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer.id
        )
        messages.error(request, f'This transfer request is already {transfer.get_status_display()}.')
        return redirect('super_admin_transfer_requests')
    
    if request.method == 'POST':
        rejection_reason = request.POST.get('rejection_reason', '').strip()
        client_ip = get_client_ip(request)
        
        # ========== REJECT TRANSFER ==========
        transfer.status = 'rejected'
        transfer.manager_notes = rejection_reason
        transfer.rejected_by = request.user
        transfer.rejected_date = timezone.now()
        transfer.save()
        
        # Create history entry
        TransferHistory.objects.create(
            transfer=transfer,
            action="Transfer Rejected by Super Admin",
            status='rejected',
            notes=f"Rejected by Super Admin {request.user.get_full_name()}. Reason: {rejection_reason or 'No reason provided'}",
            updated_by=request.user,
            is_cross_branch=True
        )
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="transfer_reject",
            module="Hardware Transfer",
            description=f"Super Admin {request.user.username} rejected cross-branch transfer #{transfer.transfer_id}",
            target_user=transfer.from_employee,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer.id,
            old_value={
                'status': 'requested',
                'from_branch': transfer.from_branch,
                'to_branch': transfer.to_branch,
                'is_cross_branch': True
            },
            new_value={
                'status': 'rejected',
                'rejected_by': request.user.username,
                'rejection_date': timezone.now().isoformat(),
                'reason': rejection_reason,
                'ip': client_ip
            }
        )
        
        # ========== CREATE NOTIFICATION ==========
        TransferNotification.objects.create(
            transfer=transfer,
            recipient=transfer.from_employee,
            message=f"❌ Cross-branch transfer #{transfer.transfer_id} has been rejected by Super Admin. Reason: {rejection_reason or 'No reason provided'}"
        )
        
        # ========== SEND EMAIL TO SENDER ==========
        try:
            send_transfer_rejection_email_to_sender(transfer, request.user, rejection_reason)
            messages.info(request, f'📧 Email sent to {transfer.from_employee.email} about the rejection.')
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Transfer",
                description=f"Sender email failed: {str(e)}",
                target_user=transfer.from_employee,
                target_model="EmployeeHardwareTransfer",
                target_id=transfer.id
            )
            messages.warning(request, f'Transfer rejected but sender email failed: {str(e)}')
        
        # ========== SEND EMAIL TO RECEIVER ==========
        try:
            send_transfer_rejection_email_to_receiver(transfer, request.user, rejection_reason)
            messages.info(request, f'📧 Email sent to {transfer.to_employee.email} about the rejection.')
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Transfer",
                description=f"Receiver email failed: {str(e)}",
                target_user=transfer.to_employee,
                target_model="EmployeeHardwareTransfer",
                target_id=transfer.id
            )
            messages.warning(request, f'Transfer rejected but receiver email failed: {str(e)}')
        
        messages.warning(request, f'❌ Cross-branch transfer #{transfer.transfer_id} rejected successfully!')
        # ✅ FIXED: Redirect uses transfer.transfer_id (UUID)
        return redirect('super_admin_transfer_requests')
    
    context = {'transfer': transfer}
    return render(request, 'super_admin/reject_transfer.html', context)


@login_required
def super_admin_transfer_details(request, transfer_id):
    """
    Super Admin view detailed transfer information
    With comprehensive audit logging
    ✅ FIXED: Uses transfer_id (UUID) for lookup
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized transfer details access by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ✅ FIXED: Lookup by transfer_id (UUID) instead of id (Integer)
    transfer = get_object_or_404(
        EmployeeHardwareTransfer,
        transfer_id=transfer_id,
        is_cross_branch=True
    )
    
    # ========== GET TRANSFER ITEMS ==========
    transfer_items = transfer.transfer_items.all().select_related(
        'hardware', 
        'hardware__hardware_type'
    )
    
    # ========== GET ASSET ENTRIES FOR EACH ITEM ==========
    for item in transfer_items:
        # Get current assignment for this hardware
        current_assignment = HardwareAssignmentItem.objects.filter(
            hardware=item.hardware,
            assignment__actual_return_date__isnull=True
        ).first()
        
        if current_assignment:
            item.current_employee = current_assignment.assignment.employee
            item.current_exam_city = current_assignment.assignment.exam_city
            item.current_assignment_id = current_assignment.assignment.id
        else:
            item.current_employee = None
            item.current_exam_city = None
            item.current_assignment_id = None
        
        # ✅ FIX: Get asset entry using the hardware assignment item
        # First find the HardwareAssignmentItem for this hardware
        try:
            # Get the current assignment item for this hardware
            hw_assignment_item = HardwareAssignmentItem.objects.filter(
                hardware=item.hardware,
                assignment__actual_return_date__isnull=True
            ).first()
            
            if hw_assignment_item:
                # Now try to get the asset entry
                asset_entry = HardwareAssetEntry.objects.get(hardware_item=hw_assignment_item)
                item.asset_entry = asset_entry
            else:
                item.asset_entry = None
        except HardwareAssetEntry.DoesNotExist:
            item.asset_entry = None
        except Exception as e:
            item.asset_entry = None
        
        # Get hardware details
        item.hardware_type_name = item.hardware.hardware_type.name if item.hardware.hardware_type else 'Unknown'
        item.hardware_status = item.hardware.status
        item.hardware_branch = item.hardware.branch_location
    
    # ========== STATISTICS ==========
    total_items = transfer_items.count()
    pending_items = transfer_items.filter(status='pending').count()
    in_transit_items = transfer_items.filter(status='in_transit').count()
    received_items = transfer_items.filter(status='received').count()
    returned_items = transfer_items.filter(status='returned').count()
    
    # ========== GET HISTORY ==========
    history = TransferHistory.objects.filter(transfer=transfer).order_by('-created_at')
    
    # ========== GET NOTIFICATIONS ==========
    notifications = TransferNotification.objects.filter(transfer=transfer).order_by('-created_at')
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="system_info",
        module="Hardware Transfer",
        description=f"Super Admin {request.user.username} viewed transfer details #{transfer.transfer_id}",
        target_user=request.user,
        target_model="EmployeeHardwareTransfer",
        target_id=transfer.id,
        new_value={
            'transfer_id': transfer.transfer_id,
            'status': transfer.status,
            'from_employee': transfer.from_employee.username,
            'to_employee': transfer.to_employee.username,
            'total_items': total_items,
            'pending_items': pending_items,
            'in_transit_items': in_transit_items,
            'received_items': received_items,
            'returned_items': returned_items
        }
    )
    
    # ========== CHECK AUTHORIZATION FOR ACTIONS ==========
    can_approve = transfer.status == 'requested'
    can_reject = transfer.status == 'requested'
    
    context = {
        'transfer': transfer,
        'transfer_items': transfer_items,
        'total_items': total_items,
        'pending_items': pending_items,
        'in_transit_items': in_transit_items,
        'received_items': received_items,
        'returned_items': returned_items,
        'history': history,
        'notifications': notifications,
        'can_approve': can_approve,
        'can_reject': can_reject,
        'is_super_admin': request.user.user_type == 'super_admin',
    }
    return render(request, 'super_admin/transfer_details.html', context)   

# ============================================================
# UPDATE TRANSFER STATUS (EMPLOYEE)
# ============================================================
# views.py - Updated update_transfer_status_employee with correct return logic

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db import transaction
from datetime import timedelta
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import (
    CustomUser, Hardware, HardwareAssignment, HardwareAssignmentItem,
    HardwareAssetEntry, Project, EmployeeHardwareTransfer,
    TransferItem, TransferHistory, TransferNotification
)
@login_required
@transaction.atomic
def update_transfer_status_employee(request, transfer_id):
    """
    Employee updates transfer status with proper hardware transfer
    ✅ FIX: Hardware branch_location is updated to receiver's branch
    ✅ FIX: Auto-updates hardware without requiring manual edit
    ✅ FIX: Correct field names (from_exam_city, to_exam_city, to_exam_center)
    ✅ FIX: assigned_by cannot be null
    ✅ FIX: Redirects using transfer.transfer_id (UUID) instead of transfer.id (Integer)
    Supports both same-branch and cross-branch transfers
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized transfer update attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('manager_dashboard')
    
    # ✅ Correctly uses transfer_id (UUID)
    transfer = get_object_or_404(EmployeeHardwareTransfer, transfer_id=transfer_id)
    
    # ========== CHECK AUTHORIZATION ==========
    if request.user not in [transfer.from_employee, transfer.to_employee]:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized transfer update attempt on #{transfer.transfer_id} by {request.user.username}",
            target_user=request.user,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer.id
        )
        messages.error(request, 'You are not authorized for this action.')
        return redirect('my_transfers')
    
    if request.method != 'POST':
        return redirect('my_transfers')
    
    action = request.POST.get('action')
    notes = request.POST.get('notes', '').strip()
    client_ip = get_client_ip(request)
    
    # ========== INITIATE TRANSFER (SENDER) ==========
    if action == 'initiate' and request.user == transfer.from_employee and transfer.status in ['approved_mgr', 'approved_sa']:
        transfer.status = 'in_transit'
        transfer.transfer_date = timezone.now().date()
        transfer.manager_notes = notes or transfer.manager_notes
        transfer.save()
        
        for item in transfer.transfer_items.all():
            item.status = 'in_transit'
            item.transfer_date = timezone.now().date()
            item.from_branch = transfer.from_branch
            item.to_branch = transfer.to_branch
            item.is_cross_branch = transfer.is_cross_branch
            item.save()
            item.hardware.status = 'maintenance'
            item.hardware.save()
        
        TransferHistory.objects.create(
            transfer=transfer,
            action="Transfer Initiated",
            status='in_transit',
            notes=f"Transfer initiated by {request.user.get_full_name()}. Notes: {notes}",
            updated_by=request.user,
            is_cross_branch=transfer.is_cross_branch
        )
        
        TransferNotification.objects.create(
            transfer=transfer,
            recipient=transfer.to_employee,
            message=f"Transfer #{transfer.transfer_id} has been initiated by {transfer.from_employee.get_full_name() or transfer.from_employee.username}. Hardware is in transit.",
            notification_type='in_transit',
            is_cross_branch=transfer.is_cross_branch
        )
        
        create_audit_log(
            request=request,
            user=request.user,
            action="transfer_initiate",
            module="Hardware Transfer",
            description=f"Employee {request.user.username} initiated transfer #{transfer.transfer_id}",
            target_user=transfer.to_employee,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer.id,
            old_value={'status': 'approved_mgr' if not transfer.is_cross_branch else 'approved_sa'},
            new_value={'status': 'in_transit', 'initiated_by': request.user.username, 'ip': client_ip}
        )
        
        messages.success(
            request, 
            f'✅ Transfer initiated! Hardware is now in transit to {transfer.to_employee.get_full_name() or transfer.to_employee.username}.'
        )
        # ✅ FIXED: Redirect uses transfer.transfer_id (UUID)
        return redirect('transfer_tracking', transfer_id=transfer.transfer_id)
    
    # ========== ✅ RECEIVE AND COMPLETE TRANSFER (RECEIVER) - AUTO UPDATE ==========
    elif action in ['receive', 'receive_and_complete'] and request.user == transfer.to_employee and transfer.status == 'in_transit':
        transferred_count = 0
        transferred_items = []
        updated_hardware_ids = []
        
        for item in transfer.transfer_items.all():
            item.status = 'received'
            item.received_date = timezone.now().date()
            item.condition_after = notes
            item.to_branch = transfer.to_branch
            item.is_cross_branch = transfer.is_cross_branch
            item.save()
            
            # ========== REMOVE HARDWARE FROM SENDER ==========
            sender_item = HardwareAssignmentItem.objects.filter(
                hardware=item.hardware,
                assignment__employee=transfer.from_employee,
                assignment__actual_return_date__isnull=True
            ).first()
            
            if sender_item:
                sender_assignment = sender_item.assignment
                sender_item.delete()
                
                remaining_items = HardwareAssignmentItem.objects.filter(
                    assignment=sender_assignment
                ).count()
                
                if remaining_items == 0:
                    sender_assignment.actual_return_date = timezone.now().date()
                    sender_assignment.save()
            
            # ========== ADD HARDWARE TO RECEIVER ==========
            project = transfer.to_project
            
            if not project:
                existing_receiver_assignment = HardwareAssignment.objects.filter(
                    employee=transfer.to_employee,
                    actual_return_date__isnull=True
                ).first()
                
                if existing_receiver_assignment:
                    project = existing_receiver_assignment.project
                else:
                    manager = request.user.manager
                    project = Project.objects.filter(
                        Q(created_by=manager) | Q(assigned_manager=manager)
                    ).first()
                    
                    if not project:
                        project = Project.objects.create(
                            project_id=f"TEMP_TRANSFER_{timezone.now().strftime('%Y%m%d%H%M%S')}",
                            project_name=f"Transfer Project - {transfer.to_employee.username}",
                            location=transfer.to_exam_city or 'Unknown',
                            start_date=timezone.now().date(),
                            end_date=timezone.now().date() + timedelta(days=365),
                            created_by=manager
                        )
            
            receiver_assignment = HardwareAssignment.objects.filter(
                employee=transfer.to_employee,
                project=project,
                actual_return_date__isnull=True
            ).first()
            
            if not receiver_assignment:
                if transfer.transfer_type == 'temporary' and transfer.expected_return_date:
                    expected_return_date = transfer.expected_return_date
                else:
                    expected_return_date = timezone.now().date() + timedelta(days=365 * 10)
                
                # ✅ FIXED: Use correct field names, assigned_by cannot be null
                assigned_by = transfer.approved_by or request.user.manager or request.user
                
                receiver_assignment = HardwareAssignment.objects.create(
                    employee=transfer.to_employee,
                    project=project,
                    exam_city=transfer.to_exam_city or transfer.from_exam_city,
                    exam_center_name=transfer.to_exam_center or '',
                    assigned_by=assigned_by,
                    expected_return_date=expected_return_date,
                    notes=f"Hardware transferred via Transfer ID: {transfer.transfer_id}"
                )
            
            existing_item = HardwareAssignmentItem.objects.filter(
                assignment=receiver_assignment,
                hardware=item.hardware
            ).first()
            
            if existing_item:
                existing_item.quantity += 1
                existing_item.condition_at_assignment = notes
                existing_item.save()
            else:
                HardwareAssignmentItem.objects.create(
                    assignment=receiver_assignment,
                    hardware=item.hardware,
                    quantity=1,
                    condition_at_assignment=notes
                )
            
            # ========== TRANSFER ASSET ENTRY ==========
            if sender_item:
                try:
                    sender_asset_entry = HardwareAssetEntry.objects.get(hardware_item=sender_item)
                    receiver_item = HardwareAssignmentItem.objects.filter(
                        assignment=receiver_assignment,
                        hardware=item.hardware
                    ).first()
                    
                    if receiver_item and not hasattr(receiver_item, 'asset_entry'):
                        HardwareAssetEntry.objects.create(
                            hardware_item=receiver_item,
                            entered_asset_number=sender_asset_entry.entered_asset_number,
                            entered_by=sender_asset_entry.entered_by,
                            entered_at=sender_asset_entry.entered_at,
                            verified=sender_asset_entry.verified,
                            verified_by=sender_asset_entry.verified_by,
                            verified_at=sender_asset_entry.verified_at
                        )
                except HardwareAssetEntry.DoesNotExist:
                    pass
            
            # ========== ✅ AUTO-UPDATE HARDWARE BRANCH LOCATION ==========
            old_branch = item.hardware.branch_location or 'Not Assigned'
            
            # Update hardware status
            item.hardware.status = 'in_use'
            
            # ✅ Update branch location to receiver's branch
            item.hardware.branch_location = transfer.to_branch
            
            # ✅ FORCE SAVE - Use save(update_fields) to be explicit
            item.hardware.save(update_fields=['status', 'branch_location', 'updated_at'])
            
            # Store the hardware ID for verification
            updated_hardware_ids.append(item.hardware.id)
            
            transferred_count += 1
            transferred_items.append({
                'hardware_type': item.hardware.hardware_type.name,
                'serial_number': item.hardware.serial_number,
                'asset_number': item.hardware.asset_number,
                'old_branch': old_branch,
                'new_branch': transfer.to_branch,
                'hardware_id': item.hardware.id,
                'branch_updated': old_branch != transfer.to_branch
            })
        
        # ========== VERIFY THE UPDATE WORKED ==========
        verification_results = []
        for hw_id in updated_hardware_ids:
            try:
                hw = Hardware.objects.get(id=hw_id)
                is_updated = hw.branch_location == transfer.to_branch
                verification_results.append({
                    'hardware_id': hw_id,
                    'asset': hw.asset_number,
                    'current_branch': hw.branch_location,
                    'expected_branch': transfer.to_branch,
                    'is_updated': is_updated
                })
                if not is_updated:
                    # Force update again if it didn't stick
                    hw.branch_location = transfer.to_branch
                    hw.save(update_fields=['branch_location', 'updated_at'])
            except Hardware.DoesNotExist:
                pass
        
        # ========== MARK TRANSFER AS COMPLETED ==========
        transfer.status = 'completed'
        transfer.actual_arrival_date = timezone.now().date()
        transfer.completion_notes = notes
        transfer.save()
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="transfer_complete",
            module="Hardware Transfer",
            description=f"Employee {request.user.username} completed transfer #{transfer.transfer_id} - {transferred_count} item(s) received in {transfer.to_branch} branch. Branch auto-updated from {transfer.from_branch} to {transfer.to_branch}.",
            target_user=transfer.from_employee,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer.id,
            old_value={
                'transfer_id': transfer.transfer_id,
                'status': 'in_transit',
                'from_employee': transfer.from_employee.username,
                'to_employee': transfer.to_employee.username,
                'from_branch': transfer.from_branch,
                'to_branch': transfer.to_branch
            },
            new_value={
                'status': 'completed',
                'items_received': transferred_count,
                'received_by': request.user.username,
                'received_date': timezone.now().isoformat(),
                'ip': client_ip,
                'items': transferred_items,
                'hardware_moved_to_branch': transfer.to_branch,
                'hardware_ids_updated': updated_hardware_ids,
                'verification_results': verification_results
            }
        )
        
        # ========== CREATE NOTIFICATION ==========
        TransferNotification.objects.create(
            transfer=transfer,
            recipient=transfer.from_employee,
            message=f"Transfer #{transfer.transfer_id} has been completed. Hardware has been transferred to {transfer.to_employee.get_full_name() or transfer.to_employee.username} in **{transfer.to_branch}** branch. Hardware branch location has been auto-updated."
        )
        
        messages.success(
            request, 
            f'✅ {transferred_count} hardware item(s) received and transfer completed! '
            f'Hardware branch location auto-updated from "{transfer.from_branch}" to "{transfer.to_branch}".'
        )
        # ✅ FIXED: Redirect uses transfer.transfer_id (UUID)
        return redirect('transfer_tracking', transfer_id=transfer.transfer_id)
    
    # ========== RETURN HARDWARE (TEMPORARY TRANSFER) ==========
    elif action == 'return' and request.user == transfer.to_employee and transfer.transfer_type == 'temporary' and transfer.status == 'completed':
        returned_count = 0
        returned_items = []
        
        for item in transfer.transfer_items.all():
            item.status = 'returned'
            item.return_date = timezone.now().date()
            item.save()
            
            # ========== REMOVE HARDWARE FROM RECEIVER ==========
            receiver_item = HardwareAssignmentItem.objects.filter(
                hardware=item.hardware,
                assignment__employee=transfer.to_employee,
                assignment__actual_return_date__isnull=True
            ).first()
            
            if receiver_item:
                receiver_assignment = receiver_item.assignment
                receiver_item.delete()
                
                if not HardwareAssignmentItem.objects.filter(assignment=receiver_assignment).exists():
                    receiver_assignment.actual_return_date = timezone.now().date()
                    receiver_assignment.save()
            
            # ========== RETURN HARDWARE TO SENDER ==========
            project = transfer.from_project or transfer.to_project
            
            if not project:
                existing_sender_assignment = HardwareAssignment.objects.filter(
                    employee=transfer.from_employee,
                    actual_return_date__isnull=True
                ).first()
                
                if existing_sender_assignment:
                    project = existing_sender_assignment.project
                else:
                    manager = request.user.manager
                    project = Project.objects.filter(
                        Q(created_by=manager) | Q(assigned_manager=manager)
                    ).first()
                    
                    if not project:
                        project = Project.objects.create(
                            project_id=f"TEMP_RETURN_{timezone.now().strftime('%Y%m%d%H%M%S')}",
                            project_name=f"Return Project - {transfer.from_employee.username}",
                            location=transfer.to_exam_city or 'Unknown',
                            start_date=timezone.now().date(),
                            end_date=timezone.now().date() + timedelta(days=365),
                            created_by=manager
                        )
            
            sender_assignment = HardwareAssignment.objects.filter(
                employee=transfer.from_employee,
                project=project,
                actual_return_date__isnull=True
            ).first()
            
            if not sender_assignment:
                expected_return_date = timezone.now().date() + timedelta(days=30)
                
                # ✅ FIXED: assigned_by cannot be null
                assigned_by = request.user.manager or request.user
                
                sender_assignment = HardwareAssignment.objects.create(
                    employee=transfer.from_employee,
                    project=project,
                    exam_city=transfer.from_exam_city or transfer.to_exam_city,
                    exam_center_name=transfer.to_exam_center or '',
                    assigned_by=assigned_by,
                    expected_return_date=expected_return_date,
                    notes=f"Hardware returned from {transfer.to_employee.get_full_name() or transfer.to_employee.username} - Transfer ID: {transfer.transfer_id}"
                )
            
            existing_item = HardwareAssignmentItem.objects.filter(
                assignment=sender_assignment,
                hardware=item.hardware
            ).first()
            
            if existing_item:
                existing_item.quantity += 1
                existing_item.save()
            else:
                HardwareAssignmentItem.objects.create(
                    assignment=sender_assignment,
                    hardware=item.hardware,
                    quantity=1
                )
            
            # ========== TRANSFER ASSET ENTRY BACK ==========
            if receiver_item:
                try:
                    receiver_asset_entry = HardwareAssetEntry.objects.get(hardware_item=receiver_item)
                    sender_item_obj = HardwareAssignmentItem.objects.filter(
                        assignment=sender_assignment,
                        hardware=item.hardware
                    ).first()
                    
                    if sender_item_obj and not hasattr(sender_item_obj, 'asset_entry'):
                        HardwareAssetEntry.objects.create(
                            hardware_item=sender_item_obj,
                            entered_asset_number=receiver_asset_entry.entered_asset_number,
                            entered_by=receiver_asset_entry.entered_by,
                            entered_at=receiver_asset_entry.entered_at,
                            verified=receiver_asset_entry.verified,
                            verified_by=receiver_asset_entry.verified_by,
                            verified_at=receiver_asset_entry.verified_at
                        )
                except HardwareAssetEntry.DoesNotExist:
                    pass
            
            # ========== ✅ HARDWARE STAYS IN RECEIVER'S BRANCH ==========
            item.hardware.status = 'in_use'
            item.hardware.branch_location = transfer.to_branch
            item.hardware.save(update_fields=['status', 'branch_location', 'updated_at'])
            
            returned_count += 1
            returned_items.append({
                'hardware_type': item.hardware.hardware_type.name,
                'serial_number': item.hardware.serial_number,
                'asset_number': item.hardware.asset_number,
                'branch': transfer.to_branch
            })
        
        # ========== MARK TRANSFER AS RETURNED ==========
        transfer.status = 'return_completed'
        transfer.return_date = timezone.now().date()
        transfer.completion_notes = notes
        transfer.save()
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="transfer_return",
            module="Hardware Transfer",
            description=f"Employee {request.user.username} returned {returned_count} item(s) for transfer #{transfer.transfer_id}. Hardware remains in {transfer.to_branch} branch",
            target_user=transfer.from_employee,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer.id,
            old_value={
                'transfer_id': transfer.transfer_id,
                'status': 'completed',
                'from_employee': transfer.from_employee.username,
                'to_employee': transfer.to_employee.username,
                'from_branch': transfer.from_branch,
                'to_branch': transfer.to_branch
            },
            new_value={
                'status': 'return_completed',
                'items_returned': returned_count,
                'returned_by': request.user.username,
                'return_date': timezone.now().isoformat(),
                'ip': client_ip,
                'items': returned_items,
                'hardware_location': transfer.to_branch
            }
        )
        
        # ========== CREATE NOTIFICATION ==========
        TransferNotification.objects.create(
            transfer=transfer,
            recipient=transfer.from_employee,
            message=f"Transfer #{transfer.transfer_id} - Hardware has been returned by {transfer.to_employee.get_full_name() or transfer.to_employee.username}. Hardware is now available in {transfer.to_branch} branch."
        )
        
        messages.success(
            request, 
            f'✅ {returned_count} hardware item(s) returned successfully! '
            f'Hardware remains in {transfer.to_branch} branch.'
        )
        # ✅ FIXED: Redirect uses transfer.transfer_id (UUID)
        return redirect('transfer_tracking', transfer_id=transfer.transfer_id)
    
    # ========== INVALID ACTION ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="system_warning",
        module="Hardware Transfer",
        description=f"Invalid transfer action '{action}' on #{transfer.transfer_id} by {request.user.username}",
        target_user=request.user,
        target_model="EmployeeHardwareTransfer",
        target_id=transfer.id,
        new_value={'action': action}
    )
    
    messages.error(request, 'Invalid action or you are not authorized for this action.')
    # ✅ FIXED: Redirect uses transfer.transfer_id (UUID)
    return redirect('transfer_tracking', transfer_id=transfer.transfer_id)
# ============================================================
# DEBUG VIEW FOR HARDWARE BRANCHES
# ============================================================

@login_required
def debug_hardware_branches(request):
    """
    Debug view to check hardware branch locations
    Super Admin only
    """
    if request.user.user_type != 'super_admin':
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    # Get all hardware with branch info
    hardware_data = Hardware.objects.all().values(
        'id', 'asset_number', 'serial_number', 'branch_location', 'status'
    ).order_by('branch_location')
    
    # Group by branch
    branch_counts = {}
    for hw in hardware_data:
        branch = hw['branch_location'] or 'Not Assigned'
        if branch not in branch_counts:
            branch_counts[branch] = {
                'total': 0,
                'available': 0,
                'assigned': 0,
                'in_use': 0,
                'maintenance': 0,
                'retired': 0
            }
        branch_counts[branch]['total'] += 1
        status = hw['status']
        if status in branch_counts[branch]:
            branch_counts[branch][status] += 1
    
    # Get cross-branch transfer issues
    mismatches = []
    completed_transfers = EmployeeHardwareTransfer.objects.filter(
        is_cross_branch=True,
        status='completed'
    ).select_related('from_employee', 'to_employee')
    
    for transfer in completed_transfers:
        for item in TransferItem.objects.filter(transfer=transfer).select_related('hardware'):
            hardware = item.hardware
            if hardware.branch_location != transfer.to_branch:
                mismatches.append({
                    'transfer_id': transfer.transfer_id,
                    'asset_number': hardware.asset_number,
                    'serial_number': hardware.serial_number,
                    'current_branch': hardware.branch_location or 'Not Assigned',
                    'expected_branch': transfer.to_branch
                })
    
    return JsonResponse({
        'total_hardware': len(hardware_data),
        'hardware_without_branch': hardware_data.filter(
            Q(branch_location__isnull=True) | Q(branch_location='')
        ).count(),
        'branch_counts': branch_counts,
        'branch_mismatches': mismatches,
        'mismatch_count': len(mismatches),
        'hardware_list': list(hardware_data[:50])
    }, status=200)

@login_required
def verify_hardware_branch_locations(request):
    """
    Super Admin tool to verify hardware branch locations
    """
    if request.user.user_type != 'super_admin':
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    from django.db.models import Count
    
    # Get all hardware with their branch locations
    hardware_by_branch = Hardware.objects.values('branch_location').annotate(
        count=Count('id')
    ).order_by('branch_location')
    
    # Get cross-branch transfers
    cross_branch_transfers = EmployeeHardwareTransfer.objects.filter(
        is_cross_branch=True,
        status='completed'
    ).select_related('from_employee', 'to_employee')
    
    transfer_details = []
    for transfer in cross_branch_transfers:
        for item in transfer.transfer_items.all():
            transfer_details.append({
                'transfer_id': transfer.transfer_id,
                'hardware': item.hardware.asset_number,
                'from_branch': transfer.from_branch,
                'to_branch': transfer.to_branch,
                'current_branch': item.hardware.branch_location,
                'status': item.status
            })
    
    return JsonResponse({
        'hardware_by_branch': list(hardware_by_branch),
        'total_hardware': Hardware.objects.count(),
        'cross_branch_transfers': transfer_details
    })

@login_required
def transfer_tracking(request, transfer_id):
    """
    Track transfer details and status for employee
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized transfer tracking access by {request.user.username}",
            target_user=request.user
        )
        return redirect('manager_dashboard')
    
    transfer = get_object_or_404(
        EmployeeHardwareTransfer,
        transfer_id=transfer_id
    )
    
    # ========== CHECK AUTHORIZATION ==========
    if request.user not in [transfer.from_employee, transfer.to_employee, request.user.manager]:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized transfer tracking access on #{transfer.transfer_id} by {request.user.username}",
            target_user=request.user,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer.id
        )
        messages.error(request, 'You are not authorized to view this transfer.')
        return redirect('my_transfers')
    
    # ========== GET TRANSFER ITEMS ==========
    transfer_items = transfer.transfer_items.all().select_related('hardware__hardware_type')
    
    total_items = transfer_items.count()
    pending_items = transfer_items.filter(status='pending').count()
    in_transit_items = transfer_items.filter(status='in_transit').count()
    received_items = transfer_items.filter(status='received').count()
    returned_items = transfer_items.filter(status='returned').count()
    
    # ========== GET HISTORY ==========
    history = []
    if hasattr(transfer, 'history'):
        history = transfer.history.all()
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="system_info",
        module="Hardware Transfer",
        description=f"Employee {request.user.username} tracked transfer #{transfer.transfer_id}",
        target_user=request.user,
        target_model="EmployeeHardwareTransfer",
        target_id=transfer.id,
        new_value={
            'transfer_id': transfer.transfer_id,
            'status': transfer.status,
            'from_employee': transfer.from_employee.username,
            'to_employee': transfer.to_employee.username,
            'total_items': total_items,
            'pending_items': pending_items,
            'in_transit_items': in_transit_items,
            'received_items': received_items,
            'returned_items': returned_items
        }
    )
    
    context = {
        'transfer': transfer,
        'transfer_items': transfer_items,
        'total_items': total_items,
        'pending_items': pending_items,
        'in_transit_items': in_transit_items,
        'received_items': received_items,
        'returned_items': returned_items,
        'history': history,
        'can_act': (request.user == transfer.from_employee or request.user == transfer.to_employee),
        'is_from_employee': request.user == transfer.from_employee,
        'is_to_employee': request.user == transfer.to_employee,
    }
    return render(request, 'employee/transfer_tracking.html', context)

# views.py - Updated Transfer Management Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q, Count
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import (
    CustomUser, HardwareAssignment, HardwareAssignmentItem, 
    HardwareAssetEntry, Hardware, Project, EmployeeHardwareTransfer,
    TransferItem, TransferHistory, TransferNotification
)


# ============================================================
# MANAGER TRANSFER REQUESTS
# ============================================================

@login_required
def manager_transfer_requests(request):
    """
    Manager views all transfer requests (both same-branch and cross-branch)
    Cross-branch transfers are visible but require Super Admin approval
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized access to transfer requests by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET TRANSFERS - Show both same and cross branch ==========
    transfers = EmployeeHardwareTransfer.objects.filter(
        Q(from_employee__manager=request.user) |
        Q(to_employee__manager=request.user)
    ).order_by('-requested_date')
    
    # ========== APPLY FILTERS ==========
    status_filter = request.GET.get('status', '')
    if status_filter:
        transfers = transfers.filter(status=status_filter)
    
    # ========== CALCULATE STATISTICS ==========
    total = transfers.count()
    pending = transfers.filter(status='requested').count()
    approved = transfers.filter(status='approved_by_manager').count()
    in_transit = transfers.filter(status='in_transit').count()
    received = transfers.filter(status='received_by_receiver').count()
    completed = transfers.filter(status='completed').count()
    rejected = transfers.filter(status='rejected').count()
    returned = transfers.filter(status='return_completed').count()
    
    # ========== ENRICH TRANSFER DATA ==========
    enriched_transfers = []
    
    for transfer in transfers:
        transfer_items = transfer.transfer_items.all()
        total_count = transfer_items.count()
        received_count = transfer_items.filter(status='received').count()
        pending_count = transfer_items.filter(status='pending').count()
        in_transit_count = transfer_items.filter(status='in_transit').count()
        returned_count = transfer_items.filter(status='returned').count()
        
        receiver_current_assignment = HardwareAssignment.objects.filter(
            employee=transfer.to_employee,
            actual_return_date__isnull=True
        ).first()
        
        receiver_current_city = receiver_current_assignment.exam_city if receiver_current_assignment else 'Not Assigned'
        receiver_current_exam_center = getattr(receiver_current_assignment, 'exam_center_name', None) if receiver_current_assignment else None
        
        # Check if this manager can approve (only same-branch where they are the manager)
        can_approve = (
            transfer.status == 'requested' and 
            not transfer.is_cross_branch and 
            transfer.from_employee.manager == request.user
        )
        can_reject = can_approve
        
        transfer_data = {
            'transfer': transfer,
            'total_items': total_count,
            'received_items': received_count,
            'pending_items': pending_count,
            'in_transit_items': in_transit_count,
            'returned_items': returned_count,
            'all_received': received_count == total_count and total_count > 0,
            'receiver_current_city': receiver_current_city,
            'receiver_current_exam_center': receiver_current_exam_center,
            'can_approve': can_approve,
            'can_reject': can_reject,
            'is_cross_branch': transfer.is_cross_branch,
            'is_manager_of_from': transfer.from_employee.manager == request.user,
            'is_manager_of_to': transfer.to_employee.manager == request.user,
        }
        enriched_transfers.append(transfer_data)
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_transfer_requests_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Hardware Transfer",
            description=f"Manager {request.user.username} viewed transfer requests ({total} total, {pending} pending)",
            target_user=request.user,
            new_value={
                'total': total,
                'pending': pending,
                'approved': approved,
                'in_transit': in_transit,
                'received': received,
                'completed': completed,
                'rejected': rejected,
                'returned': returned,
                'filter': status_filter or 'all'
            }
        )
        request.session['last_transfer_requests_view'] = timezone.now().timestamp()
    
    context = {
        'enriched_transfers': enriched_transfers,
        'total': total,
        'pending': pending,
        'approved': approved,
        'in_transit': in_transit,
        'received': received,
        'returned': returned,
        'completed': completed,
        'rejected': rejected,
        'status_filter': status_filter,
        'show_cross_branch_notice': True,
    }
    return render(request, 'manager/transfer_requests.html', context)

# ============================================================
# APPROVE TRANSFER REQUEST
# ============================================================

@login_required
def approve_transfer_request(request, transfer_id):
    """
    Manager approves transfer request - Directly sets to in_transit
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized transfer approval attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET TRANSFER ==========
    try:
        transfer = EmployeeHardwareTransfer.objects.get(
            id=transfer_id,
            from_employee__manager=request.user
        )
    except EmployeeHardwareTransfer.DoesNotExist:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Transfer approval failed - Transfer {transfer_id} not found for manager {request.user.username}",
            target_user=request.user,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer_id
        )
        messages.error(request, 'Transfer request not found or you are not authorized to manage it.')
        return redirect('manager_transfer_requests')
    
    # ========== CHECK STATUS ==========
    if transfer.status != 'requested':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Transfer approval failed - Transfer {transfer.transfer_id} is already {transfer.get_status_display()}",
            target_user=request.user,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer.id,
            old_value=transfer.status
        )
        messages.error(request, f'This transfer request is already {transfer.get_status_display()}.')
        return redirect('manager_transfer_requests')
    
    if request.method == 'POST':
        manager_notes = request.POST.get('manager_notes', '').strip()
        client_ip = get_client_ip(request)
        
        # ========== UPDATE TRANSFER ==========
        transfer.status = 'in_transit'
        transfer.approved_by = request.user
        transfer.approved_date = timezone.now()
        transfer.transfer_date = timezone.now().date()
        transfer.manager_notes = manager_notes
        transfer.save()
        
        # Update transfer items
        item_count = 0
        for item in transfer.transfer_items.all():
            item.status = 'in_transit'
            item.transfer_date = timezone.now().date()
            item.save()
            item.hardware.status = 'maintenance'
            item.hardware.save()
            item_count += 1
        
        # Create history entry
        TransferHistory.objects.create(
            transfer=transfer,
            action="Transfer Approved",
            status='in_transit',
            notes=f"Approved by {request.user.get_full_name()}. Transfer initiated automatically. Notes: {manager_notes}",
            updated_by=request.user
        )
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="transfer_approve",
            module="Hardware Transfer",
            description=f"Manager {request.user.username} approved transfer #{transfer.transfer_id} - {item_count} item(s) in transit",
            target_user=transfer.from_employee,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer.id,
            old_value={
                'transfer_id': transfer.transfer_id,
                'status': 'requested',
                'from_employee': transfer.from_employee.username,
                'to_employee': transfer.to_employee.username,
                'item_count': item_count
            },
            new_value={
                'status': 'in_transit',
                'approved_by': request.user.username,
                'approved_date': timezone.now().isoformat(),
                'transfer_date': transfer.transfer_date.isoformat(),
                'notes': manager_notes,
                'ip': client_ip
            }
        )
        
        # ========== CREATE NOTIFICATIONS ==========
        TransferNotification.objects.create(
            transfer=transfer,
            recipient=transfer.to_employee,
            message=f"Transfer request #{transfer.transfer_id} has been approved and is IN TRANSIT. Please prepare to receive the hardware."
        )
        
        TransferNotification.objects.create(
            transfer=transfer,
            recipient=transfer.from_employee,
            message=f"Your transfer request #{transfer.transfer_id} has been approved and is IN TRANSIT."
        )
        
        messages.success(request, f'✅ Transfer #{transfer.transfer_id} approved and marked as IN TRANSIT!')
        return redirect('manager_transfer_requests')
    
    # ========== GET REQUEST ==========
    context = {'transfer': transfer}
    return render(request, 'manager/approve_transfer.html', context)


# ============================================================
# REJECT TRANSFER REQUEST
# ============================================================

@login_required
def reject_transfer_request(request, transfer_id):
    """
    Manager rejects transfer request
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized transfer rejection attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET TRANSFER ==========
    try:
        transfer = EmployeeHardwareTransfer.objects.get(
            id=transfer_id,
            from_employee__manager=request.user
        )
    except EmployeeHardwareTransfer.DoesNotExist:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Transfer rejection failed - Transfer {transfer_id} not found for manager {request.user.username}",
            target_user=request.user,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer_id
        )
        messages.error(request, 'Transfer request not found or you are not authorized to manage it.')
        return redirect('manager_transfer_requests')
    
    # ========== CHECK STATUS ==========
    if transfer.status != 'requested':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Transfer rejection failed - Transfer {transfer.transfer_id} is already {transfer.get_status_display()}",
            target_user=request.user,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer.id,
            old_value=transfer.status
        )
        messages.error(request, f'This transfer request is already {transfer.get_status_display()}.')
        return redirect('manager_transfer_requests')
    
    if request.method == 'POST':
        rejection_reason = request.POST.get('rejection_reason', '').strip()
        client_ip = get_client_ip(request)
        
        # ========== UPDATE TRANSFER ==========
        transfer.status = 'rejected'
        transfer.manager_notes = rejection_reason
        transfer.save()
        
        # Create history entry
        TransferHistory.objects.create(
            transfer=transfer,
            action="Transfer Rejected",
            status='rejected',
            notes=f"Rejected by {request.user.get_full_name()}. Reason: {rejection_reason or 'No reason provided'}",
            updated_by=request.user
        )
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="transfer_reject",
            module="Hardware Transfer",
            description=f"Manager {request.user.username} rejected transfer #{transfer.transfer_id}",
            target_user=transfer.from_employee,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer.id,
            old_value={
                'transfer_id': transfer.transfer_id,
                'status': 'requested',
                'from_employee': transfer.from_employee.username,
                'to_employee': transfer.to_employee.username
            },
            new_value={
                'status': 'rejected',
                'rejected_by': request.user.username,
                'rejection_date': timezone.now().isoformat(),
                'reason': rejection_reason,
                'ip': client_ip
            }
        )
        
        # ========== CREATE NOTIFICATION ==========
        TransferNotification.objects.create(
            transfer=transfer,
            recipient=transfer.from_employee,
            message=f"Your transfer request #{transfer.transfer_id} has been rejected. Reason: {rejection_reason or 'No reason provided'}"
        )
        
        messages.warning(request, f'❌ Transfer #{transfer.transfer_id} rejected successfully.')
        return redirect('manager_transfer_requests')
    
    # ========== GET REQUEST ==========
    context = {'transfer': transfer}
    return render(request, 'manager/reject_transfer.html', context)


# ============================================================
# TRANSFER DETAILS (MANAGER)
# ============================================================
@login_required
def transfer_details(request, transfer_id):
    """
    View transfer details for manager
    Can view transfers where:
    - Manager is the manager of the from_employee (same branch)
    - OR Manager is the manager of the to_employee (cross-branch)
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'manager':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized transfer details access by {request.user.username}",
            target_user=request.user
        )
        return redirect('employee_dashboard')
    
    # ========== GET TRANSFER - Allow managers to view both sides ==========
    try:
        transfer = EmployeeHardwareTransfer.objects.get(
            transfer_id=transfer_id
        )
        
        # Check if this manager is authorized (either from or to employee's manager)
        is_authorized = (
            transfer.from_employee.manager == request.user or
            transfer.to_employee.manager == request.user
        )
        
        if not is_authorized:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Transfer",
                description=f"Transfer details access denied - Transfer {transfer_id} not authorized for manager {request.user.username}",
                target_user=request.user,
                target_model="EmployeeHardwareTransfer",
                target_id=transfer_id
            )
            messages.error(request, 'You are not authorized to view this transfer.')
            return redirect('manager_transfer_requests')
            
    except EmployeeHardwareTransfer.DoesNotExist:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Transfer details access failed - Transfer {transfer_id} not found",
            target_user=request.user,
            target_model="EmployeeHardwareTransfer",
            target_id=transfer_id
        )
        messages.error(request, 'Transfer request not found.')
        return redirect('manager_transfer_requests')
    
    # ========== GET TRANSFER ITEMS ==========
    transfer_items = transfer.transfer_items.all().select_related('hardware__hardware_type')
    
    hardware_details = []
    for item in transfer_items:
        asset_entry = None
        # Check if hardware is currently with receiver or sender
        assignment_item = HardwareAssignmentItem.objects.filter(
            hardware=item.hardware,
            assignment__actual_return_date__isnull=True
        ).first()
        
        if assignment_item:
            try:
                asset_entry = HardwareAssetEntry.objects.get(hardware_item=assignment_item)
            except HardwareAssetEntry.DoesNotExist:
                pass
        
        hardware_details.append({
            'item': item,
            'has_asset_entry': asset_entry is not None,
            'asset_entry': asset_entry
        })
    
    total_items = transfer_items.count()
    pending_items = transfer_items.filter(status='pending').count()
    in_transit_items = transfer_items.filter(status='in_transit').count()
    received_items = transfer_items.filter(status='received').count()
    returned_items = transfer_items.filter(status='returned').count()
    
    history = []
    if hasattr(transfer, 'history'):
        history = transfer.history.all()
    
    receiver_current_assignment = HardwareAssignment.objects.filter(
        employee=transfer.to_employee,
        actual_return_date__isnull=True
    ).first()
    
    sender_current_assignment = HardwareAssignment.objects.filter(
        employee=transfer.from_employee,
        actual_return_date__isnull=True
    ).first()
    
    # ========== CHECK IF MANAGER CAN APPROVE ==========
    # Manager can only approve same-branch transfers where they are the manager
    can_approve = (
        transfer.status == 'requested' and 
        not transfer.is_cross_branch and 
        transfer.from_employee.manager == request.user
    )
    can_reject = can_approve  # Same conditions for reject
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="system_info",
        module="Hardware Transfer",
        description=f"Manager {request.user.username} viewed transfer details #{transfer.transfer_id}",
        target_user=request.user,
        target_model="EmployeeHardwareTransfer",
        target_id=transfer.id,
        new_value={
            'transfer_id': transfer.transfer_id,
            'status': transfer.status,
            'from_employee': transfer.from_employee.username,
            'to_employee': transfer.to_employee.username,
            'total_items': total_items,
            'pending_items': pending_items,
            'in_transit_items': in_transit_items,
            'received_items': received_items,
            'returned_items': returned_items,
            'is_cross_branch': transfer.is_cross_branch,
            'can_approve': can_approve
        }
    )
    
    context = {
        'transfer': transfer,
        'transfer_items': transfer_items,
        'hardware_details': hardware_details,
        'total_items': total_items,
        'pending_items': pending_items,
        'in_transit_items': in_transit_items,
        'received_items': received_items,
        'returned_items': returned_items,
        'history': history,
        'receiver_current_city': receiver_current_assignment.exam_city if receiver_current_assignment else 'Not Assigned',
        'receiver_current_exam_center': getattr(receiver_current_assignment, 'exam_center_name', None) if receiver_current_assignment else None,
        'sender_current_city': sender_current_assignment.exam_city if sender_current_assignment else 'Not Assigned',
        'can_approve': can_approve,
        'can_reject': can_reject,
        'is_cross_branch': transfer.is_cross_branch,
        'is_manager_of_from': transfer.from_employee.manager == request.user,
        'is_manager_of_to': transfer.to_employee.manager == request.user,
    }
    return render(request, 'manager/transfer_details.html', context)

# ============================================================
# MY TRANSFERS (EMPLOYEE)
# ============================================================

@login_required
def my_transfers(request):
    """
    Employee views their transfers (sent and received)
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'employee':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Transfer",
            description=f"Unauthorized my transfers access by {request.user.username}",
            target_user=request.user
        )
        return redirect('manager_dashboard')
    
    # ========== GET TRANSFERS ==========
    sent_transfers = EmployeeHardwareTransfer.objects.filter(
        from_employee=request.user
    ).order_by('-requested_date')
    
    received_transfers = EmployeeHardwareTransfer.objects.filter(
        to_employee=request.user
    ).order_by('-requested_date')
    
    pending_sent = sent_transfers.filter(status='requested').count()
    pending_received = received_transfers.filter(status='in_transit').count()
    
    total_sent = sent_transfers.count()
    total_received = received_transfers.count()
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_my_transfers_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Hardware Transfer",
            description=f"Employee {request.user.username} viewed transfers ({total_sent} sent, {total_received} received)",
            target_user=request.user,
            new_value={
                'total_sent': total_sent,
                'total_received': total_received,
                'pending_sent': pending_sent,
                'pending_received': pending_received
            }
        )
        request.session['last_my_transfers_view'] = timezone.now().timestamp()
    
    context = {
        'sent_transfers': sent_transfers,
        'received_transfers': received_transfers,
        'pending_sent': pending_sent,
        'pending_received': pending_received,
    }
    return render(request, 'employee/my_transfers.html', context)



import json
import time
from datetime import datetime, timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.db.models import Q, Count, Sum
from .models import (
    Hardware, HardwareType, HardwareAssignment, HardwareAssignmentItem, 
    HardwareSerialEntry, CustomUser, Project, EmployeeHardwareTransfer, TransferItem
)


@login_required
def chatbot_view(request):
    """Chatbot interface for hardware tracking"""
    if request.user.user_type != 'manager':
        return redirect('employee_dashboard')
    
    from .models import ChatbotConversation
    
    conversations = ChatbotConversation.objects.filter(
        user=request.user
    )[:20]
    
    total_hardware = Hardware.objects.filter(created_by=request.user).count()
    active_assignments = HardwareAssignment.objects.filter(
        assigned_by=request.user,
        actual_return_date__isnull=True
    ).count()
    
    verified_items = HardwareSerialEntry.objects.filter(
        assignment_item__assignment__assigned_by=request.user,
        verified=True
    ).count()
    
    overdue_items = HardwareAssignment.objects.filter(
        assigned_by=request.user,
        actual_return_date__isnull=True,
        expected_return_date__lt=timezone.now().date()
    ).count()
    
    employee_count = CustomUser.objects.filter(
        user_type='employee',
        manager=request.user
    ).count()
    
    pending_transfers = EmployeeHardwareTransfer.objects.filter(
        from_employee__manager=request.user,
        status='requested'
    ).count()
    
    in_transit_transfers = EmployeeHardwareTransfer.objects.filter(
        from_employee__manager=request.user,
        status='in_transit'
    ).count()
    
    context = {
        'conversations': conversations,
        'total_hardware': total_hardware,
        'active_assignments': active_assignments,
        'verified_items': verified_items,
        'overdue_items': overdue_items,
        'employee_count': employee_count,
        'pending_transfers': pending_transfers,
        'in_transit_transfers': in_transit_transfers,
    }
    return render(request, 'manager/chatbot.html', context)


@login_required
@csrf_exempt
def chatbot_api(request):
    """Chatbot API endpoint"""
    if request.user.user_type != 'manager':
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        user_message = data.get('message', '').strip().lower()
        
        if not user_message:
            return JsonResponse({'error': 'Message is empty'}, status=400)
        
        response_data = process_chatbot_message(user_message, request.user)
        
        from .models import ChatbotConversation
        ChatbotConversation.objects.create(
            user=request.user,
            message=user_message,
            response=response_data['message'],
            intent=response_data.get('intent', 'chat')
        )
        
        return JsonResponse(response_data)
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def chatbot_stats_api(request):
    """Get real-time stats for chatbot dashboard"""
    if request.user.user_type != 'manager':
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    total_hardware = Hardware.objects.filter(created_by=request.user).count()
    active_assignments = HardwareAssignment.objects.filter(
        assigned_by=request.user,
        actual_return_date__isnull=True
    ).count()
    
    verified_items = HardwareSerialEntry.objects.filter(
        assignment_item__assignment__assigned_by=request.user,
        verified=True
    ).count()
    
    overdue_items = HardwareAssignment.objects.filter(
        assigned_by=request.user,
        actual_return_date__isnull=True,
        expected_return_date__lt=timezone.now().date()
    ).count()
    
    employee_count = CustomUser.objects.filter(
        user_type='employee',
        manager=request.user
    ).count()
    
    pending_transfers = EmployeeHardwareTransfer.objects.filter(
        from_employee__manager=request.user,
        status='requested'
    ).count()
    
    in_transit_transfers = EmployeeHardwareTransfer.objects.filter(
        from_employee__manager=request.user,
        status='in_transit'
    ).count()
    
    return JsonResponse({
        'total_hardware': total_hardware,
        'active_assignments': active_assignments,
        'verified_items': verified_items,
        'overdue_items': overdue_items,
        'employee_count': employee_count,
        'pending_transfers': pending_transfers,
        'in_transit_transfers': in_transit_transfers,
    })


def process_chatbot_message(message, user):
    """Process user message and return appropriate response"""
    
    if any(word in message for word in ['hi', 'hello', 'hey', 'greetings', 'good morning', 'good evening', 'gm', 'gd']):
        return {
            'message': f"""👋 Hello {user.get_full_name() or user.username}! I'm your Hardware Management Assistant.

I can help you track hardware, employees, assignments, and transfers.

🔍 **Try these commands:**
• "Total hardware" - See inventory summary
• "All employees" - List all employees
• "Active assignments" - View current assignments  
• "Verification status" - Check verification progress
• "Transfer status" - Check pending transfers
• "Help" - See all commands

What would you like to know today?""",
            'intent': 'greeting'
        }
    
    elif 'help' in message or 'what can you do' in message or 'commands' in message:
        return {
            'message': """🤖 **Hardware Bot Help - Available Commands**

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 **Hardware Management:**
• "Total hardware" - View inventory summary
• "Laptop status" - Check laptop availability
• "Hardware by type" - See distribution by type
• "Available hardware" - List available items

👥 **Employee Management:**
• "All employees" - List all employees
• "Active employees" - Employees with active assignments
• "Employee [name]" - Get employee details
• "Employee hardware [name]" - See employee's hardware

📋 **Assignment Tracking:**
• "Active assignments" - View current assignments
• "Overdue assignments" - List overdue returns
• "Due soon" - View assignments due in 3 days
• "Assignment by employee" - Group by employee

🔐 **Verification:**
• "Verification status" - Check verification progress
• "Pending verification" - View pending items
• "Verified items" - Count of verified hardware

🔄 **Transfer Management:**
• "Transfer status" - Check pending transfers
• "In transit transfers" - Hardware being transferred
• "Completed transfers" - Completed transfers

💡 **Tip:** Be specific with your questions for best results!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━""",
            'intent': 'help'
        }
    
    # ============ HARDWARE STATISTICS ============
    elif 'total hardware' in message or 'hardware count' in message or 'inventory summary' in message:
        total = Hardware.objects.filter(created_by=user).count()
        available = Hardware.objects.filter(created_by=user, status='available').count()
        assigned = Hardware.objects.filter(created_by=user, status='assigned').count()
        in_use = Hardware.objects.filter(created_by=user, status='in_use').count()
        maintenance = Hardware.objects.filter(created_by=user, status='maintenance').count()
        retired = Hardware.objects.filter(created_by=user, status='retired').count()
        
        return {
            'message': f"""📊 **Hardware Inventory Summary**

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 **Total Hardware:** {total}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Available: **{available}**
📋 Assigned: **{assigned}**
💻 In Use: **{in_use}**
🔧 Maintenance: **{maintenance}**
📦 Retired: **{retired}**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📈 **Utilization Rate:** {round(((assigned + in_use) / total * 100) if total > 0 else 0, 1)}%

Need more details? Ask for "hardware by type" or specific hardware status!""",
            'intent': 'hardware_summary'
        }
    
    elif 'hardware by type' in message or 'distribution' in message or 'type wise' in message:
        hardware_by_type = Hardware.objects.filter(
            created_by=user
        ).values('hardware_type__name').annotate(
            count=Count('id')
        ).order_by('-count')
        
        if hardware_by_type:
            response = "📊 **Hardware Distribution by Type**\n\n"
            response += "━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            for item in hardware_by_type:
                bar_length = min(20, item['count'] * 2)
                bar = "█" * bar_length + "░" * (20 - bar_length)
                response += f"• **{item['hardware_type__name']}**: {item['count']}\n"
                response += f"  {bar} {round((item['count']/hardware_by_type.aggregate(Sum('count'))['count__sum'])*100, 1)}%\n\n"
            
            total = hardware_by_type.aggregate(Sum('count'))['count__sum']
            response += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            response += f"📦 **Total:** {total} items"
        else:
            response = "No hardware data available. Please add hardware inventory first."
        
        return {'message': response, 'intent': 'hardware_by_type'}
    
    elif 'laptop' in message or 'laptops' in message:
        laptops = Hardware.objects.filter(
            created_by=user,
            hardware_type__name__icontains='laptop'
        )
        total = laptops.count()
        available = laptops.filter(status='available').count()
        assigned = laptops.filter(status='assigned').count()
        in_use = laptops.filter(status='in_use').count()
        maintenance = laptops.filter(status='maintenance').count()
        
        return {
            'message': f"""💻 **Laptops Status Report**

━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 **Total Laptops:** {total}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Available: **{available}** (Ready to assign)
📋 Assigned: **{assigned}** (Pending pickup)
💻 In Use: **{in_use}** (Currently active)
🔧 Maintenance: **{maintenance}** (Under repair)
━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 **Availability Rate:** {round((available / total * 100) if total > 0 else 0, 1)}%

Want laptop details by model? Ask for "laptop models"!""",
            'intent': 'hardware_type'
        }
    
    elif 'firewall' in message:
        firewalls = Hardware.objects.filter(
            created_by=user,
            hardware_type__name__icontains='firewall'
        )
        total = firewalls.count()
        available = firewalls.filter(status='available').count()
        assigned = firewalls.filter(status='assigned').count()
        
        return {
            'message': f"""🛡️ **Firewall Status Report**

━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 **Total Firewalls:** {total}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Available: **{available}**
📋 Assigned: **{assigned}**
🎯 Utilization: **{round(((total - available) / total * 100) if total > 0 else 0, 1)}%**
━━━━━━━━━━━━━━━━━━━━━━━━━━━

Need specific firewall details?""",
            'intent': 'hardware_type'
        }
    
    elif 'available hardware' in message or 'available items' in message:
        available_items = Hardware.objects.filter(
            created_by=user,
            status='available'
        ).select_related('hardware_type')[:20]
        
        count = available_items.count()
        
        if count > 0:
            response = f"✅ **Available Hardware ({count} items)**\n\n"
            for item in available_items:
                response += f"• **{item.hardware_type.name}** - {item.serial_number}\n"
                response += f"  {item.model_name} | {item.brand or 'No brand'}\n\n"
            if count >= 20:
                response += "Showing first 20 items. Use filters for more specific results."
        else:
            response = "✅ **No available hardware at the moment.** All hardware is either assigned or in use."
        
        return {'message': response, 'intent': 'available_hardware'}
    
    elif 'all employees' in message or 'list employees' in message or 'show employees' in message:
        employees = CustomUser.objects.filter(
            user_type='employee',
            manager=user
        ).order_by('first_name')[:15]
        
        total_employees = employees.count()
        
        if total_employees > 0:
            response = f"👥 **Employee List ({total_employees} employees)**\n\n"
            for emp in employees:
                active_count = HardwareAssignment.objects.filter(
                    employee=emp,
                    actual_return_date__isnull=True
                ).count()
                response += f"• **{emp.get_full_name() or emp.username}**\n"
                response += f"  📧 {emp.email} | 📞 {emp.phone or 'No phone'}\n"
                response += f"  💻 Active Hardware: {active_count} items\n\n"
        else:
            response = "👥 No employees found. Please create employee accounts first."
        
        return {'message': response, 'intent': 'all_employees'}
    
    elif 'active employees' in message:
        active_employees = CustomUser.objects.filter(
            user_type='employee',
            manager=user
        ).count()
        
        employees_with_assignments = CustomUser.objects.filter(
            user_type='employee',
            manager=user,
            hardware_assignments__actual_return_date__isnull=True
        ).distinct().count()
        
        response = f"""👥 **Active Employees Report**

━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 **Total Employees:** {active_employees}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ **With Active Assignments:** {employees_with_assignments}
⏳ **Idle Employees:** {active_employees - employees_with_assignments}
━━━━━━━━━━━━━━━━━━━━━━━━━━━

📈 **Activity Rate:** {round((employees_with_assignments / active_employees * 100) if active_employees > 0 else 0, 1)}%

Want to see specific employee details? Ask "Employee [name]!" """
        
        return {'message': response, 'intent': 'active_employees'}
    
    elif 'employee' in message and ('details' in message or 'info' in message or 'show' in message):
        words = message.split()
        emp_name = None
        for i, word in enumerate(words):
            if word not in ['employee', 'details', 'info', 'show', 'for', 'about']:
                emp_name = word
                break
        
        if emp_name:
            employees = CustomUser.objects.filter(
                user_type='employee',
                manager=user,
                username__icontains=emp_name
            ) | CustomUser.objects.filter(
                user_type='employee',
                manager=user,
                first_name__icontains=emp_name
            ) | CustomUser.objects.filter(
                user_type='employee',
                manager=user,
                last_name__icontains=emp_name
            )
            
            if employees.exists():
                emp = employees.first()
                
                assignments = HardwareAssignment.objects.filter(
                    employee=emp,
                    actual_return_date__isnull=True
                )
                
                hardware_count = 0
                hardware_list = []
                for assignment in assignments:
                    for item in assignment.hardwareassignmentitem_set.all():
                        hardware_count += 1
                        hardware_list.append(f"  • {item.hardware.hardware_type.name} - {item.hardware.serial_number}")
                
                completed_count = HardwareAssignment.objects.filter(
                    employee=emp,
                    actual_return_date__isnull=False
                ).count()
                
                response = f"""👤 **Employee Details: {emp.get_full_name() or emp.username}**

━━━━━━━━━━━━━━━━━━━━━━━━━━━
📧 **Email:** {emp.email}
📞 **Phone:** {emp.phone or 'Not provided'}
📅 **Joined:** {emp.date_joined.strftime('%d %b %Y')}
━━━━━━━━━━━━━━━━━━━━━━━━━━━

💻 **Current Hardware:** {hardware_count} item(s)
✅ **Completed Assignments:** {completed_count}
📊 **Status:** {'Active' if hardware_count > 0 else 'Idle'}

"""
                if hardware_list:
                    response += "\n".join(hardware_list[:5])
                    if len(hardware_list) > 5:
                        response += f"\n  ... and {len(hardware_list) - 5} more"

                response += "\n\nNeed to assign hardware? Use the assignment form!"
            else:
                response = f"❌ No employee found with name '{emp_name}'. Please check the name and try again."
        else:
            response = "Please provide an employee name. Example: 'Employee details John'"
        
        return {'message': response, 'intent': 'employee_details'}
    
    elif 'employee hardware' in message or 'hardware assigned to' in message:
        words = message.split()
        emp_name = None
        for word in words:
            if word not in ['employee', 'hardware', 'assigned', 'to', 'show', 'for', 'of']:
                emp_name = word
                break
        
        if emp_name:
            employees = CustomUser.objects.filter(
                user_type='employee',
                manager=user,
                username__icontains=emp_name
            ) | CustomUser.objects.filter(
                user_type='employee',
                manager=user,
                first_name__icontains=emp_name
            )
            
            if employees.exists():
                emp = employees.first()
                assignments = HardwareAssignment.objects.filter(
                    employee=emp,
                    actual_return_date__isnull=True
                )
                
                hardware_list = []
                for assignment in assignments:
                    for item in assignment.hardwareassignmentitem_set.all():
                        verification_status = "Not Verified"
                        try:
                            serial_entry = HardwareSerialEntry.objects.get(assignment_item=item)
                            if serial_entry.verified:
                                verification_status = "✅ Verified"
                            else:
                                verification_status = "⏳ Pending"
                        except HardwareSerialEntry.DoesNotExist:
                            verification_status = "📝 Not Entered"
                        
                        hardware_list.append({
                            'type': item.hardware.hardware_type.name,
                            'serial': item.hardware.serial_number,
                            'model': item.hardware.model_name,
                            'exam_city': assignment.exam_city,
                            'status': verification_status
                        })
                
                if hardware_list:
                    response = f"💻 **Hardware Assigned to {emp.get_full_name() or emp.username}**\n\n"
                    for hw in hardware_list:
                        response += f"• **{hw['type']}** - {hw['serial']}\n"
                        response += f"  Model: {hw['model']} | City: {hw['exam_city']}\n"
                        response += f"  Verification: {hw['status']}\n\n"
                else:
                    response = f"✅ No active hardware assigned to {emp.get_full_name() or emp.username}."
            else:
                response = f"❌ No employee found with name '{emp_name}'."
        else:
            response = "Please provide an employee name. Example: 'Employee hardware John'"
        
        return {'message': response, 'intent': 'employee_hardware'}
    
    elif 'active assignments' in message or 'current assignments' in message:
        today = timezone.now().date()
        active = HardwareAssignment.objects.filter(
            assigned_by=user,
            actual_return_date__isnull=True
        )
        
        total_active = active.count()
        overdue = active.filter(expected_return_date__lt=today).count()
        due_soon = active.filter(
            expected_return_date__gte=today,
            expected_return_date__lte=today + timedelta(days=3)
        ).count()
        
        city_stats = active.values('exam_city').annotate(count=Count('id')).order_by('-count')[:5]
        
        response = f"""📋 **Active Assignments Report**

━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 **Total Active:** {total_active}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ **Overdue:** {overdue}
⏰ **Due Soon (3 days):** {due_soon}
✅ **On Track:** {total_active - overdue - due_soon}
━━━━━━━━━━━━━━━━━━━━━━━━━━━

📍 **By Exam City:**
"""
        for city in city_stats:
            response += f"• {city['exam_city']}: {city['count']} assignments\n"
        
        response += f"\n📈 **Completion Rate:** {round(((total_active - overdue) / total_active * 100) if total_active > 0 else 100, 1)}% on track"
        
        if overdue > 0:
            response += f"\n\n⚠️ **Action Required:** {overdue} assignment(s) are overdue. Please check the assignments page."
        
        return {'message': response, 'intent': 'assignments'}
    
    elif 'overdue' in message or 'show overdue' in message:
        today = timezone.now().date()
        overdue_assignments = HardwareAssignment.objects.filter(
            assigned_by=user,
            actual_return_date__isnull=True,
            expected_return_date__lt=today
        ).select_related('employee', 'project')[:10]
        
        if overdue_assignments.exists():
            response = "⚠️ **Overdue Assignments:**\n\n"
            for assign in overdue_assignments:
                days_overdue = (today - assign.expected_return_date).days
                response += f"• **{assign.employee.get_full_name() or assign.employee.username}**\n"
                response += f"  Project: {assign.project.project_name}\n"
                response += f"  Exam City: {assign.exam_city}\n"
                response += f"  Expected: {assign.expected_return_date} ({days_overdue} days overdue)\n\n"
            if overdue_assignments.count() >= 10:
                response += "Showing first 10 results. Please check the assignments page for complete list."
            response += "\n📋 Use 'return assignment' to process returns."
        else:
            response = "✅ **No overdue assignments!** All hardware is on track."
        
        return {'message': response, 'intent': 'overdue'}
    
    elif 'due soon' in message:
        today = timezone.now().date()
        due_soon_assignments = HardwareAssignment.objects.filter(
            assigned_by=user,
            actual_return_date__isnull=True,
            expected_return_date__gte=today,
            expected_return_date__lte=today + timedelta(days=3)
        ).select_related('employee', 'project')[:10]
        
        if due_soon_assignments.exists():
            response = "⏰ **Assignments Due Soon (within 3 days):**\n\n"
            for assign in due_soon_assignments:
                days_left = (assign.expected_return_date - today).days
                response += f"• **{assign.employee.get_full_name() or assign.employee.username}**\n"
                response += f"  Project: {assign.project.project_name}\n"
                response += f"  Due: {assign.expected_return_date} ({days_left} days left)\n\n"
        else:
            response = "✅ **No assignments due soon!** All due dates are more than 3 days away."
        
        return {'message': response, 'intent': 'due_soon'}
    
    elif 'assignment by employee' in message or 'group by employee' in message:
        assignments = HardwareAssignment.objects.filter(
            assigned_by=user,
            actual_return_date__isnull=True
        ).values('employee__first_name', 'employee__last_name', 'employee__username').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        if assignments.exists():
            response = "📋 **Assignments by Employee**\n\n"
            for assign in assignments:
                name = assign.get('employee__first_name') or assign.get('employee__username')
                if assign.get('employee__last_name'):
                    name += f" {assign.get('employee__last_name')}"
                bar_length = min(20, assign['count'] * 2)
                bar = "█" * bar_length + "░" * (20 - bar_length)
                response += f"• **{name}**: {assign['count']} assignments\n"
                response += f"  {bar}\n\n"
        else:
            response = "No active assignments found."
        
        return {'message': response, 'intent': 'assignment_by_employee'}
    
    elif 'verification' in message or 'verified' in message or 'pending verification' in message:
        total_entries = HardwareSerialEntry.objects.filter(
            assignment_item__assignment__assigned_by=user
        ).count()
        
        verified_count = HardwareSerialEntry.objects.filter(
            assignment_item__assignment__assigned_by=user,
            verified=True
        ).count()
        
        pending_count = total_entries - verified_count
        
        matched = 0
        mismatch = 0
        for entry in HardwareSerialEntry.objects.filter(assignment_item__assignment__assigned_by=user, verified=False):
            if entry.serial_number == entry.assignment_item.hardware.serial_number:
                matched += 1
            else:
                mismatch += 1
        
        not_entered = HardwareAssignmentItem.objects.filter(
            assignment__assigned_by=user,
            assignment__actual_return_date__isnull=True
        ).exclude(
            id__in=HardwareSerialEntry.objects.values('assignment_item_id')
        ).count()
        
        completion_rate = round((verified_count / total_entries * 100) if total_entries > 0 else 0, 1)
        
        response = f"""🔐 **Verification Status Report**

━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 **Total Entries:** {total_entries}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ **Verified:** {verified_count}
🟦 **Matched (Pending):** {matched}
❌ **Mismatch:** {mismatch}
📝 **Not Entered:** {not_entered}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
📈 **Completion Rate:** {completion_rate}%

"""
        
        if matched > 0:
            response += f"💡 {matched} item(s) are matched and ready for verification. Use 'verify all' to approve them."
        elif mismatch > 0:
            response += f"⚠️ {mismatch} item(s) have mismatched serials. Please contact employees to correct them."
        elif not_entered > 0:
            response += f"📝 {not_entered} item(s) need serial numbers to be entered."
        
        return {'message': response, 'intent': 'verification'}
    
    # ============ TRANSFER MANAGEMENT ============
    elif 'transfer status' in message or 'pending transfers' in message:
        pending = EmployeeHardwareTransfer.objects.filter(
            from_employee__manager=user,
            status='requested'
        ).count()
        
        approved = EmployeeHardwareTransfer.objects.filter(
            from_employee__manager=user,
            status='approved_by_manager'
        ).count()
        
        in_transit = EmployeeHardwareTransfer.objects.filter(
            from_employee__manager=user,
            status='in_transit'
        ).count()
        
        completed = EmployeeHardwareTransfer.objects.filter(
            from_employee__manager=user,
            status='completed'
        ).count()
        
        rejected = EmployeeHardwareTransfer.objects.filter(
            from_employee__manager=user,
            status='rejected'
        ).count()
        
        response = f"""🔄 **Hardware Transfer Status**

━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 **Total Transfers:** {pending + approved + in_transit + completed + rejected}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
⏳ **Pending Approval:** {pending}
✅ **Approved:** {approved}
🚚 **In Transit:** {in_transit}
🎯 **Completed:** {completed}
❌ **Rejected:** {rejected}
━━━━━━━━━━━━━━━━━━━━━━━━━━━

"""
        if pending > 0:
            response += f"⚠️ {pending} transfer(s) pending your approval. Use 'transfer-requests' to review them."
        elif in_transit > 0:
            response += f"🚚 {in_transit} transfer(s) are in transit. Track them in the transfers section."
        
        return {'message': response, 'intent': 'transfer_status'}
    
    elif 'in transit transfers' in message:
        transfers = EmployeeHardwareTransfer.objects.filter(
            from_employee__manager=user,
            status='in_transit'
        ).select_related('from_employee', 'to_employee', 'hardware_item')[:10]
        
        if transfers.exists():
            response = "🚚 **In Transit Transfers:**\n\n"
            for t in transfers:
                response += f"• **{t.hardware_item.hardware_type.name}** - {t.hardware_item.serial_number}\n"
                response += f"  From: {t.from_employee.get_full_name() or t.from_employee.username} ({t.from_exam_city})\n"
                response += f"  To: {t.to_employee.get_full_name() or t.to_employee.username} ({t.to_exam_city})\n"
                response += f"  Type: {'Temporary' if t.transfer_type == 'temporary' else 'Permanent'}\n\n"
        else:
            response = "🚚 No hardware transfers are currently in transit."
        
        return {'message': response, 'intent': 'in_transit_transfers'}
    
    # ============ SEARCH HARDWARE ============
    elif 'search' in message or 'find' in message:
        import re
        # Extract search term
        search_match = re.search(r'(?:search|find)(?:\s+for)?\s+([a-zA-Z0-9-]+)', message)
        
        if search_match:
            search_term = search_match.group(1)
        else:
            words = message.split()
            for word in words:
                if len(word) > 3 and word not in ['search', 'find', 'hardware', 'for', 'show', 'me']:
                    search_term = word
                    break
        
        if search_term:
            hardware = Hardware.objects.filter(
                Q(serial_number__icontains=search_term) |
                Q(model_name__icontains=search_term) |
                Q(hardware_type__name__icontains=search_term),
                created_by=user
            )[:10]
            
            if hardware.exists():
                response = "🔍 **Search Results:**\n\n"
                for hw in hardware:
                    # Find current status/location
                    location = "Available (Not assigned)"
                    assignment_item = HardwareAssignmentItem.objects.filter(
                        hardware=hw,
                        assignment__actual_return_date__isnull=True
                    ).first()
                    
                    if assignment_item:
                        location = f"Assigned to: {assignment_item.assignment.employee.get_full_name() or assignment_item.assignment.employee.username} at {assignment_item.assignment.exam_city}"
                    
                    response += f"• **{hw.hardware_type.name}** - {hw.serial_number}\n"
                    response += f"  Model: {hw.model_name} | Brand: {hw.brand or 'N/A'}\n"
                    response += f"  Status: {hw.get_status_display()} | 📍 {location}\n\n"
            else:
                response = f"❌ No hardware found matching '{search_term}'"
        else:
            response = "Please provide a search term. Example: 'Search for laptop' or 'Find LAP-1234'"
        
        return {'message': response, 'intent': 'search'}
    
    # ============ SPECIFIC HARDWARE BY SERIAL ============
    elif re.search(r'[A-Z0-9]{4,}', message.upper()):
        import re
        serial_match = re.search(r'([A-Z0-9]{4,})', message.upper())
        
        if serial_match:
            serial_number = serial_match.group(1)
            try:
                hardware = Hardware.objects.get(serial_number__iexact=serial_number, created_by=user)
                
                # Find current assignment
                assignment_item = HardwareAssignmentItem.objects.filter(
                    hardware=hardware,
                    assignment__actual_return_date__isnull=True
                ).first()
                
                response = f"""🔍 **Hardware Details Found**

━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 **Type:** {hardware.hardware_type.name}
🔢 **Serial:** {hardware.serial_number}
📱 **Model:** {hardware.model_name}
🏷️ **Brand:** {hardware.brand or 'Not specified'}
📊 **Status:** {hardware.get_status_display()}
━━━━━━━━━━━━━━━━━━━━━━━━━━━

"""
                
                if assignment_item:
                    response += f"""👤 **Currently with:** {assignment_item.assignment.employee.get_full_name() or assignment_item.assignment.employee.username}
📍 **Location:** {assignment_item.assignment.exam_city}
📅 **Assigned Since:** {assignment_item.assignment.assigned_date.strftime('%d %b %Y')}
"""
                else:
                    response += "✅ This hardware is available for assignment."
                
                return {'message': response, 'intent': 'hardware_search'}
                
            except Hardware.DoesNotExist:
                pass
    
    # ============ DEFAULT RESPONSE ============
    else:
        return {
            'message': """🤔 I'm not sure I understand. Here's what I can help with:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 **Hardware Tracking**
• "Total hardware" - Inventory summary
• "Laptop status" - Laptop availability
• "Hardware by type" - Distribution report

👥 **Employee Tracking**
• "All employees" - List employees
• "Employee [name]" - Employee details
• "Employee hardware [name]" - Assigned hardware

📋 **Assignment Tracking**
• "Active assignments" - Current assignments
• "Overdue assignments" - Overdue items
• "Due soon" - Approaching deadlines

🔐 **Verification**
• "Verification status" - Check progress

🔄 **Transfers**
• "Transfer status" - Pending transfers

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Try one of these commands or ask "Help" for more options!""",
            'intent': 'unknown'
        }


# ============== SUPER ADMIN VIEWS ==============
# views.py - Updated Super Admin Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Count, Q
from datetime import datetime, timedelta
import json
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import (
    CustomUser, Hardware, HardwareType, Project, HardwareAssignment,
    HardwareRequest, EmployeeDeleteRequest, EmployeeUpdateRequest
)


# ============================================================
# SUPER ADMIN DASHBOARD
# ============================================================
# views.py - Updated Super Admin Dashboard with Auto Cleanup

@login_required
def super_admin_dashboard(request):
    """
    Super Admin Dashboard with full system overview and analytics
    With comprehensive audit logging and automatic log cleanup
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Super Admin Dashboard",
            description=f"Unauthorized dashboard access attempt by {request.user.username} (user_type: {request.user.user_type})",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to access the Super Admin dashboard.')
        return redirect('login')
    
    # ========== AUTO CLEANUP OLD AUDIT LOGS ==========
    # Run cleanup once a day (86400 seconds)
    if request.session.get('last_log_cleanup', 0) < timezone.now().timestamp() - 86400:
        try:
            from hardware_management.utils.audit import cleanup_old_audit_logs
            
            # Get count before deletion for logging
            cutoff_date = timezone.now() - timedelta(days=30)
            count_before = AuditLog.objects.filter(created_at__lt=cutoff_date).count()
            
            if count_before > 0:
                result = cleanup_old_audit_logs(days=30)
                
                if result['deleted_count'] > 0:
                    create_audit_log(
                        request=request,
                        user=request.user,
                        action="system_info",
                        module="Audit Logs",
                        description=f"Auto-cleanup deleted {result['deleted_count']} audit logs older than 30 days",
                        target_user=request.user,
                        new_value={
                            'deleted_count': result['deleted_count'],
                            'total_checked': result['total_count']
                        }
                    )
                    # Add a subtle message (don't distract from dashboard)
                    messages.info(request, f'🧹 Auto-cleaned {result["deleted_count"]} old audit logs.')
        except Exception as e:
            # Log error but don't break dashboard
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Auto-cleanup failed: {str(e)}")
            # Don't show error to user to avoid distraction
        
        # Update last cleanup timestamp
        request.session['last_log_cleanup'] = timezone.now().timestamp()
    
    # ========== GET SYSTEM DATA ==========
    total_employees = CustomUser.objects.filter(user_type='employee').count()
    total_managers = CustomUser.objects.filter(user_type='manager').count()
    total_hardware = Hardware.objects.count()
    total_projects = Project.objects.count()
    total_assignments = HardwareAssignment.objects.count()
    active_assignments = HardwareAssignment.objects.filter(actual_return_date__isnull=True).count()
    pending_requests = HardwareRequest.objects.filter(status='pending').count()
    
    # ========== HARDWARE STATUS ==========
    available_hardware = Hardware.objects.filter(status='available').count()
    assigned_hardware = Hardware.objects.filter(status='assigned').count()
    in_use_hardware = Hardware.objects.filter(status='in_use').count()
    maintenance_hardware = Hardware.objects.filter(status='maintenance').count()
    retired_hardware = Hardware.objects.filter(status='retired').count()
    
    total_hardware_types = HardwareType.objects.count()
    
    # ========== HARDWARE BY TYPE ==========
    hardware_by_type = {}
    for hw_type in HardwareType.objects.all():
        count = Hardware.objects.filter(hardware_type=hw_type).count()
        if count > 0:
            hardware_by_type[hw_type.name] = count
    
    # ========== MONTHLY ASSIGNMENT DATA ==========
    monthly_assignments = []
    months = []
    current_date = timezone.now().date()
    
    for i in range(5, -1, -1):
        month_date = current_date.replace(day=1) - timedelta(days=30*i)
        month_start = month_date.replace(day=1)
        if i == 0:
            month_end = current_date
        else:
            next_month = month_start.replace(day=1) + timedelta(days=32)
            month_end = next_month.replace(day=1) - timedelta(days=1)
        
        count = HardwareAssignment.objects.filter(
            assigned_date__gte=month_start,
            assigned_date__lte=month_end
        ).count()
        
        months.append(month_start.strftime('%b'))
        monthly_assignments.append(count)
    
    # ========== BRANCH DISTRIBUTION ==========
    branch_distribution = {}
    branches = CustomUser.objects.filter(
        user_type='employee'
    ).values_list('branch_location', flat=True).distinct()
    
    for branch in branches:
        if branch:
            count = CustomUser.objects.filter(
                user_type='employee',
                branch_location=branch
            ).count()
            branch_distribution[branch] = count
    
    # ========== MANAGER PERFORMANCE ==========
    manager_performance = []
    for manager in CustomUser.objects.filter(user_type='manager', is_active=True):
        assignments_count = HardwareAssignment.objects.filter(assigned_by=manager).count()
        employees_count = CustomUser.objects.filter(manager=manager).count()
        hardware_count = Hardware.objects.filter(created_by=manager).count()
        
        total_hw = Hardware.objects.filter(created_by=manager).count()
        in_use_hw = Hardware.objects.filter(created_by=manager, status='in_use').count()
        utilization = (in_use_hw / total_hw * 100) if total_hw > 0 else 0
        
        manager_performance.append({
            'name': manager.get_full_name() or manager.username,
            'branch': manager.branch_location or 'Unknown',
            'assignments': assignments_count,
            'employees': employees_count,
            'hardware': hardware_count,
            'utilization': round(utilization, 1),
        })
    
    manager_performance.sort(key=lambda x: x['assignments'], reverse=True)
    
    # ========== RECENT ACTIVITIES ==========
    recent_activities = []
    
    # Recent assignments
    recent_assignments = HardwareAssignment.objects.all().select_related(
        'employee', 'project', 'assigned_by'
    ).order_by('-assigned_date')[:10]
    
    for assignment in recent_assignments:
        recent_activities.append({
            'icon': 'clipboard-check',
            'color': 'primary',
            'title': 'New assignment created',
            'description': f'{assignment.employee.get_full_name() or assignment.employee.username} → {assignment.project.project_name}',
            'timestamp': assignment.assigned_date,
            'type': 'assignment',
            'badge': 'New',
            'branch': assignment.assigned_by.branch_location if assignment.assigned_by else 'Unknown'
        })
    
    # Recent employees
    recent_employees = CustomUser.objects.filter(
        user_type='employee'
    ).select_related('manager').order_by('-date_joined')[:10]
    
    for emp in recent_employees:
        recent_activities.append({
            'icon': 'person-plus',
            'color': 'success',
            'title': 'New employee joined',
            'description': f'{emp.get_full_name() or emp.username} - {emp.email}',
            'timestamp': emp.date_joined,
            'type': 'employee',
            'badge': 'New',
            'branch': emp.branch_location or 'Not Assigned'
        })
    
    # Recent hardware
    recent_hardware = Hardware.objects.all().select_related(
        'hardware_type', 'created_by'
    ).order_by('-created_at')[:10]
    
    for hw in recent_hardware:
        recent_activities.append({
            'icon': 'laptop',
            'color': 'info',
            'title': 'Hardware added',
            'description': f'{hw.hardware_type.name} - {hw.asset_number}',
            'timestamp': hw.created_at,
            'type': 'hardware',
            'badge': 'New',
            'branch': hw.created_by.branch_location if hw.created_by else 'Unknown'
        })
    
    recent_activities.sort(key=lambda x: x['timestamp'], reverse=True)
    recent_activities = recent_activities[:10]
    
    # ========== AUDIT LOG - DASHBOARD VIEW ==========
    if request.session.get('last_super_admin_dashboard_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Super Admin Dashboard",
            description=f"Super Admin {request.user.username} viewed dashboard",
            target_user=request.user,
            new_value={
                'total_employees': total_employees,
                'total_managers': total_managers,
                'total_hardware': total_hardware,
                'total_projects': total_projects,
                'total_assignments': total_assignments,
                'active_assignments': active_assignments,
                'pending_requests': pending_requests
            }
        )
        request.session['last_super_admin_dashboard_view'] = timezone.now().timestamp()
    
    # ========== PREPARE CONTEXT ==========
    context = {
        'total_employees': total_employees,
        'total_managers': total_managers,
        'total_hardware': total_hardware,
        'total_projects': total_projects,
        'total_assignments': total_assignments,
        'active_assignments': active_assignments,
        'pending_requests': pending_requests,
        'total_hardware_types': total_hardware_types,
        'available_hardware': available_hardware,
        'assigned_hardware': assigned_hardware,
        'in_use_hardware': in_use_hardware,
        'maintenance_hardware': maintenance_hardware,
        'retired_hardware': retired_hardware,
        'hardware_by_type': hardware_by_type,
        'hardware_by_type_json': json.dumps(hardware_by_type),
        'branch_distribution': branch_distribution,
        'branch_distribution_json': json.dumps(branch_distribution),
        'months': months,
        'months_json': json.dumps(months),
        'monthly_assignments': monthly_assignments,
        'monthly_assignments_json': json.dumps(monthly_assignments),
        'hardware_by_type_items': hardware_by_type.items(),
        'branch_distribution_items': branch_distribution.items(),
        'manager_performance': manager_performance,
        'recent_activities': recent_activities,
        'today': timezone.now().date(),
    }
    return render(request, 'super_admin/dashboard.html', context)


# ============================================================
# SUPER ADMIN CREATE MANAGER
# ============================================================
@login_required
def super_admin_create_manager(request):
    """
    Super Admin creates manager account
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.is_authenticated and request.user.user_type not in ['super_admin']:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="User Management",
            description=f"Unauthorized manager creation attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to register managers.')
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        phone = request.POST.get('phone', '').strip()
        branch_location = request.POST.get('branch_location', '').strip()
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        client_ip = get_client_ip(request)
        
        # ========== VALIDATION ==========
        validation_errors = []
        
        if not username:
            validation_errors.append('Username is required.')
        elif CustomUser.objects.filter(username=username).exists():
            validation_errors.append(f'Username "{username}" already exists.')
        
        if not email:
            validation_errors.append('Email is required.')
        elif CustomUser.objects.filter(email=email).exists():
            validation_errors.append(f'Email "{email}" already exists.')
        elif '@' not in email or '.' not in email:
            validation_errors.append('Please enter a valid email address.')
        
        if not password:
            validation_errors.append('Password is required.')
        elif len(password) < 8:
            validation_errors.append('Password must be at least 8 characters long.')
        elif password != confirm_password:
            validation_errors.append('Passwords do not match.')
        
        if validation_errors:
            for error in validation_errors:
                messages.error(request, error)
            return redirect('super_admin_create_manager')
        
        # ========== CREATE MANAGER ==========
        try:
            # ✅ FIXED: Removed 'is_first_login=False'
            user = CustomUser.objects.create_user(
                username=username,
                email=email,
                password=password,
                user_type='manager',
                phone=phone or '',
                first_name=first_name,
                last_name=last_name,
                branch_location=branch_location or 'Head Office'
            )
            
            # ========== AUDIT LOG ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="user_create",
                module="User Management",
                description=f"Super Admin {request.user.username} created manager {first_name} {last_name} ({username})",
                target_user=user,
                target_model="User",
                target_id=user.id,
                new_value={
                    'username': username,
                    'email': email,
                    'first_name': first_name,
                    'last_name': last_name,
                    'branch': branch_location or 'Head Office',
                    'phone': phone,
                    'ip': client_ip
                }
            )
            
            messages.success(request, f'✅ Manager account created successfully for {first_name} {last_name}!')
            
            if request.user.is_authenticated and request.user.user_type == 'super_admin':
                return redirect('super_admin_managers')
            else:
                return redirect('login')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="User Management",
                description=f"Manager creation failed: {str(e)}",
                target_user=request.user,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Error creating manager: {str(e)}')
            return redirect('super_admin_create_manager')
    
    return render(request, 'auth/create_manager.html')


# ============================================================
# SUPER ADMIN VIEW MANAGERS
# ============================================================

@login_required
def super_admin_managers(request):
    """
    Super Admin view all managers
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="User Management",
            description=f"Unauthorized managers view by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ========== GET MANAGERS ==========
    managers = CustomUser.objects.filter(user_type='manager').annotate(
        employee_count=Count('managed_employees', distinct=True),
        assignment_count=Count('assignments_made', distinct=True),
        hardware_count=Count('created_hardware', distinct=True),
        assigned_hardware_count=Count('assigned_hardware', distinct=True),
        request_count=Count('hardware_requests', distinct=True),
    ).order_by('-date_joined')
    
    # ========== BRANCH STATISTICS ==========
    branch_stats = {}
    for manager in managers:
        branch = manager.branch_location or 'Unassigned'
        if branch not in branch_stats:
            branch_stats[branch] = {
                'count': 0,
                'employees': 0,
                'assignments': 0,
                'hardware': 0
            }
        branch_stats[branch]['count'] += 1
        branch_stats[branch]['employees'] += manager.employee_count
        branch_stats[branch]['assignments'] += manager.assignment_count
        branch_stats[branch]['hardware'] += manager.hardware_count
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_managers_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="User Management",
            description=f"Super Admin {request.user.username} viewed managers ({managers.count()} managers)",
            target_user=request.user,
            new_value={
                'total_managers': managers.count(),
                'branches': len(branch_stats)
            }
        )
        request.session['last_managers_view'] = timezone.now().timestamp()
    
    context = {
        'managers': managers,
        'total_managers': managers.count(),
        'branch_stats': branch_stats,
    }
    return render(request, 'super_admin/managers.html', context)


# ============================================================
# SUPER ADMIN VIEW EMPLOYEES
# ============================================================

@login_required
def super_admin_employees(request):
    """
    Super Admin view all employees with filters
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="User Management",
            description=f"Unauthorized employees view by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ========== GET EMPLOYEES ==========
    employees = CustomUser.objects.filter(user_type='employee').select_related('manager').annotate(
        assignment_count=Count('hardware_assignments', distinct=True),
        active_assignment_count=Count(
            'hardware_assignments',
            filter=Q(hardware_assignments__actual_return_date__isnull=True),
            distinct=True
        )
    ).order_by('-date_joined')
    
    # ========== APPLY FILTERS ==========
    search_query = request.GET.get('search', '')
    if search_query:
        employees = employees.filter(
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(username__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(phone__icontains=search_query)
        )
    
    branch_filter = request.GET.get('branch', '')
    if branch_filter:
        employees = employees.filter(branch_location=branch_filter)
    
    status_filter = request.GET.get('status', '')
    if status_filter == 'active':
        employees = employees.filter(is_active=True)
    elif status_filter == 'inactive':
        employees = employees.filter(is_active=False)
    
    manager_filter = request.GET.get('manager', '')
    if manager_filter:
        employees = employees.filter(manager_id=manager_filter)
    
    assignment_filter = request.GET.get('assignment', '')
    if assignment_filter == 'has_active':
        employees = employees.filter(active_assignment_count__gt=0)
    elif assignment_filter == 'no_active':
        employees = employees.filter(active_assignment_count=0)
    
    # ========== GET BRANCHES AND MANAGERS ==========
    branches = CustomUser.objects.filter(
        user_type='employee'
    ).values_list('branch_location', flat=True).distinct()
    branches = [b for b in branches if b]
    branches = sorted(set(branches))
    
    managers = CustomUser.objects.filter(
        user_type='manager',
        is_active=True
    ).order_by('first_name')
    
    # ========== STATISTICS ==========
    total_employees = employees.count()
    active_count = employees.filter(is_active=True).count()
    inactive_count = employees.filter(is_active=False).count()
    has_active_assignments = employees.filter(active_assignment_count__gt=0).count()
    no_active_assignments = employees.filter(active_assignment_count=0).count()
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_employees_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="User Management",
            description=f"Super Admin {request.user.username} viewed employees ({total_employees} total, {active_count} active)",
            target_user=request.user,
            new_value={
                'total': total_employees,
                'active': active_count,
                'inactive': inactive_count,
                'has_assignments': has_active_assignments,
                'filters': {
                    'search': search_query,
                    'branch': branch_filter,
                    'status': status_filter,
                    'manager': manager_filter,
                    'assignment': assignment_filter
                }
            }
        )
        request.session['last_employees_view'] = timezone.now().timestamp()
    
    context = {
        'employees': employees,
        'total_employees': total_employees,
        'active_count': active_count,
        'inactive_count': inactive_count,
        'has_active_assignments': has_active_assignments,
        'no_active_assignments': no_active_assignments,
        'is_super_admin': True,
        'branches': branches,
        'managers': managers,
        'search_query': search_query,
        'branch_filter': branch_filter,
        'status_filter': status_filter,
        'manager_filter': manager_filter,
        'assignment_filter': assignment_filter,
    }
    return render(request, 'super_admin/employees.html', context)


# ============================================================
# SUPER ADMIN EDIT EMPLOYEE
# ============================================================

@login_required
def super_admin_edit_employee(request, employee_id):
    """
    Super Admin edit employee details
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="User Management",
            description=f"Unauthorized employee edit attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    employee = get_object_or_404(CustomUser, id=employee_id, user_type='employee')
    employee_name = employee.get_full_name() or employee.username
    
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        
        # ========== GET FORM DATA ==========
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()
        phone = request.POST.get('phone', '').strip()
        branch = request.POST.get('branch', '').strip()
        manager_id = request.POST.get('manager')
        is_active = request.POST.get('is_active') == 'on'
        new_username = request.POST.get('username', '').strip()
        
        # Store old values for audit
        old_values = {
            'username': employee.username,
            'first_name': employee.first_name,
            'last_name': employee.last_name,
            'email': employee.email,
            'phone': employee.phone,
            'branch': employee.branch_location,
            'manager': employee.manager.get_full_name() or employee.manager.username if employee.manager else 'Unassigned',
            'is_active': employee.is_active
        }
        
        # ========== VALIDATION ==========
        validation_errors = []
        
        if not first_name and not last_name:
            validation_errors.append('Please enter at least a first name.')
        
        if not email:
            validation_errors.append('Email is required.')
        elif CustomUser.objects.filter(email=email).exclude(id=employee_id).exists():
            validation_errors.append(f'Email "{email}" already exists.')
        elif '@' not in email or '.' not in email:
            validation_errors.append('Please enter a valid email address.')
        
        if not branch:
            validation_errors.append('Please select a branch.')
        
        if new_username and new_username != employee.username:
            if CustomUser.objects.filter(username=new_username).exclude(id=employee_id).exists():
                validation_errors.append(f'Username "{new_username}" already exists.')
        
        if validation_errors:
            for error in validation_errors:
                messages.error(request, error)
            return redirect('super_admin_edit_employee', employee_id=employee_id)
        
        # ========== GET MANAGER ==========
        manager = None
        manager_name = 'Unassigned'
        if manager_id:
            try:
                manager = CustomUser.objects.get(
                    id=manager_id,
                    user_type='manager',
                    branch_location=branch,
                    is_active=True
                )
                manager_name = manager.get_full_name() or manager.username
            except CustomUser.DoesNotExist:
                messages.warning(request, 'Selected manager not found. Employee updated without manager.')
        
        # ========== UPDATE EMPLOYEE ==========
        employee.first_name = first_name
        employee.last_name = last_name
        employee.email = email
        employee.phone = phone
        employee.branch_location = branch
        employee.manager = manager
        employee.is_active = is_active
        
        if new_username and new_username != employee.username:
            employee.username = new_username
        
        employee.save()
        
        # ========== AUDIT LOG ==========
        changes = []
        if old_values['first_name'] != first_name or old_values['last_name'] != last_name:
            changes.append(f"name: '{old_values['first_name']} {old_values['last_name']}' → '{first_name} {last_name}'")
        if old_values['email'] != email:
            changes.append(f"email: '{old_values['email']}' → '{email}'")
        if old_values['phone'] != phone:
            changes.append(f"phone: '{old_values['phone']}' → '{phone}'")
        if old_values['branch'] != branch:
            changes.append(f"branch: '{old_values['branch']}' → '{branch}'")
        if old_values['manager'] != manager_name:
            changes.append(f"manager: '{old_values['manager']}' → '{manager_name}'")
        if old_values['is_active'] != is_active:
            changes.append(f"status: {'active' if old_values['is_active'] else 'inactive'} → {'active' if is_active else 'inactive'}")
        if old_values['username'] != new_username and new_username:
            changes.append(f"username: '{old_values['username']}' → '{new_username}'")
        
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_update",
            module="User Management",
            description=f"Super Admin {request.user.username} updated employee {employee_name}: {', '.join(changes) if changes else 'No changes'}",
            target_user=employee,
            target_model="User",
            target_id=employee.id,
            old_value=old_values,
            new_value={
                'username': employee.username,
                'first_name': employee.first_name,
                'last_name': employee.last_name,
                'email': employee.email,
                'phone': employee.phone,
                'branch': employee.branch_location,
                'manager': manager_name,
                'is_active': employee.is_active,
                'ip': client_ip
            }
        )
        
        messages.success(request, f'✅ Employee {employee.get_full_name() or employee.username} updated successfully!')
        return redirect('super_admin_employees')
    
    # ========== GET REQUEST ==========
    branches = CustomUser.objects.filter(
        user_type='manager'
    ).values_list('branch_location', flat=True).distinct()
    branches = [b for b in branches if b]
    branches = sorted(set(branches)) or ['Hyderabad', 'Bangalore', 'Mumbai', 'Delhi', 'Chennai', 'Pune', 'Kolkata']
    
    managers = CustomUser.objects.filter(
        user_type='manager',
        is_active=True
    ).order_by('first_name')
    
    context = {
        'employee': employee,
        'branches': branches,
        'managers': managers,
    }
    return render(request, 'super_admin/edit_employee.html', context)


# ============================================================
# SUPER ADMIN DELETE EMPLOYEE
# ============================================================

@login_required
def super_admin_delete_employee(request, employee_id):
    """
    Super Admin delete an employee - Only allowed if no active assignments
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="User Management",
            description=f"Unauthorized employee deletion attempt by {request.user.username}",
            target_user=request.user
        )
        messages.error(request, 'You do not have permission to delete employees.')
        return redirect('super_admin_employees')
    
    employee = get_object_or_404(CustomUser, id=employee_id, user_type='employee')
    employee_name = employee.get_full_name() or employee.username
    
    # ========== CHECK ACTIVE ASSIGNMENTS ==========
    active_assignments = HardwareAssignment.objects.filter(
        employee=employee,
        actual_return_date__isnull=True
    )
    active_count = active_assignments.count()
    
    if active_count > 0:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="User Management",
            description=f"Employee deletion blocked - {employee_name} has {active_count} active assignment(s)",
            target_user=employee,
            target_model="User",
            target_id=employee.id,
            old_value={'active_assignments': active_count}
        )
        messages.error(
            request,
            f'❌ Cannot delete {employee_name} - has {active_count} active assignment(s). Please return all hardware first.'
        )
        return redirect('super_admin_employees')
    
    total_assignments = HardwareAssignment.objects.filter(employee=employee).count()
    
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        employee_info = {
            'name': employee_name,
            'email': employee.email,
            'username': employee.username,
            'branch': employee.branch_location,
            'manager': employee.manager.get_full_name() or employee.manager.username if employee.manager else 'Unassigned',
            'total_assignments': total_assignments
        }
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_delete",
            module="User Management",
            description=f"Super Admin {request.user.username} deleted employee {employee_name} ({employee.email})",
            target_user=employee,
            target_model="User",
            target_id=employee.id,
            old_value=employee_info,
            new_value={'deleted': True, 'ip': client_ip}
        )
        
        employee.delete()
        messages.success(request, f'✅ Employee {employee_name} deleted successfully!')
        return redirect('super_admin_employees')
    
    # ========== GET REQUEST ==========
    context = {
        'employee': employee,
        'active_assignments': active_count,
        'total_assignments': total_assignments,
    }
    return render(request, 'super_admin/confirm_delete_employee.html', context)


# views.py - Updated Super Admin Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q, Count
from django.core.paginator import Paginator
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import (
    CustomUser, Hardware, HardwareType, HardwareAssignment, 
    HardwareAssignmentItem, Project, HardwareRequest
)


# ============================================================
# SUPER ADMIN BRANCHES
# ============================================================

@login_required
def super_admin_branches(request):
    """
    Super Admin view all branches with summary
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Branch Management",
            description=f"Unauthorized branches view by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ========== GET BRANCH DATA ==========
    branches = {}
    branch_locations = CustomUser.objects.filter(
        user_type='manager'
    ).values_list('branch_location', flat=True).distinct()
    
    for branch in branch_locations:
        if branch:
            managers = CustomUser.objects.filter(user_type='manager', branch_location=branch)
            employees = CustomUser.objects.filter(user_type='employee', branch_location=branch)
            hardware = Hardware.objects.filter(created_by__branch_location=branch)
            
            all_assignments = HardwareAssignment.objects.filter(
                Q(assigned_by__branch_location=branch) |
                Q(employee__branch_location=branch)
            )
            
            active_assignments = all_assignments.filter(actual_return_date__isnull=True)
            completed_assignments = all_assignments.exclude(actual_return_date__isnull=True)
            
            total_hardware_items = 0
            for assignment in all_assignments:
                items = HardwareAssignmentItem.objects.filter(assignment=assignment)
                total_hardware_items += items.count()
            
            branches[branch] = {
                'manager_count': managers.count(),
                'employee_count': employees.count(),
                'hardware_count': hardware.count(),
                'assignment_count': all_assignments.count(),
                'active_assignment_count': active_assignments.count(),
                'completed_assignment_count': completed_assignments.count(),
                'total_hardware_items': total_hardware_items,
            }
    
    sorted_branches = dict(sorted(branches.items()))
    
    # ========== TOTAL STATISTICS ==========
    total_managers = CustomUser.objects.filter(user_type='manager').count()
    total_employees = CustomUser.objects.filter(user_type='employee').count()
    total_hardware_all = Hardware.objects.count()
    total_active_assignments = HardwareAssignment.objects.filter(actual_return_date__isnull=True).count()
    total_completed_assignments = HardwareAssignment.objects.exclude(actual_return_date__isnull=True).count()
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_branches_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Branch Management",
            description=f"Super Admin {request.user.username} viewed branches ({len(sorted_branches)} branches)",
            target_user=request.user,
            new_value={
                'total_branches': len(sorted_branches),
                'total_managers': total_managers,
                'total_employees': total_employees,
                'total_hardware': total_hardware_all,
                'active_assignments': total_active_assignments
            }
        )
        request.session['last_branches_view'] = timezone.now().timestamp()
    
    context = {
        'branches': sorted_branches,
        'total_branches': len(sorted_branches),
        'total_managers': total_managers,
        'total_employees': total_employees,
        'total_hardware': total_hardware_all,
        'total_active_assignments': total_active_assignments,
        'total_completed_assignments': total_completed_assignments,
    }
    return render(request, 'super_admin/branches.html', context)


# ============================================================
# SUPER ADMIN BRANCH ASSIGNMENTS
# ============================================================

@login_required
def super_admin_branch_assignments(request, branch_name):
    """
    Super Admin view all assignments for a specific branch
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Branch Management",
            description=f"Unauthorized branch assignments view by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ========== DECODE BRANCH NAME ==========
    branch_name = branch_name.replace('-', ' ')
    
    # ========== GET ASSIGNMENTS ==========
    all_assignments = HardwareAssignment.objects.filter(
        Q(assigned_by__branch_location=branch_name) |
        Q(employee__branch_location=branch_name)
    ).select_related('employee', 'project', 'assigned_by').order_by('-assigned_date')
    
    active_assignments = all_assignments.filter(actual_return_date__isnull=True)
    completed_assignments = all_assignments.exclude(actual_return_date__isnull=True)
    
    # ========== GET HARDWARE DETAILS ==========
    assignment_details = []
    total_hardware_items = 0
    
    for assignment in all_assignments:
        items = HardwareAssignmentItem.objects.filter(
            assignment=assignment
        ).select_related('hardware', 'hardware__hardware_type')
        
        hardware_list = []
        for item in items:
            hardware_item = item.hardware
            hardware_list.append({
                'id': hardware_item.id,
                'asset_number': hardware_item.asset_number or 'N/A',
                'serial_number': hardware_item.serial_number,
                'hardware_type': hardware_item.hardware_type.name,
                'model': hardware_item.model_name or '-',
                'brand': hardware_item.brand or '-',
                'status': hardware_item.status,
            })
            total_hardware_items += 1
        
        assignment_details.append({
            'assignment': assignment,
            'employee_name': assignment.employee.get_full_name() or assignment.employee.username,
            'employee_email': assignment.employee.email,
            'employee_phone': assignment.employee.phone or '-',
            'exam_city': assignment.exam_city or '-',
            'exam_center': getattr(assignment, 'exam_center_name', '-'),
            'assigned_date': assignment.assigned_date,
            'expected_return_date': assignment.expected_return_date,
            'actual_return_date': assignment.actual_return_date,
            'project_name': assignment.project.project_name,
            'project_id': assignment.project.project_id,
            'hardware_count': len(hardware_list),
            'hardware_list': hardware_list,
            'is_active': assignment.actual_return_date is None,
        })
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="system_info",
        module="Branch Management",
        description=f"Super Admin {request.user.username} viewed assignments for branch '{branch_name}' ({all_assignments.count()} assignments)",
        target_user=request.user,
        new_value={
            'branch': branch_name,
            'total_assignments': all_assignments.count(),
            'active': active_assignments.count(),
            'completed': completed_assignments.count(),
            'total_hardware': total_hardware_items
        }
    )
    
    # ========== PAGINATION ==========
    paginator = Paginator(assignment_details, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'branch_name': branch_name,
        'assignments': page_obj,
        'all_assignments': assignment_details,
        'active_count': active_assignments.count(),
        'completed_count': completed_assignments.count(),
        'total_count': all_assignments.count(),
        'total_hardware_items': total_hardware_items,
        'page_obj': page_obj,
    }
    return render(request, 'super_admin/branch_assignments.html', context)
# ============================================================
# SUPER ADMIN HARDWARE
# ============================================================
import json
import time
from datetime import datetime, timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.db.models import Q, Count, Sum
from django.core.paginator import Paginator
from django.db import transaction
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from hardware_management.utils.audit import create_audit_log, get_client_ip

from .models import (
    CustomUser, Hardware, HardwareType, HardwareAssignment, 
    HardwareAssignmentItem, HardwareAssetEntry, HardwareSerialEntry,
    HardwareRequest, Project, EmployeeHardwareTransfer,
    TransferItem, TransferHistory, TransferNotification,
    ChatbotConversation, HardwareKnowledgeBase
)


# ============================================================
# SUPER ADMIN HARDWARE VIEW - FIXED BRANCH LOCATION
# ============================================================

@login_required
def super_admin_hardware(request):
    """
    Super Admin view all hardware across all branches
    With audit logging - Uses hardware.branch_location for filtering
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Unauthorized hardware view by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ========== GET HARDWARE ==========
    hardware_list = Hardware.objects.all().select_related(
        'hardware_type', 'created_by'
    ).order_by('-created_at')
    
    # ========== SEARCH FILTER ==========
    search_query = request.GET.get('search', '')
    if search_query:
        hardware_list = hardware_list.filter(
            Q(asset_number__icontains=search_query) |
            Q(serial_number__icontains=search_query) |
            Q(model_name__icontains=search_query) |
            Q(hardware_type__name__icontains=search_query) |
            Q(brand__icontains=search_query) |
            Q(specifications__icontains=search_query)
        )
    
    # ========== STATUS FILTER ==========
    status_filter = request.GET.get('status', '')
    if status_filter:
        hardware_list = hardware_list.filter(status=status_filter)
    
    # ========== BRANCH FILTER - Use hardware's branch_location ==========
    branch_filter = request.GET.get('branch', '')
    if branch_filter:
        hardware_list = hardware_list.filter(branch_location=branch_filter)
    
    # ========== GET BRANCHES - DYNAMIC ONLY ==========
    # Get branches from hardware's branch_location field (exclude None/empty)
    hardware_branches = Hardware.objects.values_list('branch_location', flat=True).distinct()
    hardware_branches = [b for b in hardware_branches if b]
    
    # Get branches from managers (exclude None/empty)
    manager_branches = CustomUser.objects.filter(
        user_type='manager'
    ).values_list('branch_location', flat=True).distinct()
    manager_branches = [b for b in manager_branches if b]
    
    # ✅ Combine and sort - NO STATIC FALLBACK
    branches = sorted(set(hardware_branches) | set(manager_branches))
    
    # ========== STATISTICS ==========
    total_count = hardware_list.count()
    available_count = hardware_list.filter(status='available').count()
    assigned_count = hardware_list.filter(status='assigned').count()
    in_use_count = hardware_list.filter(status='in_use').count()
    maintenance_count = hardware_list.filter(status='maintenance').count()
    retired_count = hardware_list.filter(status='retired').count()
    
    # Hardware by type
    hardware_by_type = {}
    for hw_type in HardwareType.objects.all():
        count = hardware_list.filter(hardware_type=hw_type).count()
        if count > 0:
            hardware_by_type[hw_type.name] = count
    
    # ========== Hardware by branch for statistics ==========
    hardware_by_branch = {}
    for branch in branches:
        count = hardware_list.filter(branch_location=branch).count()
        if count > 0:
            hardware_by_branch[branch] = count
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_hardware_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Hardware Management",
            description=f"Super Admin {request.user.username} viewed hardware ({total_count} items)",
            target_user=request.user,
            new_value={
                'total': total_count,
                'available': available_count,
                'assigned': assigned_count,
                'in_use': in_use_count,
                'maintenance': maintenance_count,
                'retired': retired_count,
                'filters': {
                    'search': search_query,
                    'status': status_filter,
                    'branch': branch_filter
                }
            }
        )
        request.session['last_hardware_view'] = timezone.now().timestamp()
    
    context = {
        'hardware_list': hardware_list,
        'total_hardware': total_count,
        'branches': branches,  # ✅ Dynamic branches only
        'is_super_admin': True,
        'search_query': search_query,
        'status_filter': status_filter,
        'branch_filter': branch_filter,
        'available_count': available_count,
        'assigned_count': assigned_count,
        'in_use_count': in_use_count,
        'maintenance_count': maintenance_count,
        'retired_count': retired_count,
        'hardware_by_type': hardware_by_type,
        'hardware_by_branch': hardware_by_branch,
    }
    return render(request, 'super_admin/hardware.html', context)

# ============================================================
# SUPER ADMIN EDIT HARDWARE - UPDATED
# ============================================================
@login_required
def super_admin_edit_hardware(request, hardware_id):
    """
    Super Admin edit hardware with branch location support
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Unauthorized hardware edit attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    hardware = get_object_or_404(Hardware, id=hardware_id)
    hardware_types = HardwareType.objects.all()
    
    # ========== GET ALL BRANCHES - DYNAMIC ONLY ==========
    hardware_branches = Hardware.objects.values_list('branch_location', flat=True).distinct()
    hardware_branches = [b for b in hardware_branches if b]
    
    manager_branches = CustomUser.objects.filter(
        user_type='manager'
    ).values_list('branch_location', flat=True).distinct()
    manager_branches = [b for b in manager_branches if b]
    
    # ✅ Combine and sort - NO STATIC FALLBACK
    branches = sorted(set(hardware_branches) | set(manager_branches))
    
    # ========== GET MANAGERS FOR DROPDOWN ==========
    managers = CustomUser.objects.filter(
        user_type='manager',
        is_active=True
    ).order_by('first_name')
    
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        
        # ========== GET FORM DATA ==========
        hardware_type_id = request.POST.get('hardware_type')
        asset_number = request.POST.get('asset_number', '').strip()
        serial_number = request.POST.get('serial_number', '').strip()
        model_name = request.POST.get('model_name', '').strip()
        brand = request.POST.get('brand', '').strip()
        specifications = request.POST.get('specifications', '').strip()
        purchase_date = request.POST.get('purchase_date')
        status = request.POST.get('status')
        branch_location = request.POST.get('branch_location', '').strip()
        manager_id = request.POST.get('manager')
        
        # Store old values for audit
        old_values = {
            'hardware_type': hardware.hardware_type.name if hardware.hardware_type else None,
            'asset_number': hardware.asset_number,
            'serial_number': hardware.serial_number,
            'model_name': hardware.model_name,
            'brand': hardware.brand,
            'specifications': hardware.specifications,
            'purchase_date': hardware.purchase_date,
            'status': hardware.status,
            'branch_location': hardware.branch_location,
            'created_by': hardware.created_by.username if hardware.created_by else None,
        }
        
        # ========== VALIDATION ==========
        validation_errors = []
        
        if not hardware_type_id:
            validation_errors.append('Hardware type is required.')
        if not asset_number:
            validation_errors.append('Asset number is required.')
        if not serial_number:
            validation_errors.append('Serial number is required.')
        if not branch_location:
            validation_errors.append('Please select a branch location.')
        
        if validation_errors:
            for error in validation_errors:
                messages.error(request, error)
            return redirect('super_admin_edit_hardware', hardware_id=hardware_id)
        
        if Hardware.objects.filter(asset_number=asset_number).exclude(id=hardware_id).exists():
            messages.error(request, 'Asset number already exists!')
            return redirect('super_admin_edit_hardware', hardware_id=hardware_id)
        
        if Hardware.objects.filter(serial_number=serial_number).exclude(id=hardware_id).exists():
            messages.error(request, 'Serial number already exists!')
            return redirect('super_admin_edit_hardware', hardware_id=hardware_id)
        
        try:
            hardware_type = HardwareType.objects.get(id=hardware_type_id)
        except HardwareType.DoesNotExist:
            messages.error(request, 'Invalid hardware type selected!')
            return redirect('super_admin_edit_hardware', hardware_id=hardware_id)
        
        # ========== GET MANAGER ==========
        manager = None
        manager_name = 'Unassigned'
        if manager_id:
            try:
                manager = CustomUser.objects.get(
                    id=manager_id,
                    user_type='manager',
                    branch_location=branch_location,
                    is_active=True
                )
                manager_name = manager.get_full_name() or manager.username
            except CustomUser.DoesNotExist:
                messages.warning(request, 'Selected manager not found in this branch. Hardware updated without manager.')
        
        # ========== UPDATE HARDWARE ==========
        hardware.hardware_type = hardware_type
        hardware.asset_number = asset_number
        hardware.serial_number = serial_number
        hardware.model_name = model_name
        hardware.brand = brand
        hardware.specifications = specifications
        hardware.status = status
        hardware.branch_location = branch_location
        hardware.created_by = manager or hardware.created_by
        
        if purchase_date:
            hardware.purchase_date = purchase_date
        
        hardware.save()
        
        # ========== AUDIT LOG ==========
        changes = []
        if old_values['asset_number'] != asset_number:
            changes.append(f"asset: '{old_values['asset_number']}' → '{asset_number}'")
        if old_values['serial_number'] != serial_number:
            changes.append(f"serial: '{old_values['serial_number']}' → '{serial_number}'")
        if old_values['hardware_type'] != (hardware_type.name if hardware_type else None):
            changes.append(f"type: '{old_values['hardware_type']}' → '{hardware_type.name}'")
        if old_values['model_name'] != model_name:
            changes.append(f"model: '{old_values['model_name']}' → '{model_name}'")
        if old_values['brand'] != brand:
            changes.append(f"brand: '{old_values['brand']}' → '{brand}'")
        if old_values['status'] != status:
            changes.append(f"status: '{old_values['status']}' → '{status}'")
        if old_values['branch_location'] != branch_location:
            changes.append(f"branch: '{old_values['branch_location']}' → '{branch_location}'")
        if old_values['created_by'] != manager_name:
            changes.append(f"manager: '{old_values['created_by']}' → '{manager_name}'")
        
        create_audit_log(
            request=request,
            user=request.user,
            action="hardware_update",
            module="Hardware Management",
            description=f"Super Admin {request.user.username} updated hardware {asset_number}: {', '.join(changes) if changes else 'No changes'}",
            target_model="Hardware",
            target_id=hardware.id,
            old_value=old_values,
            new_value={
                'asset_number': asset_number,
                'serial_number': serial_number,
                'hardware_type': hardware_type.name,
                'model_name': model_name,
                'brand': brand,
                'status': status,
                'branch_location': branch_location,
                'manager': manager_name,
                'ip': client_ip
            }
        )
        
        messages.success(request, f'✅ Hardware updated successfully! Asset: {asset_number} | Branch: {branch_location}')
        return redirect('super_admin_hardware')
    
    context = {
        'hardware': hardware,
        'hardware_types': hardware_types,
        'branches': branches,  # ✅ Dynamic branches only
        'managers': managers,
        'current_branch': hardware.branch_location,
        'current_manager': hardware.created_by.id if hardware.created_by else None,
    }
    return render(request, 'super_admin/edit_hardware.html', context)
# ============================================================
# SUPER ADMIN DELETE HARDWARE
# ============================================================

@login_required
def super_admin_delete_hardware(request, hardware_id):
    """
    Super Admin delete hardware
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Unauthorized hardware deletion attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    hardware = get_object_or_404(Hardware, id=hardware_id)
    asset_number = hardware.asset_number or hardware.serial_number
    
    # ========== CHECK STATUS ==========
    if hardware.status in ['assigned', 'in_use']:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Hardware deletion blocked - {asset_number} is {hardware.status}",
            target_user=request.user,
            target_model="Hardware",
            target_id=hardware.id,
            old_value={'status': hardware.status}
        )
        messages.error(
            request,
            f'Cannot delete hardware "{asset_number}" - it is currently {hardware.get_status_display().lower()}!'
        )
        return redirect('super_admin_hardware')
    
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        
        hardware_info = {
            'asset_number': hardware.asset_number,
            'serial_number': hardware.serial_number,
            'hardware_type': hardware.hardware_type.name if hardware.hardware_type else 'Unknown',
            'model_name': hardware.model_name,
            'brand': hardware.brand,
            'status': hardware.status,
        }
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="hardware_delete",
            module="Hardware Management",
            description=f"Super Admin {request.user.username} deleted hardware {asset_number}",
            target_model="Hardware",
            target_id=hardware.id,
            old_value=hardware_info,
            new_value={'deleted': True, 'ip': client_ip}
        )
        
        hardware.delete()
        messages.success(request, f'✅ Hardware {asset_number} deleted successfully!')
        return redirect('super_admin_hardware')
    
    # ========== GET REQUEST ==========
    context = {'hardware': hardware}
    return render(request, 'super_admin/confirm_delete_hardware.html', context)


# ============================================================
# SUPER ADMIN BULK DELETE HARDWARE
# ============================================================

@login_required
def super_admin_bulk_delete_hardware(request):
    """
    Super Admin bulk delete hardware
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Unauthorized bulk deletion attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    if request.method == 'POST':
        hardware_ids = request.POST.getlist('hardware_ids')
        client_ip = get_client_ip(request)
        
        if not hardware_ids:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Management",
                description=f"Bulk deletion attempt with no items selected by {request.user.username}",
                target_user=request.user
            )
            messages.error(request, 'No hardware items selected for deletion!')
            return redirect('super_admin_hardware')
        
        # ========== FILTER VALID ITEMS ==========
        hardware_to_delete = Hardware.objects.filter(
            id__in=hardware_ids
        ).exclude(
            status__in=['assigned', 'in_use']
        )
        
        deleted_count = hardware_to_delete.count()
        skipped_count = len(hardware_ids) - deleted_count
        
        # ========== GET LIST OF DELETED ITEMS ==========
        deleted_items = []
        for hw in hardware_to_delete:
            deleted_items.append({
                'asset_number': hw.asset_number,
                'serial_number': hw.serial_number,
                'type': hw.hardware_type.name if hw.hardware_type else 'Unknown'
            })
        
        # ========== AUDIT LOG ==========
        if deleted_count > 0:
            create_audit_log(
                request=request,
                user=request.user,
                action="hardware_bulk_delete",
                module="Hardware Management",
                description=f"Super Admin {request.user.username} bulk deleted {deleted_count} hardware items",
                target_user=request.user,
                new_value={
                    'deleted_count': deleted_count,
                    'skipped_count': skipped_count,
                    'items': deleted_items[:10],  # First 10 for audit
                    'total_selected': len(hardware_ids),
                    'ip': client_ip
                }
            )
            
            hardware_to_delete.delete()
            messages.success(request, f'✅ Successfully deleted {deleted_count} hardware item(s)!')
        else:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Hardware Management",
                description=f"Bulk deletion - No valid items found among {len(hardware_ids)} selected",
                target_user=request.user,
                new_value={'selected_count': len(hardware_ids)}
            )
            messages.warning(request, 'No valid items found for deletion (all are assigned or in use).')
        
        if skipped_count > 0:
            messages.warning(request, f'Skipped {skipped_count} item(s) that are assigned or in use.')
        
        return redirect('super_admin_hardware')
    
    return redirect('super_admin_hardware')


# views.py - Updated Super Admin Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q, Count
from django.core.paginator import Paginator
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import (
    CustomUser, Hardware, HardwareType, HardwareAssignment, 
    HardwareAssignmentItem, HardwareRequest, Project
)
from .utils.email_utils import send_response_notification


# ============================================================
# SUPER ADMIN VIEW HARDWARE DETAILS
# ============================================================

@login_required
def super_admin_view_hardware_details(request, hardware_id):
    """
    Super Admin view single hardware details
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Hardware Management",
            description=f"Unauthorized hardware details view by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    hardware = get_object_or_404(Hardware, id=hardware_id)
    
    # Get assignment history
    assignments = HardwareAssignmentItem.objects.filter(
        hardware=hardware
    ).select_related('assignment__employee', 'assignment__project').order_by('-assignment__assigned_date')
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="system_info",
        module="Hardware Management",
        description=f"Super Admin {request.user.username} viewed hardware details for {hardware.asset_number}",
        target_user=request.user,
        target_model="Hardware",
        target_id=hardware.id,
        new_value={
            'asset_number': hardware.asset_number,
            'serial_number': hardware.serial_number,
            'type': hardware.hardware_type.name if hardware.hardware_type else 'Unknown',
            'status': hardware.status,
            'assignment_count': assignments.count()
        }
    )
    
    context = {
        'hardware': hardware,
        'assignments': assignments,
    }
    return render(request, 'super_admin/hardware_details.html', context)


# ============================================================
# SUPER ADMIN VIEW REQUESTS
# ============================================================

@login_required
def super_admin_requests(request):
    """
    Super Admin view all hardware requests
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Request Management",
            description=f"Unauthorized requests view by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ========== GET REQUESTS ==========
    requests_list = HardwareRequest.objects.all().select_related(
        'hardware', 'hardware__hardware_type',
        'requested_by', 'reviewed_by'
    )
    
    # ========== APPLY FILTERS ==========
    status_filter = request.GET.get('status', '')
    if status_filter:
        requests_list = requests_list.filter(status=status_filter)
    
    type_filter = request.GET.get('type', '')
    if type_filter:
        requests_list = requests_list.filter(request_type=type_filter)
    
    search_query = request.GET.get('search', '')
    if search_query:
        requests_list = requests_list.filter(
            Q(hardware__asset_number__icontains=search_query) |
            Q(hardware__serial_number__icontains=search_query) |
            Q(requested_by__username__icontains=search_query) |
            Q(requested_by__first_name__icontains=search_query) |
            Q(requested_by__last_name__icontains=search_query)
        )
    
    # ========== STATISTICS ==========
    all_requests = HardwareRequest.objects.all()
    total = all_requests.count()
    pending = all_requests.filter(status='pending').count()
    approved = all_requests.filter(status='approved').count()
    rejected = all_requests.filter(status='rejected').count()
    completed = all_requests.filter(status='completed').count()
    
    update_requests = all_requests.filter(request_type='update').count()
    delete_requests = all_requests.filter(request_type='delete').count()
    
    requests_list = requests_list.order_by('-created_at')
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_requests_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Request Management",
            description=f"Super Admin {request.user.username} viewed requests ({total} total, {pending} pending)",
            target_user=request.user,
            new_value={
                'total': total,
                'pending': pending,
                'approved': approved,
                'rejected': rejected,
                'completed': completed,
                'update_requests': update_requests,
                'delete_requests': delete_requests,
                'filters': {
                    'status': status_filter,
                    'type': type_filter,
                    'search': search_query
                }
            }
        )
        request.session['last_requests_view'] = timezone.now().timestamp()
    
    # ========== PAGINATION ==========
    paginator = Paginator(requests_list, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'requests': page_obj,
        'total': total,
        'pending': pending,
        'approved': approved,
        'rejected': rejected,
        'completed': completed,
        'update_requests': update_requests,
        'delete_requests': delete_requests,
        'status_filter': status_filter,
        'type_filter': type_filter,
        'search_query': search_query,
        'page_obj': page_obj,
        'paginator': paginator,
    }
    return render(request, 'super_admin/requests.html', context)


# ============================================================
# SUPER ADMIN VIEW REQUEST DETAILS
# ============================================================

@login_required
def super_admin_view_request(request, request_id):
    """
    Super Admin view single request details
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Request Management",
            description=f"Unauthorized request view by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    try:
        hw_request = HardwareRequest.objects.select_related(
            'hardware', 'hardware__hardware_type',
            'requested_by', 'reviewed_by'
        ).get(id=request_id)
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Request Management",
            description=f"Super Admin {request.user.username} viewed request #{request_id}",
            target_user=request.user,
            target_model="HardwareRequest",
            target_id=request_id,
            new_value={
                'request_id': request_id,
                'hardware': hw_request.hardware.asset_number,
                'hardware_uuid': str(hw_request.hardware.hardware_id),  # ✅ Log UUID
                'type': hw_request.request_type,
                'status': hw_request.status,
                'requested_by': hw_request.requested_by.username
            }
        )
        
    except HardwareRequest.DoesNotExist:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Request Management",
            description=f"Request #{request_id} not found when viewed by {request.user.username}",
            target_user=request.user,
            target_model="HardwareRequest",
            target_id=request_id
        )
        messages.error(request, f'Request #{request_id} not found.')
        return redirect('super_admin_requests')
    
    context = {'request': hw_request}
    return render(request, 'super_admin/request_details.html', context)


# ============================================================
# SUPER ADMIN APPROVE REQUEST
# ============================================================

@login_required
def super_admin_approve_request(request, request_id):
    """
    Super Admin approve a request
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Request Management",
            description=f"Unauthorized request approval attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    try:
        hw_request = HardwareRequest.objects.select_related(
            'hardware', 'requested_by'
        ).get(id=request_id, status='pending')
    except HardwareRequest.DoesNotExist:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Request Management",
            description=f"Request #{request_id} not found or already processed",
            target_user=request.user,
            target_model="HardwareRequest",
            target_id=request_id
        )
        messages.error(request, f'Request #{request_id} not found or already processed.')
        return redirect('super_admin_requests')
    
    if request.method == 'POST':
        notes = request.POST.get('notes', '').strip()
        client_ip = get_client_ip(request)
        
        hardware_asset = hw_request.hardware.asset_number or hw_request.hardware.serial_number
        
        # ✅ Use hardware_id (UUID) for lookup
        hardware = get_object_or_404(Hardware, hardware_id=hw_request.hardware.hardware_id)
        
        request_type = hw_request.request_type
        
        try:
            if request_type == 'delete':
                # ========== DELETE REQUEST ==========
                hw_request.status = 'completed'
                hw_request.reviewed_by = request.user
                hw_request.reviewed_at = timezone.now()
                if notes:
                    hw_request.notes = notes
                hw_request.save()
                
                # ========== AUDIT LOG ==========
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="hardware_approve_delete",
                    module="Request Management",
                    description=f"Super Admin {request.user.username} approved DELETE request for hardware '{hardware_asset}' from {hw_request.requested_by.get_full_name() or hw_request.requested_by.username}",
                    target_user=hw_request.requested_by,
                    target_model="HardwareRequest",
                    target_id=hw_request.id,
                    old_value={
                        'request_type': 'delete',
                        'status': 'pending',
                        'hardware': hardware_asset,
                        'requested_by': hw_request.requested_by.username
                    },
                    new_value={
                        'status': 'completed',
                        'approved_by': request.user.username,
                        'approved_at': timezone.now().isoformat(),
                        'notes': notes,
                        'ip': client_ip
                    }
                )
                
                # Delete the hardware using UUID lookup
                hardware.delete()
                
                messages.success(request, f'✅ Hardware "{hardware_asset}" deleted successfully!')
                
            else:
                # ========== UPDATE REQUEST ==========
                hw_request.status = 'approved'
                hw_request.reviewed_by = request.user
                hw_request.reviewed_at = timezone.now()
                if notes:
                    hw_request.notes = notes
                hw_request.save()
                
                # ========== AUDIT LOG ==========
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="hardware_approve_update",
                    module="Request Management",
                    description=f"Super Admin {request.user.username} approved UPDATE request for hardware '{hardware_asset}' from {hw_request.requested_by.get_full_name() or hw_request.requested_by.username}",
                    target_user=hw_request.requested_by,
                    target_model="HardwareRequest",
                    target_id=hw_request.id,
                    old_value={
                        'request_type': 'update',
                        'status': 'pending',
                        'hardware': hardware_asset,
                        'requested_by': hw_request.requested_by.username
                    },
                    new_value={
                        'status': 'approved',
                        'approved_by': request.user.username,
                        'approved_at': timezone.now().isoformat(),
                        'notes': notes,
                        'ip': client_ip
                    }
                )
                
                messages.success(request, f'✅ Update request #{hw_request.id} approved!')
            
            # ========== SEND EMAIL NOTIFICATION ==========
            try:
                email_sent = send_response_notification(request, hw_request, 'approved', notes)
                if email_sent:
                    messages.info(request, f'📧 Notification email sent to {hw_request.requested_by.email}')
                else:
                    messages.warning(request, 'Request processed but notification email could not be sent.')
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Request Management",
                    description=f"Email notification failed for approved request #{hw_request.id}: {str(e)}",
                    target_user=hw_request.requested_by,
                    target_model="HardwareRequest",
                    target_id=hw_request.id
                )
                messages.warning(request, f'Request processed but email notification failed: {str(e)}')
                
        except Hardware.DoesNotExist:
            # ========== HARDWARE ALREADY DELETED ==========
            hw_request.status = 'completed'
            hw_request.reviewed_by = request.user
            hw_request.reviewed_at = timezone.now()
            hw_request.notes = f"Hardware already deleted. {notes}"
            hw_request.save()
            
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Request Management",
                description=f"Hardware '{hardware_asset}' already deleted. Request #{hw_request.id} marked as completed.",
                target_user=hw_request.requested_by,
                target_model="HardwareRequest",
                target_id=hw_request.id
            )
            
            messages.warning(request, f'Hardware already deleted. Request marked as completed.')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Request Management",
                description=f"Error processing request #{hw_request.id}: {str(e)}",
                target_user=request.user,
                target_model="HardwareRequest",
                target_id=hw_request.id,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Error processing request: {str(e)}')
            return redirect('super_admin_requests')
        
        return redirect('super_admin_requests')
    
    context = {'request': hw_request}
    return render(request, 'super_admin/approve_request.html', context)


# ============================================================
# SUPER ADMIN REJECT REQUEST
# ============================================================

@login_required
def super_admin_reject_request(request, request_id):
    """
    Super Admin reject a request
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Request Management",
            description=f"Unauthorized request rejection attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    try:
        hw_request = HardwareRequest.objects.select_related(
            'hardware', 'requested_by'
        ).get(id=request_id, status='pending')
    except HardwareRequest.DoesNotExist:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Request Management",
            description=f"Request #{request_id} not found or already processed",
            target_user=request.user,
            target_model="HardwareRequest",
            target_id=request_id
        )
        messages.error(request, f'Request #{request_id} not found or already processed.')
        return redirect('super_admin_requests')
    
    if request.method == 'POST':
        notes = request.POST.get('notes', '').strip()
        client_ip = get_client_ip(request)
        hardware_asset = hw_request.hardware.asset_number or hw_request.hardware.serial_number
        
        # ========== UPDATE REQUEST ==========
        hw_request.status = 'rejected'
        hw_request.reviewed_by = request.user
        hw_request.reviewed_at = timezone.now()
        if notes:
            hw_request.notes = notes
        hw_request.save()
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="hardware_reject_update" if hw_request.request_type == 'update' else "hardware_reject_delete",
            module="Request Management",
            description=f"Super Admin {request.user.username} rejected {hw_request.request_type} request for hardware '{hardware_asset}' from {hw_request.requested_by.get_full_name() or hw_request.requested_by.username}",
            target_user=hw_request.requested_by,
            target_model="HardwareRequest",
            target_id=hw_request.id,
            old_value={
                'request_type': hw_request.request_type,
                'status': 'pending',
                'hardware': hardware_asset,
                'requested_by': hw_request.requested_by.username
            },
            new_value={
                'status': 'rejected',
                'rejected_by': request.user.username,
                'rejected_at': timezone.now().isoformat(),
                'reason': notes,
                'ip': client_ip
            }
        )
        
        messages.warning(request, f'❌ Request #{hw_request.id} rejected!')
        
        # ========== SEND EMAIL NOTIFICATION ==========
        try:
            email_sent = send_response_notification(request, hw_request, 'rejected', notes)
            if email_sent:
                messages.info(request, f'📧 Notification email sent to {hw_request.requested_by.email}')
            else:
                messages.warning(request, 'Request rejected but notification email could not be sent.')
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Request Management",
                description=f"Email notification failed for rejected request #{hw_request.id}: {str(e)}",
                target_user=hw_request.requested_by,
                target_model="HardwareRequest",
                target_id=hw_request.id
            )
            messages.warning(request, f'Request rejected but email notification failed: {str(e)}')
        
        return redirect('super_admin_requests')
    
    context = {'request': hw_request}
    return render(request, 'super_admin/reject_request.html', context)
# ============================================================
# SUPER ADMIN DELETE REQUEST
# ============================================================

@login_required
def super_admin_delete_request(request, request_id):
    """
    Super Admin manually delete a request
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Request Management",
            description=f"Unauthorized request deletion attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    try:
        hw_request = HardwareRequest.objects.get(id=request_id)
        hardware_asset = hw_request.hardware.asset_number if hw_request.hardware else 'N/A'
        request_type = hw_request.request_type
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="hardware_request_delete",
            module="Request Management",
            description=f"Super Admin {request.user.username} deleted {request_type} request #{request_id} for {hardware_asset}",
            target_user=hw_request.requested_by,
            target_model="HardwareRequest",
            target_id=hw_request.id,
            old_value={
                'request_id': request_id,
                'request_type': request_type,
                'hardware': hardware_asset,
                'status': hw_request.status,
                'requested_by': hw_request.requested_by.username
            }
        )
        
        hw_request.delete()
        messages.success(request, '✅ Request deleted successfully!')
        return redirect('super_admin_requests')
        
    except HardwareRequest.DoesNotExist:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Request Management",
            description=f"Request #{request_id} not found for deletion by {request.user.username}",
            target_user=request.user,
            target_model="HardwareRequest",
            target_id=request_id
        )
        messages.error(request, 'Request not found.')
        return redirect('super_admin_requests')


# ============================================================
# SUPER ADMIN VIEW ASSIGNMENTS
# ============================================================

@login_required
def super_admin_assignments(request):
    """
    Super Admin view all assignments across all branches
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Assignment Management",
            description=f"Unauthorized assignments view by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ========== GET ASSIGNMENTS ==========
    assignments = HardwareAssignment.objects.all().select_related(
        'employee', 'project', 'assigned_by'
    ).order_by('-assigned_date')
    
    total = assignments.count()
    active = assignments.filter(actual_return_date__isnull=True).count()
    completed = assignments.exclude(actual_return_date__isnull=True).count()
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_assignments_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Assignment Management",
            description=f"Super Admin {request.user.username} viewed assignments ({total} total, {active} active)",
            target_user=request.user,
            new_value={
                'total': total,
                'active': active,
                'completed': completed
            }
        )
        request.session['last_assignments_view'] = timezone.now().timestamp()
    
    context = {
        'assignments': assignments,
        'total_assignments': total,
    }
    return render(request, 'super_admin/assignments.html', context)


# ============================================================
# SUPER ADMIN DELETE MANAGER
# ============================================================

@login_required
def super_admin_delete_manager(request, manager_id):
    """
    Super Admin delete a manager
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="User Management",
            description=f"Unauthorized manager deletion attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    manager = get_object_or_404(CustomUser, id=manager_id, user_type='manager')
    manager_name = manager.get_full_name() or manager.username
    
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        
        # ========== CHECK FOR EMPLOYEES ==========
        if CustomUser.objects.filter(manager=manager).exists():
            employee_count = CustomUser.objects.filter(manager=manager).count()
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="User Management",
                description=f"Manager deletion blocked - {manager_name} has {employee_count} assigned employees",
                target_user=manager,
                target_model="User",
                target_id=manager.id,
                old_value={'employee_count': employee_count}
            )
            messages.error(request, 'Cannot delete manager with assigned employees!')
            return redirect('super_admin_managers')
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="user_delete",
            module="User Management",
            description=f"Super Admin {request.user.username} deleted manager {manager_name} ({manager.email})",
            target_user=manager,
            target_model="User",
            target_id=manager.id,
            old_value={
                'name': manager_name,
                'email': manager.email,
                'username': manager.username,
                'branch': manager.branch_location,
                'phone': manager.phone
            },
            new_value={'deleted': True, 'ip': client_ip}
        )
        
        manager.delete()
        messages.success(request, f'✅ Manager {manager_name} deleted successfully!')
        return redirect('super_admin_managers')
    
    context = {'manager': manager}
    return render(request, 'super_admin/delete_manager.html', context)


# ============================================================
# SUPER ADMIN CREATE PROJECT
# ============================================================

@login_required
def super_admin_create_project(request):
    """
    Super Admin can create global projects for ALL managers
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Project Management",
            description=f"Unauthorized project creation attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        project_id = request.POST.get('project_id', '').strip()
        project_name = request.POST.get('project_name', '').strip()
        description = request.POST.get('description', '').strip()
        start_date = request.POST.get('start_date')
        end_date = request.POST.get('end_date')
        
        # ========== VALIDATION ==========
        validation_errors = []
        
        if not project_id:
            validation_errors.append('Project ID is required.')
        elif Project.objects.filter(project_id=project_id).exists():
            validation_errors.append(f'Project ID "{project_id}" already exists.')
        
        if not project_name:
            validation_errors.append('Project Name is required.')
        elif Project.objects.filter(project_name=project_name).exists():
            validation_errors.append(f'Project name "{project_name}" already exists.')
        
        if not start_date:
            validation_errors.append('Start Date is required.')
        if not end_date:
            validation_errors.append('End Date is required.')
        
        if validation_errors:
            for error in validation_errors:
                messages.error(request, error)
            return redirect('super_admin_create_project')
        
        try:
            # ========== CREATE PROJECT ==========
            project = Project.objects.create(
                project_id=project_id,
                project_name=project_name,
                description=description,
                start_date=start_date,
                end_date=end_date,
                is_active=True,
                created_by=request.user,
                assigned_manager=None,
                location=None
            )
            
            manager_count = CustomUser.objects.filter(user_type='manager', is_active=True).count()
            
            # ========== AUDIT LOG ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="project_create",
                module="Project Management",
                description=f"Super Admin {request.user.username} created global project '{project_name}' ({project_id})",
                target_model="Project",
                target_id=project.id,
                new_value={
                    'project_id': project_id,
                    'project_name': project_name,
                    'start_date': start_date,
                    'end_date': end_date,
                    'is_active': True,
                    'available_to_managers': manager_count,
                    'ip': client_ip
                }
            )
            
            messages.success(
                request,
                f'✅ Project "{project_name}" created successfully! It is now available to ALL {manager_count} managers across ALL branches.'
            )
            return redirect('super_admin_projects')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Project Management",
                description=f"Project creation failed: {str(e)}",
                target_user=request.user,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Error creating project: {str(e)}')
            return redirect('super_admin_create_project')
    
    # ========== GET REQUEST ==========
    managers = CustomUser.objects.filter(
        user_type='manager',
        is_active=True
    ).order_by('first_name')
    
    context = {
        'today': timezone.now().date(),
        'total_projects': Project.objects.count(),
        'active_projects': Project.objects.filter(
            is_active=True,
            end_date__gte=timezone.now().date()
        ).count(),
        'manager_count': managers.count(),
    }
    return render(request, 'super_admin/create_project.html', context)

# views.py - Updated Super Admin Project Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q, Count
from django.http import HttpResponse
from datetime import datetime
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import (
    CustomUser, Project, HardwareAssignment, HardwareAssignmentItem,
    Hardware, HardwareType, HardwareAssetEntry
)


# ============================================================
# SUPER ADMIN PROJECTS
# ============================================================

@login_required
def super_admin_projects(request):
    """
    Super Admin view all projects across all branches with detailed assignment info
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Project Management",
            description=f"Unauthorized projects view by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ========== GET PROJECTS ==========
    projects = Project.objects.all().order_by('-created_at')
    
    # ========== ENRICH PROJECTS ==========
    for project in projects:
        active_assignments = HardwareAssignment.objects.filter(
            project=project,
            actual_return_date__isnull=True
        ).select_related('employee', 'assigned_by')
        
        project.active_assignments = active_assignments
        project.active_assignment_count = active_assignments.count()
        
        project.employees_detail = []
        project.total_hardware = 0
        project.active_hardware = 0
        
        for assignment in active_assignments:
            items = HardwareAssignmentItem.objects.filter(
                assignment=assignment
            ).select_related('hardware', 'hardware__hardware_type')
            
            hardware_list = []
            for item in items:
                hardware = item.hardware
                hardware_list.append({
                    'id': hardware.id,
                    'asset_number': hardware.asset_number or 'N/A',
                    'serial_number': hardware.serial_number,
                    'hardware_type': hardware.hardware_type.name,
                    'model': hardware.model_name or '-',
                    'brand': hardware.brand or '-',
                    'status': hardware.status,
                })
                project.total_hardware += 1
                if hardware.status == 'in_use':
                    project.active_hardware += 1
            
            project.employees_detail.append({
                'employee': assignment.employee,
                'employee_name': assignment.employee.get_full_name() or assignment.employee.username,
                'employee_email': assignment.employee.email,
                'assignment_id': assignment.id,
                'exam_city': assignment.exam_city or 'Not Set',
                'exam_center': getattr(assignment, 'exam_center_name', 'Not Set'),
                'assigned_date': assignment.assigned_date,
                'expected_return_date': assignment.expected_return_date,
                'hardware_count': len(hardware_list),
                'hardware_list': hardware_list,
            })
        
        project.employee_count = len(project.employees_detail)
        
        if project.assigned_manager:
            project.manager_name = project.assigned_manager.get_full_name() or project.assigned_manager.username
        else:
            project.manager_name = 'Unassigned'
        
        project.can_delete = project.total_hardware == 0
    
    # ========== APPLY FILTERS ==========
    status_filter = request.GET.get('status', '')
    if status_filter == 'active':
        projects = [p for p in projects if p.active_assignment_count > 0]
    elif status_filter == 'inactive':
        projects = [p for p in projects if p.active_assignment_count == 0]
    
    search_query = request.GET.get('search', '')
    if search_query:
        projects = [p for p in projects if 
                   search_query.lower() in p.project_name.lower() or 
                   search_query.lower() in p.project_id.lower() or
                   search_query.lower() in (p.location or '').lower()]
    
    # ========== STATISTICS ==========
    total_projects = len(projects)
    active_projects = len([p for p in projects if p.active_assignment_count > 0])
    completed_projects = len([p for p in projects if p.active_assignment_count == 0])
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_super_admin_projects_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Project Management",
            description=f"Super Admin {request.user.username} viewed projects ({total_projects} total, {active_projects} active)",
            target_user=request.user,
            new_value={
                'total': total_projects,
                'active': active_projects,
                'completed': completed_projects,
                'filters': {
                    'status': status_filter,
                    'search': search_query
                }
            }
        )
        request.session['last_super_admin_projects_view'] = timezone.now().timestamp()
    
    context = {
        'projects': projects,
        'total_projects': total_projects,
        'active_projects': active_projects,
        'completed_projects': completed_projects,
        'search_query': search_query,
        'status_filter': status_filter,
    }
    return render(request, 'super_admin/projects.html', context)


# ============================================================
# SUPER ADMIN PROJECT ASSIGNMENTS
# ============================================================

@login_required
def super_admin_project_assignments(request, project_id):
    """
    Super Admin view only active assignments for a specific project
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Project Management",
            description=f"Unauthorized project assignments view by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    project = get_object_or_404(Project, id=project_id)
    
    # ========== GET ACTIVE ASSIGNMENTS ==========
    active_assignments = HardwareAssignment.objects.filter(
        project=project,
        actual_return_date__isnull=True
    ).select_related('employee', 'assigned_by').order_by('-assigned_date')
    
    completed_assignments = HardwareAssignment.objects.filter(
        project=project
    ).exclude(actual_return_date__isnull=True).count()
    
    # ========== ENRICH ASSIGNMENTS ==========
    total_hardware_count = 0
    for assignment in active_assignments:
        items = HardwareAssignmentItem.objects.filter(
            assignment=assignment
        ).select_related('hardware', 'hardware__hardware_type')
        
        assignment.hardware_list = []
        assignment.hardware_count = items.count()
        total_hardware_count += items.count()
        
        for item in items:
            hardware = item.hardware
            assignment.hardware_list.append({
                'id': hardware.id,
                'asset_number': hardware.asset_number or 'N/A',
                'serial_number': hardware.serial_number,
                'hardware_type': hardware.hardware_type.name,
                'model': hardware.model_name or '-',
                'brand': hardware.brand or '-',
                'status': hardware.status,
            })
        
        assignment.is_active = assignment.actual_return_date is None
    
    total_assignments = HardwareAssignment.objects.filter(project=project).count()
    
    # ========== GET BRANCHES ==========
    branches = CustomUser.objects.filter(
        user_type='manager'
    ).values_list('branch_location', flat=True).distinct()
    branches = [b for b in branches if b]
    branches = sorted(set(branches)) or ['Hyderabad', 'Bangalore', 'Mumbai', 'Delhi', 'Chennai', 'Pune', 'Kolkata']
    
    # ========== AUDIT LOG ==========
    create_audit_log(
        request=request,
        user=request.user,
        action="system_info",
        module="Project Management",
        description=f"Super Admin {request.user.username} viewed assignments for project '{project.project_name}' ({active_assignments.count()} active)",
        target_user=request.user,
        target_model="Project",
        target_id=project.id,
        new_value={
            'project': project.project_name,
            'project_id': project.project_id,
            'active_assignments': active_assignments.count(),
            'completed_assignments': completed_assignments,
            'total_hardware': total_hardware_count
        }
    )
    
    context = {
        'project': project,
        'assignments': active_assignments,
        'active_count': active_assignments.count(),
        'completed_count': completed_assignments,
        'total_count': total_assignments,
        'hardware_count': total_hardware_count,
        'show_active_only': True,
        'branches': branches,
    }
    return render(request, 'super_admin/project_assignments.html', context)


# ============================================================
# SUPER ADMIN EXPORT ASSIGNMENTS EXCEL
# ============================================================

@login_required
def super_admin_export_assignments_excel(request, project_id=None):
    """
    Export Employee Wise Hardware Report to Excel with dynamic branch-wise filtering
    With comprehensive audit logging and partial return support
    ✅ FIXED: EXCLUDES returned/closed hardware items entirely from the Excel sheet.
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Unauthorized export attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ========== GET FILTER PARAMETERS ==========
    branch_filter = request.GET.get('branch', '')
    status_filter = request.GET.get('status', '')
    search_query = request.GET.get('search', '')
    client_ip = get_client_ip(request)
    
    # ========== GET ASSIGNMENTS ==========
    if project_id:
        project = get_object_or_404(Project, id=project_id)
        # ✅ ONLY ACTIVE ASSIGNMENTS (NOT CLOSED)
        assignments = HardwareAssignment.objects.filter(
            project=project,
            actual_return_date__isnull=True  # Active only
        ).select_related('employee', 'assigned_by', 'project').order_by('-assigned_date')
        filename_prefix = f"PROJECT_{project.project_id}_HARDWARE_REPORT"
    else:
        project = None
        # ✅ ONLY ACTIVE ASSIGNMENTS (NOT CLOSED)
        assignments = HardwareAssignment.objects.filter(
            actual_return_date__isnull=True  # Active only
        ).select_related('employee', 'assigned_by', 'project').order_by('-assigned_date')
        filename_prefix = "HARDWARE_REPORT"
    
    if not assignments.exists():
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Export Reports",
            description=f"Export attempt by {request.user.username} - No active assignments found",
            target_user=request.user,
            new_value={'project': project.project_name if project else 'All'}
        )
        messages.warning(request, 'No active assignments found to export.')
        if project:
            return redirect('super_admin_project_assignments', project_id=project.id)
        return redirect('super_admin_assignments')
    
    # ========== APPLY FILTERS ==========
    if branch_filter:
        assignments = assignments.filter(
            Q(employee__branch_location=branch_filter) |
            Q(project__location=branch_filter) |
            Q(assigned_by__branch_location=branch_filter)
        )
    
    if search_query:
        assignments = assignments.filter(
            Q(employee__first_name__icontains=search_query) |
            Q(employee__last_name__icontains=search_query) |
            Q(employee__username__icontains=search_query) |
            Q(employee__email__icontains=search_query) |
            Q(project__project_name__icontains=search_query) |
            Q(project__project_id__icontains=search_query) |
            Q(exam_city__icontains=search_query)
        )
    
    if not assignments.exists():
        messages.warning(request, 'No active assignments found matching the filters.')
        if project:
            return redirect('super_admin_project_assignments', project_id=project.id)
        return redirect('super_admin_assignments')
    
    try:
        # ========== CREATE WORKBOOK ==========
        wb = openpyxl.Workbook()
        
        # Define styles
        header_font = Font(bold=True, color="FFFFFF", size=11)
        header_fill = PatternFill(start_color="1a5276", end_color="1a5276", fill_type="solid")
        header_alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        success_fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
        warning_fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
        danger_fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
        info_fill = PatternFill(start_color="DDEBF7", end_color="DDEBF7", fill_type="solid")
        partial_fill = PatternFill(start_color="FFD966", end_color="FFD966", fill_type="solid")
        
        border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )
        center_alignment = Alignment(horizontal='center', vertical='center')
        left_alignment = Alignment(horizontal='left', vertical='center')
        
        # Remove default sheet
        wb.remove(wb.active)
        
        # ========== SHEET 1: EMPLOYEE WISE HARDWARE ==========
        ws = wb.create_sheet("Employee Wise Hardware")
        
        # Define headers (Removed 'Return Status' because we are excluding returned items)
        headers = [
            'Employee Name', 'Email', 'Exam City', 'Exam Center', 'Assignment ID',
            'Hardware Type', 'Asset Number', 'Serial Number', 
            'Model', 'Brand', 'Status', 'Verification'
        ]
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_alignment
            cell.border = border
        
        # ========== DATA ==========
        row_num = 2
        total_hardware = 0
        verified_count = 0
        matched_count = 0
        mismatch_count = 0
        not_entered_count = 0
        
        employee_data = {}
        tracked_assets = set()  # ✅ Track assets to avoid duplicates
        
        for assignment in assignments:
            # ✅ CRITICAL FIX: Exclude Individual Items that are already returned
            items = HardwareAssignmentItem.objects.filter(
                assignment=assignment,
                returned_at__isnull=True  # Only fetch items that are NOT returned
            ).select_related('hardware', 'hardware__hardware_type')
            
            employee_name = assignment.employee.get_full_name() or assignment.employee.username
            employee_email = assignment.employee.email
            exam_city = assignment.exam_city or '-'
            exam_center = getattr(assignment, 'exam_center_name', '-')
            
            if employee_name not in employee_data:
                employee_data[employee_name] = {
                    'email': employee_email,
                    'exam_city': exam_city,
                    'exam_center': exam_center,
                    'hardware_count': 0,
                    'verified_count': 0
                }
            
            for item in items:
                hardware = item.hardware
                asset_number = hardware.asset_number or 'N/A'
                
                # ✅ SKIP if asset is already tracked (avoid duplicates)
                asset_key = f"{asset_number}_{hardware.serial_number}"
                if asset_key in tracked_assets:
                    continue
                tracked_assets.add(asset_key)
                
                total_hardware += 1
                employee_data[employee_name]['hardware_count'] += 1
                
                verification_status = 'Not Entered'
                try:
                    asset_entry = item.asset_entry
                    if asset_entry.verified:
                        verification_status = 'Verified'
                        verified_count += 1
                        employee_data[employee_name]['verified_count'] += 1
                        if asset_entry.entered_asset_number == hardware.asset_number:
                            matched_count += 1
                        else:
                            mismatch_count += 1
                    else:
                        not_entered_count += 1
                except:
                    not_entered_count += 1
                
                row_data = [
                    employee_name,
                    employee_email,
                    exam_city,
                    exam_center,
                    str(assignment.assignment_id)[:12] + '...',
                    hardware.hardware_type.name,
                    asset_number,
                    hardware.serial_number,
                    hardware.model_name or '-',
                    hardware.brand or 'N/A',
                    'In Use' if hardware.status == 'in_use' else hardware.status.title(),
                    verification_status
                ]
                
                for col, value in enumerate(row_data, 1):
                    cell = ws.cell(row=row_num, column=col, value=value)
                    cell.border = border
                    
                    # Status column color coding
                    if col == 11:
                        if value == 'In Use':
                            cell.font = Font(color="006400")
                            cell.fill = PatternFill(start_color="d4edda", end_color="d4edda", fill_type="solid")
                        elif value == 'Assigned':
                            cell.font = Font(color="856404")
                            cell.fill = PatternFill(start_color="fff3cd", end_color="fff3cd", fill_type="solid")
                    
                    # Verification column color coding
                    if col == 12:
                        if value == 'Verified':
                            cell.font = Font(color="006400")
                            cell.fill = PatternFill(start_color="d4edda", end_color="d4edda", fill_type="solid")
                        elif value == 'Not Entered':
                            cell.font = Font(color="721c24")
                            cell.fill = PatternFill(start_color="f8d7da", end_color="f8d7da", fill_type="solid")
                
                row_num += 1
        
        # Auto-adjust column widths
        for col in range(1, len(headers) + 1):
            max_length = len(headers[col-1])
            for row in range(2, row_num):
                cell_value = ws.cell(row=row, column=col).value
                if cell_value:
                    max_length = max(max_length, len(str(cell_value)))
            adjusted_width = min(max_length + 3, 35)
            ws.column_dimensions[get_column_letter(col)].width = adjusted_width
        
        ws.freeze_panes = 'A2'
        
        # ========== SHEET 2: SUMMARY ==========
        ws_summary = wb.create_sheet("Summary")
        
        summary_headers = ['Metric', 'Value']
        for col, header in enumerate(summary_headers, 1):
            cell = ws_summary.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF", size=11)
            cell.fill = PatternFill(start_color="1a5276", end_color="1a5276", fill_type="solid")
            cell.alignment = Alignment(horizontal='center', vertical='center')
            cell.border = border
        
        summary_data = [
            ['Project', project.project_name if project else 'All Projects'],
            ['Project ID', project.project_id if project else 'N/A'],
            ['Branch Filter', branch_filter if branch_filter else 'All Branches'],
            ['Total Active Assignments', assignments.count()],
            ['Total Active Hardware Items (Unique)', total_hardware],
            ['', ''],
            ['✅ Verified', verified_count],
            ['🔄 Matched', matched_count],
            ['❌ Mismatch', mismatch_count],
            ['📝 Not Entered', not_entered_count],
            ['📈 Verification Rate', f"{round((verified_count / total_hardware * 100) if total_hardware > 0 else 0, 1)}%"],
            ['', ''],
            ['Exported By', request.user.get_full_name() or request.user.username],
            ['Export Date', datetime.now().strftime('%d-%m-%Y %H:%M')],
            ['IP Address', client_ip],
        ]
        
        for idx, (key, value) in enumerate(summary_data, 2):
            ws_summary.cell(row=idx, column=1, value=key)
            ws_summary.cell(row=idx, column=2, value=value)
            ws_summary.cell(row=idx, column=1).border = border
            ws_summary.cell(row=idx, column=2).border = border
            
            if 'Rate' in str(key) or 'Percentage' in str(key):
                ws_summary.cell(row=idx, column=2).font = Font(bold=True)
        
        ws_summary.column_dimensions['A'].width = 25
        ws_summary.column_dimensions['B'].width = 30
        
        # ========== SHEET 3: EMPLOYEE SUMMARY ==========
        ws_employee_summary = wb.create_sheet("Employee Summary")
        
        emp_headers = ['Employee Name', 'Email', 'Exam City', 'Exam Center', 'Hardware Count', 'Verified Count']
        for col, header in enumerate(emp_headers, 1):
            cell = ws_employee_summary.cell(row=1, column=col, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal='center', vertical='center')
            cell.border = border
        
        row_num = 2
        for emp_name, data in employee_data.items():
            row_data = [
                emp_name,
                data['email'],
                data['exam_city'],
                data['exam_center'],
                data['hardware_count'],
                data['verified_count']
            ]
            for col, value in enumerate(row_data, 1):
                cell = ws_employee_summary.cell(row=row_num, column=col, value=value)
                cell.border = border
            
            row_num += 1
        
        for col in range(1, len(emp_headers) + 1):
            max_length = len(emp_headers[col-1])
            for row in range(2, row_num):
                cell_value = ws_employee_summary.cell(row=row, column=col).value
                if cell_value:
                    max_length = max(max_length, len(str(cell_value)))
            adjusted_width = min(max_length + 3, 30)
            ws_employee_summary.column_dimensions[get_column_letter(col)].width = adjusted_width
        
        ws_employee_summary.freeze_panes = 'A2'
        
        # ========== SHEET 4: HARDWARE TYPE SUMMARY ==========
        ws_hw_summary = wb.create_sheet("Hardware Type Summary")
        
        hw_headers = ['Hardware Type', 'Total (Active)', 'In Use', 'Assigned']
        for col, header in enumerate(hw_headers, 1):
            cell = ws_hw_summary.cell(row=1, column=col, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal='center', vertical='center')
            cell.border = border
        
        hw_types = {}
        for assignment in assignments:
            items = HardwareAssignmentItem.objects.filter(
                assignment=assignment,
                returned_at__isnull=True  # ✅ Only active items
            ).select_related('hardware', 'hardware__hardware_type')
            for item in items:
                hardware = item.hardware
                hw_type = hardware.hardware_type.name
                
                if hw_type not in hw_types:
                    hw_types[hw_type] = {
                        'total': 0, 
                        'in_use': 0, 
                        'assigned': 0
                    }
                hw_types[hw_type]['total'] += 1
                
                if hardware.status == 'in_use':
                    hw_types[hw_type]['in_use'] += 1
                elif hardware.status == 'assigned':
                    hw_types[hw_type]['assigned'] += 1
        
        row_num = 2
        for hw_type, counts in hw_types.items():
            row_data = [
                hw_type,
                counts['total'],
                counts['in_use'],
                counts['assigned']
            ]
            for col, value in enumerate(row_data, 1):
                cell = ws_hw_summary.cell(row=row_num, column=col, value=value)
                cell.border = border
            row_num += 1
        
        for col in range(1, len(hw_headers) + 1):
            max_length = len(hw_headers[col-1])
            for row in range(2, row_num):
                cell_value = ws_hw_summary.cell(row=row, column=col).value
                if cell_value:
                    max_length = max(max_length, len(str(cell_value)))
            adjusted_width = min(max_length + 3, 20)
            ws_hw_summary.column_dimensions[get_column_letter(col)].width = adjusted_width
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="export_report",
            module="Export Reports",
            description=f"Super Admin {request.user.username} exported active assignments report ({total_hardware} active unique items, {len(employee_data)} employees)",
            target_user=request.user,
            new_value={
                'project': project.project_name if project else 'All Projects',
                'total_active_hardware': total_hardware,
                'employees': len(employee_data),
                'verified': verified_count,
                'matched': matched_count,
                'mismatch': mismatch_count,
                'not_entered': not_entered_count,
                'completion_rate': round((verified_count / total_hardware * 100) if total_hardware > 0 else 0, 1),
                'filters': {
                    'branch': branch_filter or 'All',
                    'status': status_filter or 'All',
                    'search': search_query or 'None'
                },
                'ip': client_ip
            }
        )
        
        # ========== PREPARE RESPONSE ==========
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        branch_suffix = f"_{branch_filter}" if branch_filter else ""
        filename = f"{filename_prefix}{branch_suffix}_{timestamp}.xlsx"
        
        response = HttpResponse(
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        wb.save(response)
        messages.success(request, f'✅ Report exported successfully! ({total_hardware} active unique items)')
        return response
        
    except Exception as e:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_error",
            module="Export Reports",
            description=f"Export failed for {request.user.username}: {str(e)}",
            target_user=request.user,
            new_value={'error': str(e)}
        )
        messages.error(request, f'Error exporting report: {str(e)}')
        if project:
            return redirect('super_admin_project_assignments', project_id=project.id)
        return redirect('super_admin_assignments')
        
# views.py - Updated Super Admin Views with Audit Logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q, Count
from django.core.paginator import Paginator
from hardware_management.utils.audit import create_audit_log, get_client_ip
from .models import (
    CustomUser, Project, HardwareAssignment, EmployeeDeleteRequest,
    EmployeeUpdateRequest, HardwareRequest
)
from hardware_management.utils.email_utils import (
    send_employee_delete_response_email,
    send_employee_update_response_email
)


# ============================================================
# SUPER ADMIN DELETE PROJECT
# ============================================================

@login_required
def super_admin_delete_project(request, project_id):
    """
    Super Admin delete a project
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Project Management",
            description=f"Unauthorized project deletion attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    project = get_object_or_404(Project, id=project_id)
    project_name = project.project_name
    
    # ========== CHECK ACTIVE ASSIGNMENTS ==========
    has_active_assignments = HardwareAssignment.objects.filter(
        project=project,
        actual_return_date__isnull=True
    ).exists()
    
    if has_active_assignments:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Project Management",
            description=f"Project deletion blocked - '{project_name}' has active hardware assignments",
            target_user=request.user,
            target_model="Project",
            target_id=project.id,
            old_value={'status': 'active_assignments'}
        )
        messages.error(
            request,
            f'Cannot delete "{project_name}" - has active hardware assignments!'
        )
        return redirect('super_admin_projects')
    
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        
        # ========== GET PROJECT INFO ==========
        project_info = {
            'project_id': project.project_id,
            'project_name': project.project_name,
            'location': project.location,
            'start_date': project.start_date.isoformat() if project.start_date else None,
            'end_date': project.end_date.isoformat() if project.end_date else None,
            'is_active': project.is_active,
            'created_by': project.created_by.username if project.created_by else None,
        }
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="project_delete",
            module="Project Management",
            description=f"Super Admin {request.user.username} deleted project '{project_name}' ({project.project_id})",
            target_model="Project",
            target_id=project.id,
            old_value=project_info,
            new_value={'deleted': True, 'ip': client_ip}
        )
        
        project.delete()
        messages.success(request, f'✅ Project "{project_name}" deleted successfully!')
        return redirect('super_admin_projects')
    
    # ========== GET REQUEST ==========
    context = {'project': project}
    return render(request, 'super_admin/confirm_delete_project.html', context)


# ============================================================
# SUPER ADMIN VIEW DELETE REQUESTS
# ============================================================

@login_required
def super_admin_delete_requests(request):
    """
    Super Admin view all employee delete requests
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Delete Requests",
            description=f"Unauthorized delete requests view by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    # ========== GET REQUESTS ==========
    delete_requests = EmployeeDeleteRequest.objects.all().select_related(
        'employee', 'requested_by', 'reviewed_by'
    ).order_by('-created_at')
    
    # ========== APPLY FILTERS ==========
    status_filter = request.GET.get('status', '')
    if status_filter:
        delete_requests = delete_requests.filter(status=status_filter)
    
    search_query = request.GET.get('search', '')
    if search_query:
        delete_requests = delete_requests.filter(
            Q(employee__first_name__icontains=search_query) |
            Q(employee__last_name__icontains=search_query) |
            Q(employee__username__icontains=search_query) |
            Q(employee__email__icontains=search_query) |
            Q(requested_by__first_name__icontains=search_query) |
            Q(requested_by__last_name__icontains=search_query) |
            Q(requested_by__username__icontains=search_query)
        )
    
    # ========== STATISTICS ==========
    total = delete_requests.count()
    pending = delete_requests.filter(status='pending').count()
    approved = delete_requests.filter(status='approved').count()
    rejected = delete_requests.filter(status='rejected').count()
    
    # ========== AUDIT LOG ==========
    if request.session.get('last_delete_requests_view', 0) < timezone.now().timestamp() - 300:
        create_audit_log(
            request=request,
            user=request.user,
            action="system_info",
            module="Employee Delete Requests",
            description=f"Super Admin {request.user.username} viewed delete requests ({total} total, {pending} pending)",
            target_user=request.user,
            new_value={
                'total': total,
                'pending': pending,
                'approved': approved,
                'rejected': rejected,
                'filters': {
                    'status': status_filter,
                    'search': search_query
                }
            }
        )
        request.session['last_delete_requests_view'] = timezone.now().timestamp()
    
    # ========== PAGINATION ==========
    paginator = Paginator(delete_requests, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'delete_requests': page_obj,
        'total': total,
        'pending': pending,
        'approved': approved,
        'rejected': rejected,
        'status_filter': status_filter,
        'search_query': search_query,
        'page_obj': page_obj,
        'paginator': paginator,
    }
    return render(request, 'super_admin/delete_requests.html', context)


# ============================================================
# SUPER ADMIN APPROVE DELETE REQUEST
# ============================================================

@login_required
def super_admin_approve_delete_request(request, request_id):
    """
    Super Admin approve employee delete request
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Delete Requests",
            description=f"Unauthorized approve delete attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    delete_request = get_object_or_404(EmployeeDeleteRequest, id=request_id, status='pending')
    employee = delete_request.employee
    employee_name = employee.get_full_name() or employee.username
    employee_email = employee.email
    
    if request.method == 'POST':
        notes = request.POST.get('notes', '').strip()
        client_ip = get_client_ip(request)
        
        # ========== CHECK ACTIVE ASSIGNMENTS ==========
        active_assignments = HardwareAssignment.objects.filter(
            employee=employee,
            actual_return_date__isnull=True
        ).count()
        
        if active_assignments > 0:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Employee Delete Requests",
                description=f"Delete blocked for {employee_name} - {active_assignments} active assignment(s)",
                target_user=employee,
                target_model="EmployeeDeleteRequest",
                target_id=delete_request.id,
                old_value={'active_assignments': active_assignments}
            )
            messages.error(
                request,
                f'Cannot delete - {employee_name} has {active_assignments} active assignment(s).'
            )
            return redirect('super_admin_delete_requests')
        
        # ========== UPDATE REQUEST ==========
        delete_request.status = 'approved'
        delete_request.reviewed_by = request.user
        delete_request.reviewed_at = timezone.now()
        if notes:
            delete_request.notes = notes
        delete_request.save()
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_approve_delete",
            module="Employee Delete Requests",
            description=f"Super Admin {request.user.username} approved deletion of {employee_name} ({employee_email})",
            target_user=employee,
            target_model="EmployeeDeleteRequest",
            target_id=delete_request.id,
            old_value={
                'employee': employee_name,
                'email': employee_email,
                'branch': employee.branch_location,
                'requested_by': delete_request.requested_by.username,
                'status': 'pending'
            },
            new_value={
                'status': 'approved',
                'approved_by': request.user.username,
                'approved_at': timezone.now().isoformat(),
                'notes': notes,
                'ip': client_ip
            }
        )
        
        # ========== DELETE EMPLOYEE ==========
        try:
            employee_info = {
                'name': employee_name,
                'email': employee_email,
                'username': employee.username,
                'branch': employee.branch_location,
                'manager': employee.manager.get_full_name() or employee.manager.username if employee.manager else 'Unassigned'
            }
            
            employee.delete()
            
            # ========== AUDIT LOG - DELETION COMPLETE ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="employee_delete",
                module="User Management",
                description=f"Super Admin {request.user.username} deleted employee {employee_name} via delete request #{delete_request.id}",
                target_model="User",
                target_id=employee.id,
                old_value=employee_info,
                new_value={'deleted': True, 'ip': client_ip}
            )
            
            messages.success(request, f'✅ Employee {employee_name} deleted successfully!')
            
            # ========== SEND EMAIL NOTIFICATION ==========
            try:
                send_employee_delete_response_email(delete_request, 'approved', notes)
                messages.info(request, f'📧 Notification sent to {delete_request.requested_by.email}')
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Employee Delete Requests",
                    description=f"Email notification failed for delete approval: {str(e)}",
                    target_user=delete_request.requested_by,
                    target_model="EmployeeDeleteRequest",
                    target_id=delete_request.id
                )
                messages.warning(request, f'Employee deleted but email notification failed: {str(e)}')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Employee Delete Requests",
                description=f"Error deleting {employee_name}: {str(e)}",
                target_user=employee,
                target_model="EmployeeDeleteRequest",
                target_id=delete_request.id,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Error deleting employee: {str(e)}')
        
        return redirect('super_admin_delete_requests')
    
    # ========== GET REQUEST ==========
    context = {'delete_request': delete_request}
    return render(request, 'super_admin/approve_delete_request.html', context)


# ============================================================
# SUPER ADMIN REJECT DELETE REQUEST
# ============================================================

@login_required
def super_admin_reject_delete_request(request, request_id):
    """
    Super Admin reject employee delete request
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Delete Requests",
            description=f"Unauthorized reject delete attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    delete_request = get_object_or_404(EmployeeDeleteRequest, id=request_id, status='pending')
    employee_name = delete_request.employee.get_full_name() or delete_request.employee.username
    
    if request.method == 'POST':
        notes = request.POST.get('notes', '').strip()
        client_ip = get_client_ip(request)
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_reject_delete",
            module="Employee Delete Requests",
            description=f"Super Admin {request.user.username} rejected deletion request for {employee_name}",
            target_user=delete_request.employee,
            target_model="EmployeeDeleteRequest",
            target_id=delete_request.id,
            old_value={
                'employee': employee_name,
                'requested_by': delete_request.requested_by.username,
                'status': 'pending'
            },
            new_value={
                'status': 'rejected',
                'rejected_by': request.user.username,
                'rejected_at': timezone.now().isoformat(),
                'reason': notes,
                'ip': client_ip
            }
        )
        
        # ========== UPDATE REQUEST ==========
        delete_request.status = 'rejected'
        delete_request.reviewed_by = request.user
        delete_request.reviewed_at = timezone.now()
        if notes:
            delete_request.notes = notes
        delete_request.save()
        
        messages.warning(
            request,
            f'❌ Delete request for {employee_name} rejected.'
        )
        
        # ========== SEND EMAIL NOTIFICATION ==========
        try:
            send_employee_delete_response_email(delete_request, 'rejected', notes)
            messages.info(request, f'📧 Notification sent to {delete_request.requested_by.email}')
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Employee Delete Requests",
                description=f"Email notification failed for delete rejection: {str(e)}",
                target_user=delete_request.requested_by,
                target_model="EmployeeDeleteRequest",
                target_id=delete_request.id
            )
            messages.warning(request, f'Request rejected but email notification failed: {str(e)}')
        
        return redirect('super_admin_delete_requests')
    
    # ========== GET REQUEST ==========
    context = {'delete_request': delete_request}
    return render(request, 'super_admin/reject_delete_request.html', context)


# ============================================================
# SUPER ADMIN DELETE UPDATE REQUEST (Previously in employee views)
# ============================================================

@login_required
def super_admin_delete_update_request(request, request_id):
    """
    Super Admin delete an employee update request
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Update Requests",
            description=f"Unauthorized update request deletion attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    update_request = get_object_or_404(EmployeeUpdateRequest, id=request_id)
    employee_name = update_request.employee.get_full_name() or update_request.employee.username
    
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_reject_update",
            module="Employee Update Requests",
            description=f"Super Admin {request.user.username} deleted update request #{request_id} for {employee_name}",
            target_user=update_request.employee,
            target_model="EmployeeUpdateRequest",
            target_id=update_request.id,
            old_value={
                'field': update_request.field_updated,
                'proposed_value': update_request.proposed_value,
                'requested_by': update_request.requested_by.username,
                'status': update_request.status
            },
            new_value={'deleted': True, 'ip': client_ip}
        )
        
        update_request.delete()
        messages.success(request, f'✅ Update request #{request_id} for {employee_name} deleted successfully!')
        return redirect('super_admin_update_requests')
    
    # ========== GET REQUEST ==========
    context = {'update_request': update_request}
    return render(request, 'super_admin/delete_update_request.html', context)


# ============================================================
# SUPER ADMIN APPROVE UPDATE REQUEST (Previously in employee views)
# ============================================================

@login_required
def super_admin_approve_update_request(request, request_id):
    """
    Super Admin approve employee update request
    With comprehensive audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Update Requests",
            description=f"Unauthorized approve update attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    update_request = get_object_or_404(EmployeeUpdateRequest, id=request_id, status='pending')
    employee = update_request.employee
    employee_name = employee.get_full_name() or employee.username
    old_value = update_request.current_value
    proposed_value = update_request.proposed_value
    field_updated = update_request.field_updated
    
    if request.method == 'POST':
        notes = request.POST.get('notes', '').strip()
        client_ip = get_client_ip(request)
        
        # ========== AUDIT LOG - BEFORE UPDATE ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_approve_update",
            module="Employee Update Requests",
            description=f"Super Admin {request.user.username} approved update request #{update_request.id} for {employee_name} - {field_updated}: '{old_value}' → '{proposed_value}'",
            target_user=employee,
            target_model="EmployeeUpdateRequest",
            target_id=update_request.id,
            old_value=old_value,
            new_value=proposed_value
        )
        
        try:
            # ========== APPLY UPDATE ==========
            if field_updated == 'name':
                name_parts = proposed_value.strip().split(' ', 1)
                employee.first_name = name_parts[0]
                employee.last_name = name_parts[1] if len(name_parts) > 1 else ''
            
            elif field_updated == 'email':
                if CustomUser.objects.filter(email=proposed_value).exclude(id=employee.id).exists():
                    messages.error(request, f'Email "{proposed_value}" already exists!')
                    return redirect('super_admin_update_requests')
                employee.email = proposed_value
            
            elif field_updated == 'phone':
                employee.phone = proposed_value
            
            elif field_updated == 'branch':
                employee.branch_location = proposed_value
            
            elif field_updated == 'manager':
                try:
                    manager = CustomUser.objects.get(
                        username__iexact=proposed_value,
                        user_type='manager',
                        is_active=True
                    )
                    employee.manager = manager
                except CustomUser.DoesNotExist:
                    create_audit_log(
                        request=request,
                        user=request.user,
                        action="system_warning",
                        module="Employee Update Requests",
                        description=f"Manager '{proposed_value}' not found for update request #{update_request.id}",
                        target_user=employee,
                        target_model="EmployeeUpdateRequest",
                        target_id=update_request.id
                    )
                    messages.error(request, f'Manager "{proposed_value}" not found. Request rejected.')
                    return redirect('super_admin_update_requests')
            
            elif field_updated == 'multiple':
                messages.warning(request, 'Multiple field updates require manual processing.')
            
            employee.save()
            
            # ========== UPDATE REQUEST ==========
            update_request.status = 'approved'
            update_request.reviewed_by = request.user
            update_request.reviewed_at = timezone.now()
            if notes:
                update_request.notes = notes
            update_request.save()
            
            # ========== AUDIT LOG - AFTER UPDATE ==========
            create_audit_log(
                request=request,
                user=request.user,
                action="employee_update",
                module="User Management",
                description=f"Super Admin {request.user.username} updated {employee_name}: {field_updated} changed",
                target_user=employee,
                target_model="User",
                target_id=employee.id,
                old_value=old_value,
                new_value=proposed_value,
                new_value_extra={'ip': client_ip}
            )
            
            messages.success(
                request,
                f'✅ Update request approved! {employee_name} updated successfully.'
            )
            
            # ========== SEND EMAIL NOTIFICATION ==========
            try:
                from hardware_management.utils.email_utils import send_employee_update_response_email
                send_employee_update_response_email(update_request, 'approved', notes)
                messages.info(request, f'📧 Notification sent to {update_request.requested_by.email}')
            except Exception as e:
                create_audit_log(
                    request=request,
                    user=request.user,
                    action="system_warning",
                    module="Employee Update Requests",
                    description=f"Email notification failed for update request #{update_request.id}: {str(e)}",
                    target_user=update_request.requested_by,
                    target_model="EmployeeUpdateRequest",
                    target_id=update_request.id
                )
                messages.warning(request, f'Update approved but email notification failed: {str(e)}')
            
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_error",
                module="Employee Update Requests",
                description=f"Error applying update for {employee_name}: {str(e)}",
                target_user=employee,
                target_model="EmployeeUpdateRequest",
                target_id=update_request.id,
                new_value={'error': str(e)}
            )
            messages.error(request, f'Error updating employee: {str(e)}')
        
        return redirect('super_admin_update_requests')
    
    # ========== GET REQUEST ==========
    context = {'update_request': update_request}
    return render(request, 'super_admin/approve_update_request.html', context)


# ============================================================
# SUPER ADMIN REJECT UPDATE REQUEST (Previously in employee views)
# ============================================================

@login_required
def super_admin_reject_update_request(request, request_id):
    """
    Super Admin reject employee update request
    With audit logging
    """
    
    # ========== AUTHORIZATION CHECK ==========
    if request.user.user_type != 'super_admin':
        create_audit_log(
            request=request,
            user=request.user,
            action="system_warning",
            module="Employee Update Requests",
            description=f"Unauthorized reject update attempt by {request.user.username}",
            target_user=request.user
        )
        return redirect('login')
    
    update_request = get_object_or_404(EmployeeUpdateRequest, id=request_id, status='pending')
    employee_name = update_request.employee.get_full_name() or update_request.employee.username
    
    if request.method == 'POST':
        notes = request.POST.get('notes', '').strip()
        client_ip = get_client_ip(request)
        
        # ========== AUDIT LOG ==========
        create_audit_log(
            request=request,
            user=request.user,
            action="employee_reject_update",
            module="Employee Update Requests",
            description=f"Super Admin {request.user.username} rejected update request #{update_request.id} for {employee_name} - {update_request.field_updated}: '{update_request.proposed_value}'",
            target_user=update_request.employee,
            target_model="EmployeeUpdateRequest",
            target_id=update_request.id,
            old_value={
                'field': update_request.field_updated,
                'proposed_value': update_request.proposed_value,
                'requested_by': update_request.requested_by.username,
                'status': 'pending'
            },
            new_value={
                'status': 'rejected',
                'rejected_by': request.user.username,
                'rejected_at': timezone.now().isoformat(),
                'reason': notes,
                'ip': client_ip
            }
        )
        
        # ========== UPDATE REQUEST ==========
        update_request.status = 'rejected'
        update_request.reviewed_by = request.user
        update_request.reviewed_at = timezone.now()
        if notes:
            update_request.notes = notes
        update_request.save()
        
        messages.warning(
            request,
            f'❌ Update request for {employee_name} rejected.'
        )
        
        # ========== SEND EMAIL NOTIFICATION ==========
        try:
            from hardware_management.utils.email_utils import send_employee_update_response_email
            send_employee_update_response_email(update_request, 'rejected', notes)
            messages.info(request, f'📧 Notification sent to {update_request.requested_by.email}')
        except Exception as e:
            create_audit_log(
                request=request,
                user=request.user,
                action="system_warning",
                module="Employee Update Requests",
                description=f"Email notification failed for rejection: {str(e)}",
                target_user=update_request.requested_by,
                target_model="EmployeeUpdateRequest",
                target_id=update_request.id
            )
            messages.warning(request, f'Request rejected but email notification failed: {str(e)}')
        
        return redirect('super_admin_update_requests')
    
    # ========== GET REQUEST ==========
    context = {'update_request': update_request}
    return render(request, 'super_admin/reject_update_request.html', context)


