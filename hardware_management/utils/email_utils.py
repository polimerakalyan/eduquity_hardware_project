# hardware_management/utils/email_utils.py

from datetime import date, timezone
from email.policy import default
from turtle import title

from django.core.mail import send_mail
from django.db.models.functions import Length
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib.auth import get_user_model
from django.urls import reverse

User = get_user_model()

def get_super_admins():
    """Get all super admin users"""
    return User.objects.filter(user_type='super_admin', is_active=True)

def get_base_url():
    """Get base URL from settings or use default"""
    return getattr(settings, 'BASE_URL', 'http://127.0.0.1:8000')


# ============================================================
# SEND EXTRA HARDWARE EMAIL (Added from views.py)
# ============================================================
def send_extra_hardware_email(assignment, added_hardware, notes):
    """
    Send email notification to employee about extra hardware added
    Uses Django template rendering for HTML emails.
    """
    from django.core.mail import send_mail
    from django.conf import settings
    from django.template.loader import render_to_string

    employee = assignment.employee
    manager = assignment.assigned_by

    employee_name = employee.get_full_name() or employee.username
    manager_name = manager.get_full_name() or manager.username

    subject = f'📦 Extra Hardware Added - Assignment {assignment.assignment_id}'

    # ========== 🔥 FORCE HTML EMAIL (Remove try/except to see errors) ==========
    # If this path is wrong, Django will throw a TemplateDoesNotExist error.
    # This guarantees the email WILL NOT send as plain text.
    html_message = render_to_string('emails/extra_hardware_added.html', {
        'assignment': assignment,
        'employee': employee,
        'manager': manager,
        'added_items': added_hardware,
        'notes': notes,
    })

    # ========== PLAIN TEXT FALLBACK ==========
    hardware_list_text = ''
    for idx, hw in enumerate(added_hardware, 1):
        hardware_list_text += f"{idx}. {hw['type']} - Asset: {hw['asset_number']} | Serial: {hw['serial_number']}\n"

    plain_message = f"""
    EXTRA HARDWARE ADDED TO ASSIGNMENT
    ==================================

    Dear {employee_name},

    Assignment Updated! Additional hardware has been added to your assignment by {manager_name}.

    Assignment Information:
    -----------------------
    Assignment ID: {assignment.assignment_id}
    Project: {assignment.project.project_name}
    Exam City: {assignment.exam_city or 'Not specified'}
    Expected Return: {assignment.expected_return_date.strftime('%d %B %Y')}
    Added By: {manager_name}

    Extra Hardware Items Added:
    ---------------------------
    {hardware_list_text}

    Total Added: {len(added_hardware)}

    {f'Manager Notes: {notes}' if notes else ''}

    Next Steps:
    -----------
    1. Go to the Eduquity Hardware Portal
    2. Navigate to "My Assignments" section
    3. Click "Enter Asset" to input the Asset Numbers for the new hardware
    4. Your manager will verify the new entries

    ---
    Eduquity Hardware Management Team
    """

    # ========== SEND EMAIL ==========
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[employee.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending extra hardware email: {e}")
        # Re-raise the error so you can see it in your terminal
        raise

# ============================================================
# SEND REQUEST NOTIFICATION
# ============================================================
def send_request_notification(request, hw_request, request_type):
    """
    Send email notification to all Super Admins about a new request
    """
    super_admins = get_super_admins()
    
    if not super_admins.exists():
        return False
    
    # Build absolute URLs using the request if available
    if request:
        admin_url = request.build_absolute_uri(reverse('super_admin_requests'))
        approve_url = request.build_absolute_uri(reverse('super_admin_approve_request', args=[hw_request.id]))
        reject_url = request.build_absolute_uri(reverse('super_admin_reject_request', args=[hw_request.id]))
    else:
        base_url = get_base_url()
        admin_url = base_url + reverse('super_admin_requests')
        approve_url = base_url + reverse('super_admin_approve_request', args=[hw_request.id])
        reject_url = base_url + reverse('super_admin_reject_request', args=[hw_request.id])
    
    # Prepare email context
    context = {
        'request': hw_request,
        'request_type': request_type,
        'hardware': hw_request.hardware,
        'requested_by': hw_request.requested_by,
        'request_id': hw_request.id,
        'reason': hw_request.reason,
        'created_at': hw_request.created_at,
        'admin_url': admin_url,
        'approve_url': approve_url,
        'reject_url': reject_url,
    }
    
    subject = f"🔔 New {request_type.capitalize()} Request - {hw_request.hardware.asset_number}"
    
    try:
        html_message = render_to_string('emails/request_notification.html', context)
        plain_message = render_to_string('emails/request_notification.txt', context)
    except Exception:
        # Fallback
        plain_message = f"""
        New {request_type} Request
        
        Request ID: #{hw_request.id}
        Hardware: {hw_request.hardware.asset_number}
        Requested By: {hw_request.requested_by.get_full_name() or hw_request.requested_by.username}
        Reason: {hw_request.reason}
        
        Please login to review this request:
        {admin_url}
        """
        html_message = None
    
    # Send to all Super Admins
    recipient_list = [admin.email for admin in super_admins if admin.email]
    
    if recipient_list:
        try:
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipient_list,
                html_message=html_message,
                fail_silently=False,
            )
            return True
        except Exception as e:
            print(f"Error sending email: {e}")
            return False
    
    return False


# ============================================================
# SEND RESPONSE NOTIFICATION
# ============================================================
def send_response_notification(request, hw_request, action, notes=None):
    """
    Send email notification to the manager about the response to their request
    """
    manager = hw_request.requested_by
    
    if not manager.email:
        return False
    
    if request:
        manage_url = request.build_absolute_uri(reverse('manage_hardware'))
    else:
        base_url = get_base_url()
        manage_url = base_url + reverse('manage_hardware')
    
    context = {
        'request': hw_request,
        'action': action,
        'hardware': hw_request.hardware,
        'manager': manager,
        'reviewed_by': hw_request.reviewed_by,
        'reviewed_at': hw_request.reviewed_at,
        'request_id': hw_request.id,
        'reason': hw_request.reason,
        'notes': notes or hw_request.notes,
        'manage_url': manage_url,
    }
    
    if action == 'approved':
        subject = f"✅ Your hardware request was approved - {hw_request.hardware.asset_number}"
    else:
        subject = f"❌ Your hardware request was rejected - {hw_request.hardware.asset_number}"
    
    try:
        html_message = render_to_string('emails/response_notification.html', context)
        plain_message = render_to_string('emails/response_notification.txt', context)
    except Exception:
        plain_message = f"""
        {action.upper()} - Hardware Request Response
        
        Request ID: #{hw_request.id}
        Hardware: {hw_request.hardware.asset_number}
        Request Type: {hw_request.get_request_type_display()}
        Status: {action.upper()}
        
        Reason: {hw_request.reason}
        {f'Admin Notes: {notes or hw_request.notes}' if (notes or hw_request.notes) else ''}
        
        Please login to view your hardware inventory:
        {manage_url}
        """
        html_message = None
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[manager.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending response email: {e}")
        return False


# ============================================================
# EMPLOYEE DELETE REQUEST EMAILS
# ============================================================
def send_employee_delete_request_email(delete_request):
    """
    Send email notification to Super Admin about new employee delete request
    """
    super_admins = User.objects.filter(user_type='super_admin', is_active=True)
    
    if not super_admins.exists():
        return False
    
    base_url = get_base_url()
    admin_url = base_url + reverse('super_admin_delete_requests')
    approve_url = base_url + reverse('super_admin_approve_delete_request', args=[delete_request.id])
    reject_url = base_url + reverse('super_admin_reject_delete_request', args=[delete_request.id])
    
    context = {
        'delete_request': delete_request,
        'employee': delete_request.employee,
        'requested_by': delete_request.requested_by,
        'reason': delete_request.reason,
        'created_at': delete_request.created_at,
        'admin_url': admin_url,
        'approve_url': approve_url,
        'reject_url': reject_url,
    }
    
    subject = f"🔔 New Employee Delete Request - {delete_request.employee.get_full_name() or delete_request.employee.username}"
    
    try:
        html_message = render_to_string('emails/employee_delete_request.html', context)
        plain_message = render_to_string('emails/employee_delete_request.txt', context)
    except Exception:
        plain_message = f"""
        New Employee Delete Request
        
        Employee: {delete_request.employee.get_full_name() or delete_request.employee.username}
        Requested By: {delete_request.requested_by.get_full_name() or delete_request.requested_by.username}
        Reason: {delete_request.reason}
        
        Please login to review this request:
        {admin_url}
        """
        html_message = None
    
    recipient_list = [admin.email for admin in super_admins if admin.email]
    
    if recipient_list:
        try:
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipient_list,
                html_message=html_message,
                fail_silently=False,
            )
            return True
        except Exception as e:
            print(f"Error sending email: {e}")
            return False
    
    return False


def send_employee_delete_response_email(delete_request, action, notes=None):
    """
    Send email notification to manager about the response to delete request
    """
    manager = delete_request.requested_by
    employee = delete_request.employee
    
    if not manager.email:
        return False
    
    base_url = get_base_url()
    employee_list_url = base_url + reverse('employee_list')
    
    context = {
        'delete_request': delete_request,
        'employee': employee,
        'manager': manager,
        'action': action,
        'notes': notes or delete_request.notes,
        'reviewed_by': delete_request.reviewed_by,
        'reviewed_at': delete_request.reviewed_at,
        'employee_list_url': employee_list_url,
    }
    
    if action == 'approved':
        subject = f"✅ Employee Delete Request Approved - {employee.get_full_name() or employee.username}"
    else:
        subject = f"❌ Employee Delete Request Rejected - {employee.get_full_name() or employee.username}"
    
    try:
        html_message = render_to_string('emails/employee_delete_response.html', context)
        plain_message = render_to_string('emails/employee_delete_response.txt', context)
    except Exception:
        plain_message = f"""
        Employee Delete Request {action.upper()}
        
        Employee: {employee.get_full_name() or employee.username}
        Status: {action.upper()}
        {f'Notes: {notes or delete_request.notes}' if (notes or delete_request.notes) else ''}
        
        Please login to view your employees:
        {employee_list_url}
        """
        html_message = None
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[manager.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending response email: {e}")
        return False


# ============================================================
# EMPLOYEE UPDATE REQUEST EMAILS
# ============================================================
def send_employee_update_request_email(update_request):
    """
    Send email notification to Super Admin about new employee update request
    """
    super_admins = User.objects.filter(user_type='super_admin', is_active=True)
    
    if not super_admins.exists():
        return False
    
    base_url = get_base_url()
    admin_url = base_url + reverse('super_admin_update_requests')
    approve_url = base_url + reverse('super_admin_approve_update_request', args=[update_request.id])
    reject_url = base_url + reverse('super_admin_reject_update_request', args=[update_request.id])
    
    context = {
        'update_request': update_request,
        'employee': update_request.employee,
        'requested_by': update_request.requested_by,
        'field_updated': update_request.get_field_updated_display(),
        'current_value': update_request.current_value or 'Not set',
        'proposed_value': update_request.proposed_value,
        'reason': update_request.reason,
        'created_at': update_request.created_at,
        'admin_url': admin_url,
        'approve_url': approve_url,
        'reject_url': reject_url,
    }
    
    subject = f"🔔 New Employee Update Request - {update_request.employee.get_full_name() or update_request.employee.username}"
    
    try:
        html_message = render_to_string('emails/employee_update_request.html', context)
        plain_message = render_to_string('emails/employee_update_request.txt', context)
    except Exception:
        plain_message = f"""
        New Employee Update Request
        
        Employee: {update_request.employee.get_full_name() or update_request.employee.username}
        Requested By: {update_request.requested_by.get_full_name() or update_request.requested_by.username}
        Field to Update: {update_request.get_field_updated_display()}
        Proposed Value: {update_request.proposed_value}
        Reason: {update_request.reason}
        
        Please login to review this request:
        {admin_url}
        """
        html_message = None
    
    recipient_list = [admin.email for admin in super_admins if admin.email]
    
    if recipient_list:
        try:
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipient_list,
                html_message=html_message,
                fail_silently=False,
            )
            return True
        except Exception as e:
            print(f"Error sending email: {e}")
            return False
    
    return False


def send_employee_update_response_email(update_request, action, notes=None):
    """
    Send email notification to manager about the response to update request
    """
    manager = update_request.requested_by
    employee = update_request.employee
    
    if not manager.email:
        return False
    
    base_url = get_base_url()
    employee_list_url = base_url + reverse('employee_list')
    
    context = {
        'update_request': update_request,
        'employee': employee,
        'manager': manager,
        'action': action,
        'notes': notes or update_request.notes,
        'reviewed_by': update_request.reviewed_by,
        'reviewed_at': update_request.reviewed_at,
        'employee_list_url': employee_list_url,
    }
    
    if action == 'approved':
        subject = f"✅ Employee Update Request Approved - {employee.get_full_name() or employee.username}"
    else:
        subject = f"❌ Employee Update Request Rejected - {employee.get_full_name() or employee.username}"
    
    try:
        html_message = render_to_string('emails/employee_update_response.html', context)
        plain_message = render_to_string('emails/employee_update_response.txt', context)
    except Exception:
        plain_message = f"""
        Employee Update Request {action.upper()}
        
        Employee: {employee.get_full_name() or employee.username}
        Field: {update_request.get_field_updated_display()}
        Status: {action.upper()}
        {f'Notes: {notes or update_request.notes}' if (notes or update_request.notes) else ''}
        
        Please login to view your employees:
        {employee_list_url}
        """
        html_message = None
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[manager.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending response email: {e}")
        return False


# ============================================================
# BULK WELCOME EMAIL
# ============================================================
def send_bulk_welcome_emails(employees, admin, branch, manager=None):
    """
    Send welcome emails to multiple employees with default password
    """
    default_password = getattr(settings, 'DEFAULT_PASSWORD', 'Eduquity@2024')
    manager_name = manager.get_full_name() or manager.username if manager else 'Not Assigned'
    
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
1. Use the password above to login
2. Keep your credentials secure
3. Do not share your password with anyone

Best regards,
Eduquity Hardware Management Team
                ''',
                html_message=f'''
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
                <h3>Your Login Credentials:</h3>
                <p><strong>Full Name:</strong> {name}</p>
                <p><strong>Username:</strong> {username}</p>
                <p><strong>Password:</strong> <code style="background: #fff; padding: 5px 10px; border-radius: 3px; font-size: 14px;">{default_password}</code></p>
                <p><strong>Branch:</strong> {branch}</p>
                <p><strong>Manager:</strong> {manager_name}</p>
                <p><strong>Login URL:</strong> <a href="http://eduquityinventory.co.in/login/">http://eduquityinventory.co.in/login/</a></p>
                <a href="http://eduquityinventory.co.in/login/" class="btn">Login Now</a>
            </div>
            
            <p><strong>About the System:</strong><br>
            The Eduquity Hardware Management System allows you to:
            <ul>
                <li>View your hardware assignments</li>
                <li>Enter serial numbers of assigned hardware</li>
                <li>Track hardware status</li>
                <li>Communicate with your manager</li>
            </ul>
            </p>
            
            <div class="footer">
                <p><strong>Eduquity Hardware Management Team</strong><br>
                Established in 2000 - Thought-leader in the Indian assessment industry</p>
                <p><em>This is an automated email. Please do not reply to this message.</em></p>
            </div>
        </div>
    </div>
</body>
</html>
                ''',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=True,
            )
        except Exception as e:
            print(f"Failed to send email to {emp.get('email', 'unknown')}: {str(e)}")


# ============================================================
# SEND ASSIGNMENT EMAIL
# ============================================================
def send_assignment_email(assignment, employee, project, hardware_details):
    """
    Send assignment details email to employee
    """
    from django.core.mail import send_mail
    from django.conf import settings
    from urllib.parse import urljoin
    from django.utils import timezone
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
        employee_name = str(employee.get_full_name() or employee.username)
        manager_name = str(assignment.assigned_by.get_full_name() or assignment.assigned_by.username)
        base_url = getattr(settings, 'BASE_URL', 'http://127.0.0.1:8000')
        
        # Build hardware list
        hardware_list_html = ''
        hardware_list_text = ''
        for idx, hw in enumerate(hardware_details, 1):
            hw_type = str(hw.get('type', 'Unknown'))
            asset_number = str(hw.get('asset_number', 'N/A'))
            
            hardware_list_html += f"""
                <tr>
                    <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{idx}</td>
                    <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><strong>{hw_type}</strong></td>
                    <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{asset_number}</code></td>
                </tr>
            """
            hardware_list_text += f"{idx}. {hw_type} - Asset: {asset_number}\n"
        
        subject = f'Hardware Assignment - {str(project.project_name)} - {str(assignment.assignment_id)}'
        
        # Dates
        exam_city = str(getattr(assignment, 'exam_city', 'Not specified') or 'Not specified')
        exam_center_name = str(getattr(assignment, 'exam_center_name', 'Not specified') or 'Not specified')
        
        assigned_date_val = assignment.assigned_date
        if hasattr(assigned_date_val, 'strftime'):
            assigned_date = timezone.localtime(assigned_date_val).strftime('%d %B %Y')
        else:
            assigned_date = str(assigned_date_val or 'N/A')
            
        expected_return_date_val = assignment.expected_return_date
        if hasattr(expected_return_date_val, 'strftime'):
            expected_return_date = expected_return_date_val.strftime('%d %B %Y')
        else:
            expected_return_date = str(expected_return_date_val or 'N/A')
        
        # HTML Message
        html_message = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(90deg, #2c3e50 0%, #3498db 100%); color: white; padding: 25px; text-align: center; border-radius: 8px 8px 0 0; }}
                .header h2 {{ margin: 0; font-weight: 300; }}
                .content {{ background: #ffffff; padding: 30px; border: 1px solid #e9ecef; border-top: none; border-radius: 0 0 8px 8px; }}
                .info-box {{ background: #f8f9fa; padding: 15px 20px; margin: 15px 0; border-radius: 6px; border-left: 4px solid #3498db; }}
                .info-box h6 {{ margin: 0 0 5px 0; color: #495057; }}
                .table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 14px; }}
                .table th {{ background: #2c3e50; color: white; padding: 10px 12px; text-align: left; }}
                .table td {{ padding: 10px 12px; border-bottom: 1px solid #e9ecef; }}
                .table tr:hover {{ background: #f8f9fa; }}
                .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
                .badge-success {{ background: #28a745; color: white; }}
                .badge-primary {{ background: #3498db; color: white; }}
                .badge-warning {{ background: #ffc107; color: #212529; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px; text-align: center; }}
                .btn {{ display: inline-block; padding: 10px 24px; background: linear-gradient(90deg, #2c3e50 0%, #3498db 100%); color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
                .btn:hover {{ opacity: 0.9; }}
                .alert {{ padding: 12px 16px; border-radius: 6px; margin: 10px 0; }}
                .alert-info {{ background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }}
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
                    <h2>📋 Hardware Assignment Notification</h2>
                </div>
                <div class="content">
                    <p>Dear <strong>{employee_name}</strong>,</p>
                    
                    <p>You have been assigned hardware for the upcoming examination. Please review the details below.</p>
                    
                    <div class="info-box">
                        <h6>📌 Assignment Information</h6>
                        <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                            <tr>
                                <td style="padding: 4px 0; width: 35%;"><strong>Assignment ID:</strong></td>
                                <td style="padding: 4px 0;"><code>{str(assignment.assignment_id)}</code></td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Project:</strong></td>
                                <td style="padding: 4px 0;">{str(project.project_name)} ({str(project.project_id)})</td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Exam City:</strong></td>
                                <td style="padding: 4px 0;"><span class="badge badge-success">{exam_city}</span></td>
                            </tr>
                            <tr>
                                <td style="padding: 4px 0;"><strong>Exam Center:</strong></td>
                                <td style="padding: 4px 0;"><span class="badge badge-primary">{exam_center_name}</span></td>
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
                                <td style="padding: 4px 0;"><strong>Assigned By:</strong></td>
                                <td style="padding: 4px 0;">{manager_name}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <h6 style="margin-top: 20px; margin-bottom: 10px;">🖥️ Assigned Hardware Items</h6>
                    <div style="overflow-x: auto;">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th style="width: 40px;">#</th>
                                    <th>Hardware Type</th>
                                    <th>Asset Number</th>
                                </tr>
                            </thead>
                            <tbody>
                                {hardware_list_html}
                            </tbody>
                        </table>
                    </div>
                    <p style="margin: 10px 0;"><span class="badge badge-primary">Total Items: {len(hardware_details)}</span></p>
                    
                    <div class="alert alert-info">
                        <strong>📌 Next Steps:</strong>
                        <ol style="margin: 8px 0 0 20px;">
                            <li>Go to the <a href="{urljoin(base_url, '/')}" style="color: #3498db; text-decoration: none; font-weight: 600;">Eduquity Hardware Portal</a></li>
                            <li>Navigate to <strong>"My Assignments"</strong> section</li>
                            <li>Click <strong>"Enter Asset"</strong> to input the Asset Numbers from your physical devices</li>
                            <li>Your manager will verify the entries</li>
                        </ol>
                    </div>
                    
                    <div class="alert alert-warning">
                        <strong>⚠️ Important Instructions:</strong>
                        <ul style="margin: 8px 0 0 20px;">
                            <li>Asset Numbers must be entered accurately from the physical devices</li>
                            <li>Asset Number is the primary identifier for verification</li>
                            <li>Keep the hardware safe and in good condition</li>
                            <li>Return all hardware before the due date: <strong>{expected_return_date}</strong></li>
                            <li><strong>Bring hardware to {exam_center_name} ({exam_city}) for the exam</strong></li>
                        </ul>
                    </div>
                    
                    <p style="margin-top: 20px;">
                        <a href="{urljoin(base_url, '/')}" class="btn">🚀 Go to Hardware Portal</a>
                    </p>
                    
                    <div class="footer">
                        <p><strong>Eduquity Hardware Management Team</strong><br>
                        Established in 2000 - Thought-leader in the Indian assessment industry</p>
                        <p><em>This is an automated email. Please do not reply to this message.</em></p>
                        <p style="font-size: 11px;">If you have any issues, please contact your manager: {manager_name}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain Text
        plain_message = f"""
        HARDWARE ASSIGNMENT NOTIFICATION
        ================================
        
        Dear {employee_name},
        
        You have been assigned hardware for the upcoming examination.
        
        Assignment Information:
        -----------------------
        Assignment ID: {str(assignment.assignment_id)}
        Project: {str(project.project_name)} ({str(project.project_id)})
        Exam City: {exam_city}
        Exam Center: {exam_center_name}
        Assigned Date: {assigned_date}
        Expected Return: {expected_return_date}
        Assigned By: {manager_name}
        
        Assigned Hardware Items:
        -----------------------
        {hardware_list_text}
        
        Total Items: {len(hardware_details)}
        
        Next Steps:
        ----------
        1. Go to the Eduquity Hardware Portal
        2. Navigate to "My Assignments" section
        3. Click "Enter Asset" to input the Asset Numbers from your physical devices
        4. Your manager will verify the entries
        
        Important Instructions:
        -----------------------
        - Asset Numbers must be entered accurately from the physical devices
        - Asset Number is the primary identifier for verification
        - Keep the hardware safe and in good condition
        - Return all hardware before the due date: {expected_return_date}
        - Bring hardware to {exam_center_name} ({exam_city}) for the exam
        
        If you have any issues, please contact your manager: {manager_name}
        
        ---
        Eduquity Hardware Management Team
        """
        
        if not employee.email:
            logger.error(f"No email address for {employee_name}")
            return False
        
        # Prevent sending to self
        if employee.email == settings.EMAIL_HOST_USER:
            print(f"\n===== EMAIL PREVIEW (Skipping Self-Delivery) =====")
            print(f"To: {employee.email}")
            print("---------------------------------------------------")
            print(plain_message)
            print("===================================================\n")
            return True

        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[employee.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
        
    except Exception as e:
        error_msg = f"Email sending failed: {str(e)}"
        print(f"\n❌ ERROR: {error_msg}\n")
        logger.error(error_msg)
        return False


# ============================================================
# TRANSFER APPROVAL & REJECTION EMAILS (Sender & Receiver)
# ============================================================
def send_transfer_approval_email_to_sender(transfer, super_admin):
    """
    Send email to sender notifying them that the transfer is approved
    """
    from_employee = transfer.from_employee
    to_employee = transfer.to_employee
    admin_name = super_admin.get_full_name() or super_admin.username
    
    from_name = from_employee.get_full_name() or from_employee.username
    to_name = to_employee.get_full_name() or to_employee.username
    
    transfer_type_display = 'Temporary' if transfer.transfer_type == 'temporary' else 'Permanent'
    transfer_type_badge = 'badge-warning' if transfer.transfer_type == 'temporary' else 'badge-primary'
    requested_date_formatted = transfer.requested_date.strftime('%d %B %Y at %I:%M %p') if transfer.requested_date else 'N/A'
    approved_date_formatted = timezone.now().strftime('%d %B %Y at %I:%M %p')
    from_branch_display = transfer.from_branch or 'Not Assigned'
    to_branch_display = transfer.to_branch or 'Not Assigned'
    to_city_display = transfer.to_exam_city or 'Not specified'
    expected_arrival_display = transfer.expected_arrival_date.strftime('%d %B %Y') if transfer.expected_arrival_date else 'Not specified'
    
    hardware_list = []
    for item in transfer.transfer_items.all().select_related('hardware__hardware_type'):
        hardware_list.append({
            'type': item.hardware.hardware_type.name,
            'asset_number': item.hardware.asset_number or 'N/A',
            'serial_number': item.hardware.serial_number,
            'model': item.hardware.model_name or 'N/A',
            'brand': item.hardware.brand or 'N/A'
        })
    
    hardware_list_html = ''
    hardware_list_text = ''
    for idx, hw in enumerate(hardware_list, 1):
        hardware_list_html += f"""
        <tr>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{idx}</td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><strong>{hw['type']}</strong></td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{hw['asset_number']}</code></td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{hw['serial_number']}</code></td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{hw['model']}</td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{hw['brand']}</td>
        </tr>
        """
        hardware_list_text += f"{idx}. {hw['type']} - Asset: {hw['asset_number']} | Serial: {hw['serial_number']} | Model: {hw['model']}\n"
    
    subject = f'✅ Transfer Approved - Please Initiate Transfer #{transfer.transfer_id}'
    
    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #28a745; color: white; padding: 25px; text-align: center; border-radius: 8px 8px 0 0; }}
            .header h2 {{ margin: 0; font-weight: 300; }}
            .content {{ background: #ffffff; padding: 30px; border: 1px solid #e9ecef; border-top: none; border-radius: 0 0 8px 8px; }}
            .info-box {{ background: #f8f9fa; padding: 15px 20px; margin: 15px 0; border-radius: 6px; border-left: 4px solid #28a745; }}
            .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
            .badge-success {{ background: #28a745; color: white; }}
            .badge-warning {{ background: #ffc107; color: #212529; }}
            .badge-info {{ background: #17a2b8; color: white; }}
            .badge-primary {{ background: #007bff; color: white; }}
            .alert {{ padding: 12px 16px; border-radius: 6px; margin: 10px 0; }}
            .alert-success {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
            .alert-info {{ background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }}
            .alert-warning {{ background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }}
            .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px; text-align: center; }}
            .btn {{ display: inline-block; padding: 10px 24px; background: #28a745; color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
            .btn:hover {{ background: #1e7e34; }}
            .table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 14px; }}
            .table th {{ background: #2c3e50; color: white; padding: 10px 12px; text-align: left; }}
            .table td {{ padding: 10px 12px; border-bottom: 1px solid #e9ecef; }}
            code {{ background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; }}
            .step {{ display: inline-block; padding: 4px 12px; background: #e9ecef; border-radius: 20px; margin: 2px; }}
            .step-active {{ background: #28a745; color: white; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>✅ Transfer Approved!</h2>
                <p style="margin: 5px 0 0 0; opacity: 0.9; font-size: 14px;">Cross-Branch Transfer #{transfer.transfer_id}</p>
            </div>
            <div class="content">
                <p>Dear <strong>{from_name}</strong>,</p>
                <div class="alert alert-success">
                    <strong>✅ Great News!</strong> Your cross-branch hardware transfer request has been approved by <strong>{admin_name}</strong> (Super Admin).
                </div>
                <div class="info-box">
                    <h6>📌 Transfer Details</h6>
                    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                        <tr>
                            <td style="padding: 4px 0; width: 35%;"><strong>Transfer ID:</strong></td>
                            <td style="padding: 4px 0;"><code>{transfer.transfer_id}</code></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Transfer Type:</strong></td>
                            <td style="padding: 4px 0;"><span class="badge {transfer_type_badge}">{transfer_type_display}</span></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Receiver:</strong></td>
                            <td style="padding: 4px 0;"><strong>{to_name}</strong></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>To Branch:</strong></td>
                            <td style="padding: 4px 0;"><span class="badge badge-info">{to_branch_display}</span></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>From Branch:</strong></td>
                            <td style="padding: 4px 0;"><span class="badge badge-info">{from_branch_display}</span></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Receiver City:</strong></td>
                            <td style="padding: 4px 0;">{to_city_display}</td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Expected Arrival:</strong></td>
                            <td style="padding: 4px 0;">{expected_arrival_display}</td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Approved By:</strong></td>
                            <td style="padding: 4px 0;">{admin_name}</td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Approved On:</strong></td>
                            <td style="padding: 4px 0;">{approved_date_formatted}</td>
                        </tr>
                    </table>
                </div>
                
                <h6 style="margin-top: 20px; margin-bottom: 10px;">🖥️ Hardware Items to Transfer ({len(hardware_list)})</h6>
                <div style="overflow-x: auto;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th style="width: 40px;">#</th>
                                <th>Type</th>
                                <th>Asset Number</th>
                                <th>Serial Number</th>
                                <th>Model</th>
                                <th>Brand</th>
                            </tr>
                        </thead>
                        <tbody>
                            {hardware_list_html}
                        </tbody>
                    </table>
                </div>
                
                <div class="alert alert-warning">
                    <strong>⚠️ Action Required - Please Initiate Transfer</strong>
                    <p style="margin: 5px 0 0 0;">
                        Since this is a cross-branch transfer, <strong>you need to initiate the transfer</strong> by following these steps:
                    </p>
                </div>
                
                <div style="background: #e8f4fc; padding: 15px; border-radius: 6px; margin: 15px 0;">
                    <h6 style="margin: 0 0 10px 0; color: #0c5460;">📋 Steps to Initiate Transfer:</h6>
                    <ol style="margin: 0 0 0 20px; color: #0c5460;">
                        <li style="padding: 4px 0;">
                            <span class="step step-active">1</span> 
                            Go to <strong>"My Transfers"</strong> section in your dashboard
                        </li>
                        <li style="padding: 4px 0;">
                            <span class="step step-active">2</span> 
                            Find the transfer request <strong>#{transfer.transfer_id}</strong>
                        </li>
                        <li style="padding: 4px 0;">
                            <span class="step step-active">3</span> 
                            Click on <strong>"Initiate Transfer"</strong> button
                        </li>
                        <li style="padding: 4px 0;">
                            <span class="step step-active">4</span> 
                            Provide condition notes and confirm
                        </li>
                        <li style="padding: 4px 0;">
                            <span class="step step-active">5</span> 
                            Hardware will be marked as <strong>"In Transit"</strong>
                        </li>
                    </ol>
                </div>
                
                <div style="text-align: center; margin: 20px 0;">
                    <a href="http://eduquityinventory.co.in/employee/my-transfers/" class="btn">
                        🚀 Go to My Transfers
                    </a>
                </div>
                
                <div class="alert alert-info">
                    <strong>📌 Important Information:</strong>
                    <ul style="margin: 5px 0 0 20px;">
                        <li>Hardware must be in <strong>good condition</strong> before transfer</li>
                        <li>Update the <strong>condition notes</strong> when initiating</li>
                        <li>The receiver will confirm receipt upon arrival</li>
                        <li>This transfer is tracked and logged in the system</li>
                    </ul>
                </div>
                
                <div class="footer">
                    <p><strong>Eduquity Hardware Management Team</strong><br>
                    Established in 2000 - Thought-leader in the Indian assessment industry</p>
                    <p style="font-size: 11px;">If you have any issues, please contact your manager or the Super Admin.</p>
                    <p><em>This is an automated email. Please do not reply to this message.</em></p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    plain_message = f"""
    ✅ TRANSFER APPROVED - PLEASE INITIATE TRANSFER
    ==============================================
    
    Dear {from_name},
    
    ✅ Great News! Your cross-branch hardware transfer request has been approved by {admin_name} (Super Admin).
    
    Transfer Details:
    -----------------
    Transfer ID: {transfer.transfer_id}
    Transfer Type: {transfer_type_display}
    Receiver: {to_name}
    To Branch: {to_branch_display}
    From Branch: {from_branch_display}
    Receiver City: {to_city_display}
    Expected Arrival: {expected_arrival_display}
    Approved By: {admin_name}
    Approved On: {approved_date_formatted}
    
    Hardware Items to Transfer ({len(hardware_list)}):
    -------------------------------
    {hardware_list_text}
    
    ⚠️ ACTION REQUIRED - PLEASE INITIATE TRANSFER
    ----------------------------------------------
    
    Since this is a cross-branch transfer, you need to initiate the transfer by following these steps:
    
    1. Go to "My Transfers" section in your dashboard
    2. Find the transfer request #{transfer.transfer_id}
    3. Click on "Initiate Transfer" button
    4. Provide condition notes and confirm
    5. Hardware will be marked as "In Transit"
    
    Important Information:
    ----------------------
    - Hardware must be in good condition before transfer
    - Update the condition notes when initiating
    - The receiver will confirm receipt upon arrival
    - This transfer is tracked and logged in the system
    
    If you have any issues, please contact your manager or the Super Admin.
    
    ---
    Eduquity Hardware Management Team
    """
    
    try:
        send_mail(
            subject,
            plain_message,
            'noreply@eduquity.com',
            [from_employee.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Sender approval email error: {str(e)}")
        raise


def send_transfer_approval_email_to_receiver(transfer, super_admin):
    """
    Send email to receiver notifying them that the transfer is approved
    """
    from_employee = transfer.from_employee
    to_employee = transfer.to_employee
    admin_name = super_admin.get_full_name() or super_admin.username
    
    from_name = from_employee.get_full_name() or from_employee.username
    to_name = to_employee.get_full_name() or to_employee.username
    
    transfer_type_display = 'Temporary' if transfer.transfer_type == 'temporary' else 'Permanent'
    transfer_type_badge = 'badge-warning' if transfer.transfer_type == 'temporary' else 'badge-primary'
    requested_date_formatted = transfer.requested_date.strftime('%d %B %Y at %I:%M %p') if transfer.requested_date else 'N/A'
    approved_date_formatted = timezone.now().strftime('%d %B %Y at %I:%M %p')
    from_branch_display = transfer.from_branch or 'Not Assigned'
    to_branch_display = transfer.to_branch or 'Not Assigned'
    to_city_display = transfer.to_exam_city or 'Not specified'
    expected_arrival_display = transfer.expected_arrival_date.strftime('%d %B %Y') if transfer.expected_arrival_date else 'Not specified'
    
    hardware_list = []
    for item in transfer.transfer_items.all().select_related('hardware__hardware_type'):
        hardware_list.append({
            'type': item.hardware.hardware_type.name,
            'asset_number': item.hardware.asset_number or 'N/A',
            'serial_number': item.hardware.serial_number,
            'model': item.hardware.model_name or 'N/A',
            'brand': item.hardware.brand or 'N/A'
        })
    
    hardware_list_html = ''
    hardware_list_text = ''
    for idx, hw in enumerate(hardware_list, 1):
        hardware_list_html += f"""
        <tr>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{idx}</td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><strong>{hw['type']}</strong></td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{hw['asset_number']}</code></td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{hw['serial_number']}</code></td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{hw['model']}</td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{hw['brand']}</td>
        </tr>
        """
        hardware_list_text += f"{idx}. {hw['type']} - Asset: {hw['asset_number']} | Serial: {hw['serial_number']} | Model: {hw['model']}\n"
    
    subject = f'✅ Transfer Approved - Hardware Incoming #{transfer.transfer_id}'
    
    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #17a2b8; color: white; padding: 25px; text-align: center; border-radius: 8px 8px 0 0; }}
            .header h2 {{ margin: 0; font-weight: 300; }}
            .content {{ background: #ffffff; padding: 30px; border: 1px solid #e9ecef; border-top: none; border-radius: 0 0 8px 8px; }}
            .info-box {{ background: #f8f9fa; padding: 15px 20px; margin: 15px 0; border-radius: 6px; border-left: 4px solid #17a2b8; }}
            .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
            .badge-success {{ background: #28a745; color: white; }}
            .badge-info {{ background: #17a2b8; color: white; }}
            .badge-warning {{ background: #ffc107; color: #212529; }}
            .badge-primary {{ background: #007bff; color: white; }}
            .alert {{ padding: 12px 16px; border-radius: 6px; margin: 10px 0; }}
            .alert-success {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
            .alert-info {{ background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }}
            .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px; text-align: center; }}
            .btn {{ display: inline-block; padding: 10px 24px; background: #17a2b8; color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
            .btn:hover {{ background: #138496; }}
            .table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 14px; }}
            .table th {{ background: #2c3e50; color: white; padding: 10px 12px; text-align: left; }}
            .table td {{ padding: 10px 12px; border-bottom: 1px solid #e9ecef; }}
            code {{ background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>📦 Transfer Approved - Hardware Incoming!</h2>
                <p style="margin: 5px 0 0 0; opacity: 0.9; font-size: 14px;">Transfer #{transfer.transfer_id}</p>
            </div>
            <div class="content">
                <p>Dear <strong>{to_name}</strong>,</p>
                
                <div class="alert alert-success">
                    <strong>✅ Great News!</strong> A cross-branch hardware transfer has been approved by <strong>{admin_name}</strong> (Super Admin).
                </div>
                
                <p>You will be receiving hardware from <strong>{from_name}</strong>.</p>
                
                <div class="info-box">
                    <h6>📌 Transfer Details</h6>
                    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                        <tr>
                            <td style="padding: 4px 0; width: 35%;"><strong>Transfer ID:</strong></td>
                            <td style="padding: 4px 0;"><code>{transfer.transfer_id}</code></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>From:</strong></td>
                            <td style="padding: 4px 0;"><strong>{from_name}</strong></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>From Branch:</strong></td>
                            <td style="padding: 4px 0;">
                                <span class="badge badge-info">{from_branch_display}</span>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>To Branch:</strong></td>
                            <td style="padding: 4px 0;">
                                <span class="badge badge-info">{to_branch_display}</span>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Your City:</strong></td>
                            <td style="padding: 4px 0;">{to_city_display}</td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Expected Arrival:</strong></td>
                            <td style="padding: 4px 0;">{expected_arrival_display}</td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Transfer Type:</strong></td>
                            <td style="padding: 4px 0;">
                                <span class="badge {transfer_type_badge}">{transfer_type_display}</span>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <h6 style="margin-top: 20px; margin-bottom: 10px;">🖥️ Hardware Items to Receive ({len(hardware_list)})</h6>
                <div style="overflow-x: auto;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th style="width: 40px;">#</th>
                                <th>Type</th>
                                <th>Asset Number</th>
                                <th>Serial Number</th>
                                <th>Model</th>
                                <th>Brand</th>
                            </tr>
                        </thead>
                        <tbody>
                            {hardware_list_html}
                        </tbody>
                    </table>
                </div>
                
                <div class="alert alert-info">
                    <strong>📌 What to Expect:</strong>
                    <ul style="margin: 5px 0 0 20px;">
                        <li>The sender will initiate the transfer shortly</li>
                        <li>You will receive a notification when the hardware is in transit</li>
                        <li>Upon receipt, you need to <strong>confirm receipt</strong> to complete the transfer</li>
                        <li>Hardware will be automatically assigned to you after confirmation</li>
                    </ul>
                </div>
                
                <div style="text-align: center; margin: 20px 0;">
                    <a href="http://eduquityinventory.co.in/employee/my-transfers/" class="btn">
                        🚀 Go to My Transfers
                    </a>
                </div>
                
                <div class="footer">
                    <p><strong>Eduquity Hardware Management Team</strong><br>
                    Established in 2000 - Thought-leader in the Indian assessment industry</p>
                    <p style="font-size: 11px;">If you have any issues, please contact your manager or the Super Admin.</p>
                    <p><em>This is an automated email. Please do not reply to this message.</em></p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    plain_message = f"""
    📦 TRANSFER APPROVED - HARDWARE INCOMING
    ========================================
    
    Dear {to_name},
    
    ✅ Great News! A cross-branch hardware transfer has been approved by {admin_name} (Super Admin).
    
    You will be receiving hardware from {from_name}.
    
    Transfer Details:
    -----------------
    Transfer ID: {transfer.transfer_id}
    From: {from_name}
    From Branch: {from_branch_display}
    To Branch: {to_branch_display}
    Your City: {to_city_display}
    Expected Arrival: {expected_arrival_display}
    Transfer Type: {transfer_type_display}
    
    Hardware Items to Receive ({len(hardware_list)}):
    ---------------------------------
    {hardware_list_text}
    
    What to Expect:
    ---------------
    - The sender will initiate the transfer shortly
    - You will receive a notification when the hardware is in transit
    - Upon receipt, you need to confirm receipt to complete the transfer
    - Hardware will be automatically assigned to you after confirmation
    
    If you have any issues, please contact your manager or the Super Admin.
    
    ---
    Eduquity Hardware Management Team
    """
    
    try:
        send_mail(
            subject,
            plain_message,
            'noreply@eduquity.com',
            [to_employee.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Receiver approval email error: {str(e)}")
        raise


def send_transfer_rejection_email_to_sender(transfer, super_admin, rejection_reason):
    """
    Send email to sender notifying them that the transfer request was rejected
    """
    from_employee = transfer.from_employee
    to_employee = transfer.to_employee
    admin_name = super_admin.get_full_name() or super_admin.username
    
    from_name = from_employee.get_full_name() or from_employee.username
    to_name = to_employee.get_full_name() or to_employee.username
    
    transfer_type_display = 'Temporary' if transfer.transfer_type == 'temporary' else 'Permanent'
    transfer_type_badge = 'badge-warning' if transfer.transfer_type == 'temporary' else 'badge-primary'
    requested_date_formatted = transfer.requested_date.strftime('%d %B %Y at %I:%M %p') if transfer.requested_date else 'N/A'
    rejected_date_formatted = timezone.now().strftime('%d %B %Y at %I:%M %p')
    from_branch_display = transfer.from_branch or 'Not Assigned'
    to_branch_display = transfer.to_branch or 'Not Assigned'
    
    hardware_list = []
    for item in transfer.transfer_items.all().select_related('hardware__hardware_type'):
        hardware_list.append({
            'type': item.hardware.hardware_type.name,
            'asset_number': item.hardware.asset_number or 'N/A',
            'serial_number': item.hardware.serial_number,
            'model': item.hardware.model_name or 'N/A',
            'brand': item.hardware.brand or 'N/A'
        })
    
    hardware_list_html = ''
    hardware_list_text = ''
    for idx, hw in enumerate(hardware_list, 1):
        hardware_list_html += f"""
        <tr>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">{idx}</td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><strong>{hw['type']}</strong></td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{hw['asset_number']}</code></td>
            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;"><code style="background: #f8f9fa; padding: 2px 6px; border-radius: 4px;">{hw['serial_number']}</code></td>
        </tr>
        """
        hardware_list_text += f"{idx}. {hw['type']} - Asset: {hw['asset_number']} | Serial: {hw['serial_number']}\n"
    
    subject = f'❌ Transfer Request Rejected - #{transfer.transfer_id}'
    
    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #dc3545; color: white; padding: 25px; text-align: center; border-radius: 8px 8px 0 0; }}
            .header h2 {{ margin: 0; font-weight: 300; }}
            .content {{ background: #ffffff; padding: 30px; border: 1px solid #e9ecef; border-top: none; border-radius: 0 0 8px 8px; }}
            .info-box {{ background: #f8f9fa; padding: 15px 20px; margin: 15px 0; border-radius: 6px; border-left: 4px solid #dc3545; }}
            .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
            .badge-info {{ background: #17a2b8; color: white; }}
            .badge-danger {{ background: #dc3545; color: white; }}
            .badge-warning {{ background: #ffc107; color: #212529; }}
            .badge-primary {{ background: #007bff; color: white; }}
            .alert {{ padding: 12px 16px; border-radius: 6px; margin: 10px 0; }}
            .alert-danger {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }}
            .alert-info {{ background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }}
            .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px; text-align: center; }}
            .btn {{ display: inline-block; padding: 10px 24px; background: #dc3545; color: white; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
            .btn:hover {{ background: #c82333; }}
            .table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 14px; }}
            .table th {{ background: #2c3e50; color: white; padding: 10px 12px; text-align: left; }}
            .table td {{ padding: 10px 12px; border-bottom: 1px solid #e9ecef; }}
            code {{ background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; }}
            .rejection-box {{ background: #f8d7da; border: 2px solid #dc3545; padding: 12px 16px; border-radius: 6px; margin: 10px 0; }}
            .rejection-box strong {{ color: #721c24; }}
            .rejection-box p {{ margin: 5px 0 0 0; color: #721c24; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>❌ Transfer Request Rejected</h2>
                <p style="margin: 5px 0 0 0; opacity: 0.9; font-size: 14px;">Transfer #{transfer.transfer_id}</p>
            </div>
            <div class="content">
                <p>Dear <strong>{from_name}</strong>,</p>
                
                <div class="alert alert-danger">
                    <strong>❌ Sorry!</strong> Your cross-branch hardware transfer request has been rejected by <strong>{admin_name}</strong> (Super Admin).
                </div>
                
                <div class="rejection-box">
                    <strong>📌 Rejection Reason:</strong>
                    <p>{rejection_reason or 'No specific reason provided.'}</p>
                </div>
                
                <div class="info-box">
                    <h6>📌 Transfer Details</h6>
                    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                        <tr>
                            <td style="padding: 4px 0; width: 35%;"><strong>Transfer ID:</strong></td>
                            <td style="padding: 4px 0;"><code>{transfer.transfer_id}</code></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Receiver:</strong></td>
                            <td style="padding: 4px 0;"><strong>{to_name}</strong></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>To Branch:</strong></td>
                            <td style="padding: 4px 0;">
                                <span class="badge badge-info">{to_branch_display}</span>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>From Branch:</strong></td>
                            <td style="padding: 4px 0;">
                                <span class="badge badge-info">{from_branch_display}</span>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Transfer Type:</strong></td>
                            <td style="padding: 4px 0;">
                                <span class="badge {transfer_type_badge}">{transfer_type_display}</span>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Requested On:</strong></td>
                            <td style="padding: 4px 0;">{requested_date_formatted}</td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Rejected By:</strong></td>
                            <td style="padding: 4px 0;">{admin_name}</td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Rejected On:</strong></td>
                            <td style="padding: 4px 0;">{rejected_date_formatted}</td>
                        </tr>
                    </table>
                </div>
                
                <h6 style="margin-top: 20px; margin-bottom: 10px;">🖥️ Hardware Items in Request ({len(hardware_list)})</h6>
                <div style="overflow-x: auto;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th style="width: 40px;">#</th>
                                <th>Type</th>
                                <th>Asset Number</th>
                                <th>Serial Number</th>
                            </tr>
                        </thead>
                        <tbody>
                            {hardware_list_html}
                        </tbody>
                    </table>
                </div>
                
                <div class="alert alert-info">
                    <strong>📌 What to Do Next:</strong>
                    <ul style="margin: 5px 0 0 20px;">
                        <li>Review the rejection reason provided above</li>
                        <li>If needed, contact <strong>{admin_name}</strong> (Super Admin) for clarification</li>
                        <li>You can create a <strong>new transfer request</strong> with corrected details</li>
                        <li>Ensure all hardware items are in good condition</li>
                    </ul>
                </div>
                
                <div style="text-align: center; margin: 20px 0;">
                    <a href="http://eduquityinventory.co.in/employee/my-transfers/" class="btn">
                        🚀 Go to My Transfers
                    </a>
                </div>
                
                <div class="footer">
                    <p><strong>Eduquity Hardware Management Team</strong><br>
                    Established in 2000 - Thought-leader in the Indian assessment industry</p>
                    <p style="font-size: 11px;">If you have any questions, please contact your manager or the Super Admin.</p>
                    <p><em>This is an automated email. Please do not reply to this message.</em></p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    plain_message = f"""
    ❌ TRANSFER REQUEST REJECTED
    ============================
    
    Dear {from_name},
    
    ❌ Sorry! Your cross-branch hardware transfer request has been rejected by {admin_name} (Super Admin).
    
    Rejection Reason:
    -----------------
    {rejection_reason or 'No specific reason provided.'}
    
    Transfer Details:
    -----------------
    Transfer ID: {transfer.transfer_id}
    Receiver: {to_name}
    To Branch: {to_branch_display}
    From Branch: {from_branch_display}
    Transfer Type: {transfer_type_display}
    Requested On: {requested_date_formatted}
    Rejected By: {admin_name}
    Rejected On: {rejected_date_formatted}
    
    Hardware Items in Request ({len(hardware_list)}):
    -------------------------------
    {hardware_list_text}
    
    What to Do Next:
    ---------------
    - Review the rejection reason provided above
    - If needed, contact {admin_name} (Super Admin) for clarification
    - You can create a new transfer request with corrected details
    - Ensure all hardware items are in good condition
    
    If you have any questions, please contact your manager or the Super Admin.
    
    ---
    Eduquity Hardware Management Team
    """
    
    try:
        send_mail(
            subject,
            plain_message,
            'noreply@eduquity.com',
            [from_employee.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Sender email error: {str(e)}")
        raise        


def send_transfer_rejection_email_to_receiver(transfer, super_admin, rejection_reason):
    """
    Send email to receiver notifying them that the transfer request was rejected
    """
    from_employee = transfer.from_employee
    to_employee = transfer.to_employee
    admin_name = super_admin.get_full_name() or super_admin.username
    
    from_name = from_employee.get_full_name() or from_employee.username
    to_name = to_employee.get_full_name() or to_employee.username
    
    requested_date_formatted = transfer.requested_date.strftime('%d %B %Y at %I:%M %p') if transfer.requested_date else 'N/A'
    rejected_date_formatted = timezone.now().strftime('%d %B %Y at %I:%M %p')
    from_branch_display = transfer.from_branch or 'Not Assigned'
    to_branch_display = transfer.to_branch or 'Not Assigned'
    
    subject = f'❌ Transfer Request Rejected - #{transfer.transfer_id}'
    
    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #dc3545; color: white; padding: 25px; text-align: center; border-radius: 8px 8px 0 0; }}
            .header h2 {{ margin: 0; font-weight: 300; }}
            .content {{ background: #ffffff; padding: 30px; border: 1px solid #e9ecef; border-top: none; border-radius: 0 0 8px 8px; }}
            .info-box {{ background: #f8f9fa; padding: 15px 20px; margin: 15px 0; border-radius: 6px; border-left: 4px solid #dc3545; }}
            .alert {{ padding: 12px 16px; border-radius: 6px; margin: 10px 0; }}
            .alert-danger {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }}
            .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px; text-align: center; }}
            code {{ background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; }}
            .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
            .badge-info {{ background: #17a2b8; color: white; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>❌ Transfer Request Rejected</h2>
                <p style="margin: 5px 0 0 0; opacity: 0.9; font-size: 14px;">Transfer #{transfer.transfer_id}</p>
            </div>
            <div class="content">
                <p>Dear <strong>{to_name}</strong>,</p>
                
                <div class="alert alert-danger">
                    <strong>❌ Notice:</strong> The cross-branch hardware transfer request from <strong>{from_name}</strong> has been rejected by <strong>{admin_name}</strong> (Super Admin).
                </div>
                
                <div class="info-box">
                    <h6>📌 Transfer Details</h6>
                    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                        <tr>
                            <td style="padding: 4px 0; width: 35%;"><strong>Transfer ID:</strong></td>
                            <td style="padding: 4px 0;"><code>{transfer.transfer_id}</code></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Sender:</strong></td>
                            <td style="padding: 4px 0;"><strong>{from_name}</strong></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>From Branch:</strong></td>
                            <td style="padding: 4px 0;"><span class="badge badge-info">{from_branch_display}</span></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>To Branch:</strong></td>
                            <td style="padding: 4px 0;"><span class="badge badge-info">{to_branch_display}</span></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Rejection Reason:</strong></td>
                            <td style="padding: 4px 0;">{rejection_reason or 'No specific reason provided.'}</td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Rejected By:</strong></td>
                            <td style="padding: 4px 0;">{admin_name}</td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0;"><strong>Rejected On:</strong></td>
                            <td style="padding: 4px 0;">{rejected_date_formatted}</td>
                        </tr>
                    </table>
                </div>
                
                <p style="margin-top: 15px;">If you have any questions about this rejection, please contact your manager or the Super Admin.</p>
                
                <div class="footer">
                    <p><strong>Eduquity Hardware Management Team</strong><br>
                    Established in 2000 - Thought-leader in the Indian assessment industry</p>
                    <p><em>This is an automated email. Please do not reply to this message.</em></p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    plain_message = f"""
    ❌ TRANSFER REQUEST REJECTED
    ============================
    
    Dear {to_name},
    
    ❌ Notice: The cross-branch hardware transfer request from {from_name} has been rejected by {admin_name} (Super Admin).
    
    Transfer ID: {transfer.transfer_id}
    Sender: {from_name}
    Rejection Reason: {rejection_reason or 'No specific reason provided.'}
    Rejected By: {admin_name}
    Rejected On: {rejected_date_formatted}
    
    If you have any questions about this rejection, please contact your manager or the Super Admin.
    
    ---
    Eduquity Hardware Management Team
    """
    
    try:
        send_mail(
            subject,
            plain_message,
            'noreply@eduquity.com',
            [to_employee.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Receiver email error: {str(e)}")
        raise