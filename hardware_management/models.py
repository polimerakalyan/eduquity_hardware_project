from django.db import models

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import uuid

from eduquity_hardware import settings

class CustomUser(AbstractUser):
    USER_TYPE_CHOICES = (
        ('super_admin', 'Super Admin'),
        ('manager', 'Manager'),
        ('employee', 'Employee'),
    )
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES, default='employee')
    manager = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='managed_employees')
    phone = models.CharField(max_length=15, blank=True, null=True)
    branch_location = models.CharField(max_length=200, blank=True, null=True)
    password_change_locked = models.BooleanField(
        default=False,
        help_text="If True, the employee cannot change their own password. Only Super Admin can unlock it."
    )
    otp_code = models.CharField(max_length=6, null=True, blank=True)
    otp_expiry = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.username} ({self.get_user_type_display()})"
    
    @property
    def is_super_admin(self):
        return self.user_type == 'super_admin'


class Project(models.Model):
    project_id = models.CharField(max_length=50, unique=True)
    project_name = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    start_date = models.DateField()
    end_date = models.DateField()
    # Make location completely optional - just for reference
    location = models.CharField(max_length=100, blank=True, null=True, 
                                help_text="Optional: Reference location only - project is available to ALL managers")
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='created_projects')
    assigned_manager = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_projects')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.project_id} - {self.project_name}"
    
    class Meta:
        ordering = ['-created_at']


class HardwareType(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    icon = models.CharField(max_length=50, default='laptop', blank=True, null=True)  # Add this field
 
    
    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ['name']
    
class Hardware(models.Model):
    STATUS_CHOICES = (
        ('available', 'Available'),
        ('assigned', 'Assigned'),
        ('in_use', 'In Use'),
        ('maintenance', 'Under Maintenance'),
        ('retired', 'Retired'),
    )
    
    # Basic Information
    hardware_id = models.UUIDField(
        default=uuid.uuid4, 
        unique=True, 
        editable=False,
        db_index=True
    )

    hardware_type = models.ForeignKey('HardwareType', on_delete=models.CASCADE, related_name='hardware_items')
    asset_number = models.CharField(max_length=100, unique=True, null=True, blank=True, help_text="Unique asset tag number")
    serial_number = models.CharField(max_length=100, unique=True)
    model_name = models.CharField(max_length=200, blank=True, null=True)
    brand = models.CharField(max_length=100, blank=True, null=True)
    specifications = models.TextField(blank=True, null=True)
    purchase_date = models.DateField(blank=True, null=True)
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='available')
    
    # Relations
    created_by = models.ForeignKey('CustomUser', on_delete=models.CASCADE, related_name='created_hardware')
    branch_location = models.CharField(max_length=100, blank=True, null=True, 
                                       help_text="Parent branch where hardware belongs")
    hardware_location = models.CharField(max_length=200, blank=True, null=True, 
                                         help_text="Current physical location of the hardware")
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Optional: For tracking
    assigned_to = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_hardware')
    assigned_date = models.DateTimeField(null=True, blank=True)
    expected_return_date = models.DateField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['asset_number']),
            models.Index(fields=['serial_number']),
            models.Index(fields=['status']),
            models.Index(fields=['branch_location']),
        ]
    
    def __str__(self):
        return f"{self.asset_number or 'No Asset'} - {self.hardware_type.name} - {self.serial_number}"
    
    def get_status_display(self):
        return dict(self.STATUS_CHOICES).get(self.status, self.status)
    
    def is_available(self):
        return self.status == 'available'
    
    def is_assigned(self):
        return self.status in ['assigned', 'in_use']
    
    def can_be_deleted(self):
        """Check if hardware can be deleted (not assigned or in use)"""
        return self.status not in ['assigned', 'in_use']
    
class HardwareAssignment(models.Model):
    assignment_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    employee = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='hardware_assignments')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='hardware_assignments')
    hardware_items = models.ManyToManyField(Hardware, through='HardwareAssignmentItem')
    exam_city = models.CharField(max_length=200, blank=True, null=True, help_text="City where the employee will take the exam")
    exam_center_name = models.CharField(max_length=200, blank=True, null=True, help_text="Name of the exam center")
    assigned_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='assignments_made')
    assigned_date = models.DateTimeField(auto_now_add=True)
    expected_return_date = models.DateField()
    actual_return_date = models.DateField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"Assignment {self.assignment_id} - {self.employee.username}"

class HardwareAssignmentItem(models.Model):
    assignment = models.ForeignKey(HardwareAssignment, on_delete=models.CASCADE)
    hardware = models.ForeignKey(Hardware, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    returned_at = models.DateTimeField(null=True, blank=True)  
    returned_asset_number = models.CharField(max_length=100, blank=True, null=True)  
    condition_at_assignment = models.TextField(blank=True, null=True)
    condition_at_return = models.TextField(blank=True, null=True)
    
    class Meta:
        unique_together = ('assignment', 'hardware')

class HardwareSerialEntry(models.Model):
    assignment_item = models.OneToOneField(HardwareAssignmentItem, on_delete=models.CASCADE, related_name='serial_entry')
    serial_number = models.CharField(max_length=100)
    entered_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    entered_at = models.DateTimeField(auto_now_add=True)
    verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='verified_entries')
    verified_at = models.DateTimeField(blank=True, null=True)
    
    def __str__(self):
        return f"Serial: {self.serial_number}"
    
class HardwareAssetEntry(models.Model):
    hardware_item = models.OneToOneField('HardwareAssignmentItem', on_delete=models.CASCADE, related_name='asset_entry')
    entered_asset_number = models.CharField(max_length=100)
    entered_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='asset_entries')
    entered_at = models.DateTimeField(auto_now_add=True)
    verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='verified_asset_entries')
    verified_at = models.DateTimeField(null=True, blank=True)    
    

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid
import random

User = get_user_model()

class PasswordResetOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    
    def __str__(self):
        return f"OTP for {self.user.username}"
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    @classmethod
    def generate_otp(cls, user):
        otp = str(random.randint(100000, 999999))
        expires_at = timezone.now() + timezone.timedelta(seconds=300)  
        
        cls.objects.filter(user=user, is_used=False).update(is_used=True)
        
        return cls.objects.create(
            user=user,
            otp=otp,
            expires_at=expires_at
        )
    
    class Meta:
        ordering = ['-created_at']    
        
# models.py - Updated EmployeeHardwareTransfer Model

class EmployeeHardwareTransfer(models.Model):
    """Model to track hardware transfer between employees"""
    
    STATUS_CHOICES = (
        ('requested', 'Transfer Requested'),
        ('approved_mgr', 'Approved by Manager'),        # Shorter
        ('approved_sa', 'Approved by Super Admin'),     # Shorter
        ('in_transit', 'In Transit'),
        ('received', 'Received by Receiver'),           # Shorter
        ('completed', 'Completed'),
        ('rejected', 'Rejected'),
        ('cancelled', 'Cancelled'),
    )
    
    TRANSFER_TYPE_CHOICES = (
        ('temporary', 'Temporary Transfer'),
        ('permanent', 'Permanent Transfer'),
    )
    
    transfer_id = models.CharField(max_length=20, unique=True, editable=False)
    
    hardware_items = models.ManyToManyField(Hardware, through='TransferItem', related_name='employee_transfers')
    
    from_employee = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='transfers_given')
    to_employee = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='transfers_received')
    
    from_exam_city = models.CharField(max_length=200)
    to_exam_city = models.CharField(max_length=200)
    to_exam_center = models.CharField(max_length=200, blank=True, null=True)
    
    # NEW: Branch fields for cross-branch transfers
    from_branch = models.CharField(max_length=200, blank=True, null=True)
    to_branch = models.CharField(max_length=200, blank=True, null=True)
    is_cross_branch = models.BooleanField(default=False)
    
    from_project = models.ForeignKey(Project, on_delete=models.SET_NULL, null=True, related_name='transfers_from_emp')
    to_project = models.ForeignKey(Project, on_delete=models.SET_NULL, null=True, related_name='transfers_to_emp')
    
    transfer_type = models.CharField(max_length=20, choices=TRANSFER_TYPE_CHOICES, default='temporary')
    reason = models.TextField()
    expected_return_date = models.DateField(null=True, blank=True)
    
    requested_date = models.DateTimeField(auto_now_add=True)
    approved_date = models.DateTimeField(null=True, blank=True)
    transfer_date = models.DateField(null=True, blank=True)
    expected_arrival_date = models.DateField()
    actual_arrival_date = models.DateField(null=True, blank=True)
    return_date = models.DateField(null=True, blank=True)
    
    status = models.CharField(max_length=100, choices=STATUS_CHOICES, default='requested')
    
    # NEW: Different approvers for different scenarios
    approved_by = models.ForeignKey(
        CustomUser, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='transfers_approved_emp'
    )
    approved_by_super_admin = models.ForeignKey(
        CustomUser, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='super_admin_approved_transfers'
    )
    super_admin_approved_date = models.DateTimeField(null=True, blank=True)
    
    delivery_method = models.CharField(max_length=100, blank=True, null=True)
    tracking_number = models.CharField(max_length=100, blank=True, null=True)
    
    requester_notes = models.TextField(blank=True, null=True)
    manager_notes = models.TextField(blank=True, null=True)
    completion_notes = models.TextField(blank=True, null=True)
    
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='transfers_created_emp')
    updated_at = models.DateTimeField(auto_now=True)
    
    # NEW: Rejection reason field
    rejection_reason = models.TextField(blank=True, null=True)
    rejected_by = models.ForeignKey(
        CustomUser, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='rejected_transfers'
    )
    rejected_date = models.DateTimeField(null=True, blank=True)
    
    def save(self, *args, **kwargs):
        if not self.transfer_id:
            import random
            import string
            date_str = timezone.now().strftime('%Y%m%d')
            random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            self.transfer_id = f"EMP-{date_str}-{random_str}"
        super().save(*args, **kwargs)
    
    @property
    def total_items(self):
        return self.transfer_items.count()
    
    @property
    def received_items_count(self):
        return self.transfer_items.filter(status='received').count()
    
    @property
    def is_same_branch(self):
        """Check if transfer is within same branch"""
        return not self.is_cross_branch
    
    @property
    def approval_required(self):
        """Return who needs to approve this transfer"""
        if self.is_cross_branch:
            return 'Super Admin'
        return 'Manager'
    
    @property
    def approval_status(self):
        """Return current approval status"""
        if self.status == 'requested':
            return f"Pending {self.approval_required} Approval"
        elif self.status == 'approved_by_manager':
            return "Approved by Manager"
        elif self.status == 'approved_by_super_admin':
            return "Approved by Super Admin"
        elif self.status == 'rejected':
            return "Rejected"
        return self.get_status_display()
    
    def __str__(self):
        return f"{self.transfer_id} - {self.total_items} item(s) - {self.status}"
        

# models.py - Updated TransferItem

class TransferItem(models.Model):
    """Individual hardware items in a transfer"""
    
    ITEM_STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('in_transit', 'In Transit'),
        ('received', 'Received'),
        ('returned', 'Returned'),
        ('cancelled', 'Cancelled'),
    )
    
    transfer = models.ForeignKey(EmployeeHardwareTransfer, on_delete=models.CASCADE, related_name='transfer_items')
    hardware = models.ForeignKey(Hardware, on_delete=models.CASCADE)
    
    status = models.CharField(max_length=20, choices=ITEM_STATUS_CHOICES, default='pending')
    
    condition_before = models.TextField(blank=True, null=True)
    condition_after = models.TextField(blank=True, null=True)
    
    tracking_number = models.CharField(max_length=100, blank=True, null=True)
    
    transfer_date = models.DateField(null=True, blank=True)
    received_date = models.DateField(null=True, blank=True)
    return_date = models.DateField(null=True, blank=True)
    
    notes = models.TextField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # NEW: Branch tracking for each item
    from_branch = models.CharField(max_length=200, blank=True, null=True)
    to_branch = models.CharField(max_length=200, blank=True, null=True)
    is_cross_branch = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ('transfer', 'hardware')
    
    def __str__(self):
        return f"{self.transfer.transfer_id} - {self.hardware.serial_number}"

# models.py - Updated TransferHistory

class TransferHistory(models.Model):
    """Model to track transfer history and updates"""
    transfer = models.ForeignKey(EmployeeHardwareTransfer, on_delete=models.CASCADE, related_name='history')
    action = models.CharField(max_length=100, default='action')
    status = models.CharField(max_length=20, choices=EmployeeHardwareTransfer.STATUS_CHOICES)
    notes = models.TextField(blank=True, null=True)
    updated_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # NEW: Track approval type
    approval_type = models.CharField(max_length=20, blank=True, null=True, choices=(
        ('manager', 'Manager Approval'),
        ('super_admin', 'Super Admin Approval'),
    ))
    is_cross_branch = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.transfer.transfer_id} - {self.action} at {self.created_at}"

# models.py - Updated TransferNotification

class TransferNotification(models.Model):
    """Model to track transfer notifications"""
    transfer = models.ForeignKey(EmployeeHardwareTransfer, on_delete=models.CASCADE, related_name='notifications')
    recipient = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)
    
    # NEW: Notification type
    notification_type = models.CharField(max_length=20, blank=True, null=True, choices=(
        ('request_created', 'Transfer Request Created'),
        ('manager_approval', 'Manager Approval Required'),
        ('super_admin_approval', 'Super Admin Approval Required'),
        ('approved', 'Transfer Approved'),
        ('rejected', 'Transfer Rejected'),
        ('in_transit', 'Transfer In Transit'),
        ('received', 'Transfer Received'),
        ('completed', 'Transfer Completed'),
        ('returned', 'Transfer Returned'),
    ))
    is_cross_branch = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Notification for {self.transfer.transfer_id}"

class ChatbotConversation(models.Model):
    """Store chatbot conversations"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='chat_conversations')
    message = models.TextField()
    response = models.TextField()
    intent = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.username} - {self.created_at}"


class HardwareKnowledgeBase(models.Model):
    """Knowledge base for AI training"""
    title = models.CharField(max_length=200)
    content = models.TextField()
    category = models.CharField(max_length=100, choices=[
        ('hardware', 'Hardware Info'),
        ('procedure', 'Procedure'),
        ('faq', 'FAQ'),
        ('policy', 'Policy'),
    ], default='hardware')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.title
 # models.py
class HardwareRequest(models.Model):
    """Model to track hardware update/delete requests from managers"""
    
    REQUEST_TYPES = (
        ('update', 'Update Request'),
        ('delete', 'Delete Request'),
    )
    
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('completed', 'Completed'),
    )
    
    hardware = models.ForeignKey(Hardware, on_delete=models.CASCADE, related_name='requests')
    requested_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='hardware_requests')
    request_type = models.CharField(max_length=20, choices=REQUEST_TYPES)
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    notes = models.TextField(blank=True, null=True)
    reviewed_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_requests')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # New field to track when request was processed (approved/rejected/completed)
    processed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.get_request_type_display()} - {self.hardware.asset_number} - {self.get_status_display()}"
    
    def save(self, *args, **kwargs):
        # Set processed_at when status changes from pending to processed
        if self.pk:
            old_instance = HardwareRequest.objects.get(pk=self.pk)
            if old_instance.status == 'pending' and self.status != 'pending':
                if not self.processed_at:
                    self.processed_at = timezone.now()
        super().save(*args, **kwargs)

class EmployeeDeleteRequest(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )
    
    employee = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='delete_requests')
    requested_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='employee_delete_requests')
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    notes = models.TextField(blank=True, null=True)
    reviewed_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_delete_requests')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Delete {self.employee.username} - {self.status}"        

# models.py

class EmployeeUpdateRequest(models.Model):
    """Model to track employee update requests from managers to Super Admin"""
    
    FIELD_CHOICES = (
        ('name', 'Name'),
        ('email', 'Email'),
        ('phone', 'Phone'),
        ('branch', 'Branch'),
        ('manager', 'Manager'),
        ('multiple', 'Multiple Fields'),
    )
    
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('completed', 'Completed'),
    )
    
    employee = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='update_requests')
    requested_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='employee_update_requests')
    field_updated = models.CharField(max_length=20, choices=FIELD_CHOICES)
    current_value = models.TextField(blank=True, null=True)
    proposed_value = models.TextField()
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    notes = models.TextField(blank=True, null=True)
    reviewed_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_update_requests')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Update {self.employee.username} - {self.field_updated} - {self.status}"    


# Add to models.py - Enhanced AuditLog

class AuditLog(models.Model):
    ROLE_CHOICES = (
        ('super_admin', 'Super Admin'),
        ('manager', 'Manager'),
        ('employee', 'Employee'),
        ('system', 'System'),
    )

    ACTION_CHOICES = (
        # Authentication
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('failed_login', 'Failed Login'),
        ('password_change', 'Password Change'),
        ('password_reset', 'Password Reset'),
        ('password_reset_request', 'Password Reset Request'),
        
        # User Management
        ('user_create', 'Create User'),
        ('user_update', 'Update User'),
        ('user_delete', 'Delete User'),
        ('user_bulk_create', 'Bulk Create Users'),
        ('user_activate', 'Activate User'),
        ('user_deactivate', 'Deactivate User'),
        ('user_type_change', 'Change User Type'),
        
        # Employee Operations (Manager)
        ('employee_create', 'Create Employee'),
        ('employee_update', 'Update Employee'),
        ('employee_delete', 'Delete Employee'),
        ('employee_bulk_create', 'Bulk Create Employees'),
        ('employee_request_delete', 'Request Employee Delete'),
        ('employee_request_update', 'Request Employee Update'),
        
        # Super Admin Employee Operations
        ('employee_approve_delete', 'Approve Employee Delete'),
        ('employee_reject_delete', 'Reject Employee Delete'),
        ('employee_approve_update', 'Approve Employee Update'),
        ('employee_reject_update', 'Reject Employee Update'),
        
        # Hardware Operations
        ('hardware_create', 'Create Hardware'),
        ('hardware_update', 'Update Hardware'),
        ('hardware_delete', 'Delete Hardware'),
        ('hardware_bulk_create', 'Bulk Create Hardware'),
        ('hardware_status_change', 'Change Hardware Status'),
        ('hardware_request_update', 'Request Hardware Update'),
        ('hardware_request_delete', 'Request Hardware Delete'),
        
        # Super Admin Hardware Operations
        ('hardware_approve_update', 'Approve Hardware Update'),
        ('hardware_reject_update', 'Reject Hardware Update'),
        ('hardware_approve_delete', 'Approve Hardware Delete'),
        ('hardware_reject_delete', 'Reject Hardware Delete'),
        ('hardware_type_create', 'Create Hardware Type'),
        ('hardware_type_update', 'Update Hardware Type'),
        ('hardware_type_delete', 'Delete Hardware Type'),
        
        # Assignment Operations
        ('assignment_create', 'Create Assignment'),
        ('assignment_update', 'Update Assignment'),
        ('assignment_return', 'Return Assignment'),
        ('assignment_auto_return', 'Auto Return Assignment'),
        ('assignment_item_add', 'Add Hardware to Assignment'),
        ('assignment_item_remove', 'Remove Hardware from Assignment'),
        ('assignment_item_remove_all', 'Remove All Hardware from Assignment'),
        
        # Verification Operations
        ('asset_entry', 'Asset Number Entry'),
        ('asset_entry_update', 'Asset Number Update'),
        ('asset_verify', 'Verify Asset'),
        ('asset_verify_all', 'Verify All Assets'),
        ('asset_entry_remove', 'Remove Asset Entry'),
        
        # Transfer Operations
        ('transfer_request', 'Request Transfer'),
        ('transfer_approve', 'Approve Transfer'),
        ('transfer_reject', 'Reject Transfer'),
        ('transfer_complete', 'Complete Transfer'),
        ('transfer_return', 'Return Transfer'),
        ('transfer_cancel', 'Cancel Transfer'),
        ('transfer_status_update', 'Update Transfer Status'),
        
        # Project Operations
        ('project_create', 'Create Project'),
        ('project_update', 'Update Project'),
        ('project_delete', 'Delete Project'),
        ('project_archive', 'Archive Project'),
        ('project_export', 'Export Project'),
        
        # Report/Export Operations
        ('export_report', 'Export Report'),
        ('export_assignments', 'Export Assignments'),
        ('export_hardware', 'Export Hardware'),
        
        # Chatbot
        ('chatbot_query', 'Chatbot Query'),
        
        # System
        ('system_error', 'System Error'),
        ('system_warning', 'System Warning'),
        ('system_info', 'System Info'),
    )

    log_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    module = models.CharField(max_length=100)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    browser = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    
    # Enhanced fields for better tracking
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='target_audit_logs'
    )
    target_model = models.CharField(max_length=100, blank=True, null=True)
    target_id = models.CharField(max_length=50, blank=True, null=True)
    old_value = models.TextField(blank=True, null=True)
    new_value = models.TextField(blank=True, null=True)
    request_path = models.CharField(max_length=500, blank=True, null=True)
    request_method = models.CharField(max_length=10, blank=True, null=True)
    session_key = models.CharField(max_length=40, blank=True, null=True)  # For session tracking

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['user', 'action']),
            models.Index(fields=['role', 'action']),
            models.Index(fields=['target_model', 'target_id']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['created_at']),
        ]

    def save(self, *args, **kwargs):
        if self.pk:
            raise Exception("Audit logs cannot be modified.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise Exception("Audit logs cannot be deleted.")

    def __str__(self):
        return f"{self.user} - {self.action} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"


class HardwareAssetDraft(models.Model):
    """Model to store auto-saved drafts for asset entry"""
    assignment = models.ForeignKey('HardwareAssignment', on_delete=models.CASCADE, related_name='drafts')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    data = models.JSONField(default=dict, blank=True)
    last_saved = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['assignment', 'user']
        ordering = ['-last_saved']
    
    def __str__(self):
        return f"Draft for {self.assignment.assignment_id} by {self.user.username}"    


class AssignmentDraft(models.Model):
    """Model to store auto-saved drafts for assignment creation"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    data = models.JSONField(default=dict, blank=True)
    is_completed = models.BooleanField(default=False)
    last_saved = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-last_saved']
    
    def __str__(self):
        return f"Assignment draft for {self.user.username} - {self.last_saved.strftime('%Y-%m-%d %H:%M')}"    