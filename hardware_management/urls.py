from django.urls import path
from . import views

urlpatterns = [

    path('super-admin/audit-logs/', views.view_audit_logs, name='view_audit_logs'),
path('super-admin/audit-logs/export/', views.export_audit_logs_excel, name='export_audit_logs_excel'),
path('super-admin/audit-logs/cleanup/', views.cleanup_audit_logs, name='cleanup_audit_logs'),
path('super-admin/audit-otp-login/', views.audit_otp_login, name='audit_otp_login'),
path('super-admin/audit-otp-send/', views.audit_otp_send, name='audit_otp_send'),
path('super-admin/audit-otp-verify/', views.audit_otp_verify, name='audit_otp_verify'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('change-password/', views.change_password, name='change_password'),
    path('super-admin/suspicious-activity/', views.check_suspicious_activity, name='check_suspicious_activity'),
# urls.py
path('super-admin/toggle-password-lock/<int:employee_id>/', views.toggle_password_lock, name='toggle_password_lock'),
# urls.py

path('super-admin/bulk-lock-employees/', views.bulk_lock_employees, name='bulk_lock_employees'),
path('super-admin/bulk-unlock-employees/', views.bulk_unlock_employees, name='bulk_unlock_employees'),
    
    # ============== MANAGER DASHBOARD & MANAGEMENT ==============
    path('manager/dashboard/', views.manager_dashboard, name='manager_dashboard'),
    path('super-admin/create-employee/', views.create_employee, name='create_employee'),
    path('manager/delete-employee/<int:employee_id>/', views.delete_employee, name='delete_employee'),
    path('manager/employee-list/', views.employee_list, name='employee_list'),
    path('manager/request-employee-delete/<int:employee_id>/', views.request_employee_delete, name='request_employee_delete'),

#     path('manager/create-project/', views.create_project, name='create_project'),
#     path('delete-project/<int:project_id>/', views.delete_project, name='delete_project'),
    path('export-all-projects/', views.export_all_projects_excel, name='export_all_projects_excel'),
     path('manager/projects/', views.manager_projects, name='manager_projects'),
    path('manager/projects/export/', views.manager_projects, name='export_manager_projects'),
    path('manager/project-assignments/<str:project_id>/', views.project_assignments, name='project_assignments'),
    path('export_manager_projects_excel/<int:project_id>/', views.export_manager_projects_excel, name='export_manager_projects_excel'),
        path('export_project_hardware_excel/<int:project_id>/', views.export_project_hardware_excel, name='export_project_hardware_excel'),

    # ============== HARDWARE MANAGEMENT ==============
    path('manager/manage-hardware/', views.manage_hardware, name='manage_hardware'),
    path('manager/active-hardware/', views.manager_active_hardware, name='manager_active_hardware'),
    path('super-admin/add-hardware/', views.add_hardware, name='add_hardware'),
    path('download-hardware-template/', views.download_hardware_template, name='download_hardware_template'),
    path('manager/manage-hardware-types/', views.manage_hardware_types, name='manage_hardware_types'),
    
    # ============== ASSIGNMENT MANAGEMENT ==============
    path('manager/create-assignment/', views.create_assignment, name='create_assignment'),
    path('manager/view-assignments/', views.view_assignments, name='view_assignments'),
    path('assignment-details/<uuid:assignment_id>/', views.assignment_details, name='assignment_details'),
    path('return-assignment/<str:assignment_id>/', views.return_assignment, name='return_assignment'),
    path('manager/serial-entries/', views.view_serial_entries, name='view_serial_entries'),
    path('manager/verify-serial/<int:entry_id>/', views.verify_serial_entry, name='verify_serial_entry'),
    path('manager/verify-all/<int:assignment_id>/', views.verify_all_employee_entries, name='verify_all_employee_entries'),
    path('manager/verification-status/', views.manager_verification_status, name='manager_verification_status'),
    path('manager/verification-details/<uuid:assignment_id>/', views.manager_verification_details, name='manager_verification_details'),
    path('verify-asset-entry/<int:entry_id>/', views.verify_asset_entry, name='verify_asset_entry'),
    path('manager/add-extra-hardware/<uuid:assignment_id>/', 
         views.add_extra_hardware_to_assignment, 
         name='add_extra_hardware_to_assignment'),
     path('manager/remove-hardware/<uuid:assignment_id>/<int:item_id>/', 
         views.remove_hardware_from_assignment, 
         name='remove_hardware_from_assignment'),
    
    path('manager/remove-all-unverified/<uuid:assignment_id>/', 
         views.remove_all_unverified_hardware, 
         name='remove_all_unverified_hardware'),
    
    path('manager/remove-verified-warning/<int:assignment_id>/<int:item_id>/', 
         views.remove_verified_hardware_warning, 
         name='remove_verified_hardware_warning'),    
     # urls.py
path('manager/request-hardware-update/<uuid:hardware_id>/', views.request_hardware_update, name='request_hardware_update'),
path('manager/request-hardware-delete/<uuid:hardware_id>/', views.request_hardware_delete, name='request_hardware_delete'),
    # ============== EMPLOYEE MANAGEMENT ==============
    path('employee/dashboard/', views.employee_dashboard, name='employee_dashboard'),
    path('employee/my-assignments/', views.view_my_assignments, name='view_my_assignments'),
    path('employee/assignment-details/<str:assignment_id>/', views.my_assignment_details, name='my_assignment_details'),
    path('employee/enter-serials/<str:assignment_id>/', views.enter_serial_numbers, name='enter_serial_numbers'),
    path('employee/edit-serials/<uuid:assignment_id>/', views.edit_serial_numbers, name='edit_serial_numbers'),
    path('employee/my-hardware/', views.my_hardware, name='my_hardware'),
    path('employee/export-my-hardware/', views.export_my_hardware_excel, name='export_my_hardware_excel'),
    path('export-assignment/<uuid:assignment_id>/', views.export_assignment_excel, name='export_assignment_excel'),
    
    # ============== EMPLOYEE TRANSFER MANAGEMENT ==============
    path('employee/request-transfer/', views.request_hardware_transfer, name='request_hardware_transfer'),
    path('employee/my-transfers/', views.my_transfers, name='my_transfers'),
    path('employee/transfer-tracking/<str:transfer_id>/', views.transfer_tracking, name='transfer_tracking'),
    path('employee/update-transfer-status/<str:transfer_id>/', views.update_transfer_status_employee, name='update_transfer_status_employee'),
    
    # ============== MANAGER TRANSFER MANAGEMENT ==============
    path('manager/transfer-requests/', views.manager_transfer_requests, name='manager_transfer_requests'),
    path('manager/approve-transfer/<int:transfer_id>/', views.approve_transfer_request, name='approve_transfer_request'),
    path('manager/reject-transfer/<int:transfer_id>/', views.reject_transfer_request, name='reject_transfer_request'),
    path('manager/transfer_details/<str:transfer_id>/', views.transfer_details, name='transfer_details'),
    
   

    
    # ============== BULK OPERATIONS ==============
    path('manager/bulk-create-employees/', views.bulk_create_employees, name='bulk_create_employees'),
    path('manager/download-sample-csv/', views.download_sample_csv, name='download_sample_csv'),
    path('manager/export-employees-hardware/', views.export_all_employees_hardware, name='export_employees_hardware'),
    
    # ============== CHATBOT ==============
    path('manager/chatbot/', views.chatbot_view, name='chatbot'),
    path('manager/chatbot-api/', views.chatbot_api, name='chatbot_api'),
    path('manager/chatbot-stats/', views.chatbot_stats_api, name='chatbot_stats_api'),
    
    # ============== API ENDPOINTS ==============
    path('api/hardware-by-type/', views.api_get_hardware_by_type, name='api_hardware_by_type'),
    path('api/assignment/<int:assignment_id>/', views.api_get_assignment_details, name='api_assignment_details'),
    path('api/check-serial/', views.api_check_serial_exists, name='api_check_serial_exists'),
    
    # ============== PROFILE & AUTH ==============
    path('profile/', views.profile, name='profile'),
    path('profile/update/', views.update_profile, name='update_profile'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('verify-otp/<uuid:token>/', views.verify_otp, name='verify_otp'),
    path('reset-password/<uuid:token>/', views.reset_password, name='reset_password'),

    path('super-admin/dashboard/', views.super_admin_dashboard, name='super_admin_dashboard'),
    path('super-admin/managers/', views.super_admin_managers, name='super_admin_managers'),
    path('super-admin/employees/', views.super_admin_employees, name='super_admin_employees'),
    path('super-admin/delete-employee/<int:employee_id>/', views.super_admin_delete_employee, name='super_admin_delete_employee'),
    path('super-admin/edit-employee/<int:employee_id>/', views.super_admin_edit_employee, name='super_admin_edit_employee'),
    path('super-admin/branches/', views.super_admin_branches, name='super_admin_branches'),
    path('super-admin/branch-assignments/<str:branch_name>/', views.super_admin_branch_assignments, name='super_admin_branch_assignments'),
    path('super-admin/hardware/', views.super_admin_hardware, name='super_admin_hardware'),
     path('super-admin/hardware/edit/<int:hardware_id>/', views.super_admin_edit_hardware, name='super_admin_edit_hardware'),
    path('super-admin/hardware/delete/<int:hardware_id>/', views.super_admin_delete_hardware, name='super_admin_delete_hardware'),
    path('super-admin/hardware/bulk-delete/', views.super_admin_bulk_delete_hardware, name='super_admin_bulk_delete_hardware'),
    path('super-admin/hardware/view/<int:hardware_id>/', views.super_admin_view_hardware_details, name='super_admin_view_hardware_details'),
    path('super-admin/requests/', views.super_admin_requests, name='super_admin_requests'),
    path('super-admin/request/<int:request_id>/', views.super_admin_view_request, name='super_admin_view_request'),
    path('super-admin/request/approve/<int:request_id>/', views.super_admin_approve_request, name='super_admin_approve_request'),
    path('super-admin/request/reject/<int:request_id>/', views.super_admin_reject_request, name='super_admin_reject_request'),
    path('delete-request/<int:request_id>/', views.super_admin_delete_request, name='super_admin_delete_request'),
    path('super-admin/assignments/', views.super_admin_assignments, name='super_admin_assignments'),
    path('super-admin/create-manager/', views.super_admin_create_manager, name='super_admin_create_manager'),
    path('super-admin/delete-manager/<int:manager_id>/', views.super_admin_delete_manager, name='super_admin_delete_manager'),
     path('super-admin/create-project/', views.super_admin_create_project, name='super_admin_create_project'),
    path('super-admin/projects/', views.super_admin_projects, name='super_admin_projects'),
    path('super-admin/delete-project/<int:project_id>/', views.super_admin_delete_project, name='super_admin_delete_project'),
path('super-admin/project-assignments/<int:project_id>/', views.super_admin_project_assignments, name='super_admin_project_assignments'),
    # In urls.py
path('super-admin/export-assignments-excel/<int:project_id>/', views.super_admin_export_assignments_excel, name='super_admin_export_assignments_excel'),

# urls.py

# Manager URLs
path('manager/request-employee-update/<int:employee_id>/', views.request_employee_update, name='request_employee_update'),

# Super Admin URLs
path('super-admin/update-requests/', views.super_admin_update_requests, name='super_admin_update_requests'),
path('super-admin/update-request/delete/<int:request_id>/', views.super_admin_delete_update_request, name='super_admin_delete_update_request'),
path('super-admin/update-request/approve/<int:request_id>/', views.super_admin_approve_update_request, name='super_admin_approve_update_request'),
path('super-admin/update-request/reject/<int:request_id>/', views.super_admin_reject_update_request, name='super_admin_reject_update_request'),
# URLs for Super Admin
path('super-admin/delete-requests/', views.super_admin_delete_requests, name='super_admin_delete_requests'),
path('super-admin/delete-request/approve/<int:request_id>/', views.super_admin_approve_delete_request, name='super_admin_approve_delete_request'),
path('super-admin/delete-request/reject/<int:request_id>/', views.super_admin_reject_delete_request, name='super_admin_reject_delete_request'),
# urls.py

# Hardware Type Management (Super Admin only)
path('super-admin/manage-hardware-types/', views.manage_hardware_types, name='manage_hardware_types'),
path('super-admin/edit-hardware-type/<int:type_id>/', views.super_admin_edit_hardware_type, name='super_admin_edit_hardware_type'),
path('super-admin/delete-hardware-type/<int:type_id>/', views.super_admin_delete_hardware_type, name='super_admin_delete_hardware_type'),


path('super-admin/transfers/', views.super_admin_transfer_requests, name='super_admin_transfer_requests'),
    path('super-admin/transfers/approve/<str:transfer_id>/', views.super_admin_approve_transfer, name='super_admin_approve_transfer'),
    path('super-admin/transfers/reject/<str:transfer_id>/', views.super_admin_reject_transfer, name='super_admin_reject_transfer'),
path('super-admin/transfer-details/<str:transfer_id>/', views.super_admin_transfer_details, name='super_admin_transfer_details'),
     path('super-admin/verify-hardware-branches/', 
         views.verify_hardware_branch_locations, 
         name='verify_hardware_branch_locations'),
    
    # Or if you want it as an API endpoint:
    path('api/verify-hardware-branches/', 
         views.verify_hardware_branch_locations, 
         name='api_verify_hardware_branch_locations'),
             path('super-admin/debug-branches/', views.debug_hardware_branches, name='debug_hardware_branches'),

]

