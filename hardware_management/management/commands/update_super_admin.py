#!/usr/bin/env python
"""
Update Super Admin Account
Run: python update_super_admin.py
"""

import os
import django
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eduquity_hardware.settings')
django.setup()

from hardware_management.models import CustomUser

def update_super_admin():
    """Update existing super admin or create if not exists"""
    
    username = 'superadmin'
    email = 'sridhar77801@gmail.com'
    password = 'SuperAdmin@2024'
    
    try:
        user = CustomUser.objects.get(username=username)
        
        # Update existing user
        user.email = email
        user.first_name = 'Super'
        user.last_name = 'Admin'
        user.branch_location = 'Head Office'
        user.phone = '+91 7569148233'
        user.is_first_login = False
        user.is_superuser = True
        user.is_staff = True
        user.set_password(password)
        user.save()
        
        print("=" * 50)
        print("✅ SUPER ADMIN UPDATED SUCCESSFULLY!")
        print("=" * 50)
        print(f"👤 Username: {user.username}")
        print(f"📧 Email: {user.email}")
        print(f"🔒 Password: {password}")
        print("=" * 50)
        
    except CustomUser.DoesNotExist:
        # Create if doesn't exist
        user = CustomUser.objects.create_superuser(
            username=username,
            email=email,
            password=password,
            user_type='super_admin',
            first_name='Super',
            last_name='Admin',
            branch_location='Head Office',
            is_first_login=False,
            phone='+91 7569148233'
        )
        
        print("=" * 50)
        print("✅ SUPER ADMIN CREATED SUCCESSFULLY!")
        print("=" * 50)
        print(f"👤 Username: {user.username}")
        print(f"📧 Email: {user.email}")
        print(f"🔒 Password: {password}")
        print("=" * 50)

if __name__ == '__main__':
    update_super_admin()