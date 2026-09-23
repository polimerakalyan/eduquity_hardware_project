from django.core.management.base import BaseCommand
from hardware_management.models import CustomUser
from django.db import transaction

class Command(BaseCommand):
    help = 'Create a super admin user'

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            type=str,
            default='superadmin',
            help='Username for the super admin (default: superadmin)'
        )
        parser.add_argument(
            '--email',
            type=str,
            default='sridharnidamanuri@gmail.com',
            help='Email for the super admin'
        )
        parser.add_argument(
            '--password',
            type=str,
            default='SuperAdmin@2026',
            help='Password for the super admin'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force create even if user exists (will update existing)'
        )

    @transaction.atomic
    def handle(self, *args, **options):
        username = options.get('username', 'superadmin')
        email = options.get('email', 'sridharnidamanuri@gmail.com')
        password = options.get('password', 'SuperAdmin@2026')
        force = options.get('force', False)

        # Check if user exists
        user_exists = CustomUser.objects.filter(username=username).exists()
        email_exists = CustomUser.objects.filter(email=email).exists()

        if user_exists and not force:
            self.stdout.write(self.style.ERROR(f'❌ User "{username}" already exists!'))
            self.stdout.write(f'   Use --force to update existing user')
            return

        if email_exists and not force and not user_exists:
            self.stdout.write(self.style.ERROR(f'❌ Email "{email}" already exists!'))
            return

        try:
            if user_exists and force:
                # Update existing user
                user = CustomUser.objects.get(username=username)
                user.email = email
                user.user_type = 'super_admin'
                user.first_name = 'Super'
                user.last_name = 'Admin'
                user.branch_location = 'Head Office'
                user.phone = '+91 7569148233'
                user.set_password(password)
                user.save()
                
                self.stdout.write(self.style.WARNING('=' * 50))
                self.stdout.write(self.style.WARNING('⚠️  EXISTING USER UPDATED!'))
                self.stdout.write(self.style.WARNING('=' * 50))
                self.stdout.write(f'Username: {user.username}')
                self.stdout.write(f'Email: {user.email}')
                self.stdout.write(f'User Type: {user.user_type}')
                self.stdout.write(self.style.WARNING('=' * 50))
                
            else:
                # Create new user
                user = CustomUser.objects.create_user(
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
                
                self.stdout.write(self.style.SUCCESS('=' * 50))
                self.stdout.write(self.style.SUCCESS('✅ SUPER ADMIN CREATED SUCCESSFULLY!'))
                self.stdout.write(self.style.SUCCESS('=' * 50))
                self.stdout.write(f'Username: {user.username}')
                self.stdout.write(f'Email: {user.email}')
                self.stdout.write(f'Password: {password}')
                self.stdout.write(f'User Type: {user.user_type}')
                self.stdout.write(self.style.SUCCESS('=' * 50))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Error: {str(e)}'))
