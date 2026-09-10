# management/commands/fix_hardware_branches.py

from django.core.management.base import BaseCommand
from django.db import transaction
from django.apps import apps


class Command(BaseCommand):
    help = 'Fix hardware branch locations for completed cross-branch transfers'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be fixed without making changes',
        )
        parser.add_argument(
            '--transfer-id',
            type=int,
            help='Fix only a specific transfer by ID',
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run', False)
        transfer_id = options.get('transfer_id')
        
        # Get models
        Hardware = apps.get_model('hardware_management', 'Hardware')
        EmployeeHardwareTransfer = apps.get_model('hardware_management', 'EmployeeHardwareTransfer')
        TransferItem = apps.get_model('hardware_management', 'TransferItem')
        
        self.stdout.write(self.style.WARNING('🔍 Checking hardware branch locations...'))
        
        # Filter transfers
        if transfer_id:
            completed_transfers = EmployeeHardwareTransfer.objects.filter(
                id=transfer_id,
                is_cross_branch=True,
                status='completed'
            )
            if not completed_transfers.exists():
                self.stdout.write(self.style.ERROR(f'❌ Transfer #{transfer_id} not found or not completed'))
                return
        else:
            completed_transfers = EmployeeHardwareTransfer.objects.filter(
                is_cross_branch=True,
                status='completed'
            )
        
        fixed_count = 0
        mismatch_count = 0
        
        for transfer in completed_transfers:
            self.stdout.write(f'\n📦 Transfer: {transfer.transfer_id}')
            self.stdout.write(f'   From: {transfer.from_employee.username} ({transfer.from_branch})')
            self.stdout.write(f'   To: {transfer.to_employee.username} ({transfer.to_branch})')
            self.stdout.write('   ────────────────────────────')
            
            for item in TransferItem.objects.filter(transfer=transfer).select_related('hardware'):
                hardware = item.hardware
                expected_branch = transfer.to_branch
                current_branch = hardware.branch_location
                
                if current_branch != expected_branch:
                    mismatch_count += 1
                    self.stdout.write(
                        f'   ❌ {hardware.asset_number}: '
                        f'Current: {current_branch or "Not Assigned"} → Expected: {expected_branch}'
                    )
                    
                    if not dry_run:
                        with transaction.atomic():
                            hardware.branch_location = expected_branch
                            hardware.save(update_fields=['branch_location', 'updated_at'])
                            fixed_count += 1
                            self.stdout.write(
                                self.style.SUCCESS(f'      ✅ Fixed: {hardware.asset_number}')
                            )
                else:
                    self.stdout.write(
                        f'   ✅ {hardware.asset_number}: Branch correct ({current_branch})'
                    )
        
        # Summary
        self.stdout.write('')
        self.stdout.write('=' * 50)
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(f'📊 Found {mismatch_count} mismatches (dry run - no changes made)')
            )
            if mismatch_count > 0:
                self.stdout.write('')
                self.stdout.write('To fix these, run:')
                self.stdout.write('  python manage.py fix_hardware_branches')
        else:
            self.stdout.write(
                self.style.SUCCESS(f'✅ Fixed {fixed_count} hardware branch locations')
            )
            if mismatch_count > 0 and fixed_count == 0:
                self.stdout.write(
                    self.style.WARNING(f'⚠️ {mismatch_count} mismatches found but could not be fixed')
                )
        
        self.stdout.write('=' * 50)