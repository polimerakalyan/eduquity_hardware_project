# management/commands/cleanup_audit_logs.py

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
import logging
from ...models import AuditLog

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Delete old audit logs automatically'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days to keep logs (default: 30)'
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=1000,
            help='Number of logs to delete per batch (default: 1000)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )
        parser.add_argument(
            '--quiet',
            action='store_true',
            help='Suppress output'
        )

    def handle(self, *args, **options):
        days = options['days']
        batch_size = options['batch_size']
        dry_run = options['dry_run']
        quiet = options['quiet']
        
        cutoff_date = timezone.now() - timedelta(days=days)
        
        # Count logs to delete
        logs_to_delete = AuditLog.objects.filter(created_at__lt=cutoff_date)
        total_count = logs_to_delete.count()
        
        if not quiet:
            self.stdout.write(f"Checking audit logs older than {days} days...")
            self.stdout.write(f"Found {total_count} logs to process.")
        
        if total_count == 0:
            if not quiet:
                self.stdout.write(self.style.SUCCESS("No old logs to delete."))
            return
        
        if dry_run:
            if not quiet:
                self.stdout.write(self.style.WARNING(f"DRY RUN - Would delete {total_count} logs"))
            return
        
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
                
                if not quiet:
                    self.stdout.write(f"Deleted {deleted} logs (total: {total_deleted})")
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error deleting logs: {str(e)}"))
            logger.error(f"Audit log cleanup failed: {str(e)}")
            return
        
        if not quiet:
            self.stdout.write(self.style.SUCCESS(f"Cleanup complete. Deleted {total_deleted} logs."))
        
        # Log the cleanup
        logger.info(f"Audit log cleanup: Deleted {total_deleted} logs older than {days} days")