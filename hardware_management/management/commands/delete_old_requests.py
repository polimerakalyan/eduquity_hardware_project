from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from hardware_management.models import HardwareRequest

class Command(BaseCommand):
    help = 'Delete hardware requests that have been processed for more than 24 hours'

    def handle(self, *args, **options):
        # Calculate the cutoff time (24 hours ago)
        cutoff_time = timezone.now() - timedelta(hours=24)
        
        # Get all processed requests older than 24 hours
        old_requests = HardwareRequest.objects.filter(
            processed_at__lte=cutoff_time
        ).exclude(status='pending')
        
        count = old_requests.count()
        
        if count > 0:
            # Delete the old requests
            old_requests.delete()
            self.stdout.write(
                self.style.SUCCESS(f'Successfully deleted {count} old request(s)')
            )
        else:
            self.stdout.write(
                self.style.SUCCESS('No old requests to delete')
            )