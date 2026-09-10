# signals.py

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from .models import EmployeeHardwareTransfer, TransferItem, Hardware


@receiver(post_save, sender=EmployeeHardwareTransfer)
def update_hardware_branch_on_transfer_complete(sender, instance, created, **kwargs):
    """
    Automatically update hardware branch location when transfer is completed
    """
    # Only run when transfer is marked as completed
    if instance.status == 'completed' and instance.is_cross_branch:
        # Get all transfer items for this transfer
        transfer_items = TransferItem.objects.filter(transfer=instance).select_related('hardware')
        
        for item in transfer_items:
            hardware = item.hardware
            # Update hardware branch to receiver's branch
            if hardware.branch_location != instance.to_branch:
                hardware.branch_location = instance.to_branch
                hardware.save(update_fields=['branch_location', 'updated_at'])
                
                # Log the change
                print(f"Signal: Updated hardware {hardware.asset_number} branch to {instance.to_branch}")