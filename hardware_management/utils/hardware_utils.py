# utils/hardware_utils.py

from django.db import transaction
from .models import Hardware, EmployeeHardwareTransfer, TransferItem


def verify_and_fix_hardware_branch(transfer_id=None):
    """
    Verify and optionally fix hardware branch locations
    """
    if transfer_id:
        transfers = EmployeeHardwareTransfer.objects.filter(id=transfer_id)
    else:
        transfers = EmployeeHardwareTransfer.objects.filter(
            is_cross_branch=True,
            status='completed'
        )
    
    results = []
    for transfer in transfers:
        for item in TransferItem.objects.filter(transfer=transfer).select_related('hardware'):
            hardware = item.hardware
            if hardware.branch_location != transfer.to_branch:
                with transaction.atomic():
                    old_branch = hardware.branch_location
                    hardware.branch_location = transfer.to_branch
                    hardware.save(update_fields=['branch_location', 'updated_at'])
                    results.append({
                        'transfer_id': transfer.transfer_id,
                        'hardware_id': hardware.id,
                        'asset_number': hardware.asset_number,
                        'old_branch': old_branch,
                        'new_branch': transfer.to_branch,
                        'fixed': True
                    })
    
    return results