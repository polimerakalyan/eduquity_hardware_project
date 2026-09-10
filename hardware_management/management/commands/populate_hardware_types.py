from django.core.management.base import BaseCommand
from hardware_management.models import HardwareType

class Command(BaseCommand):
    help = 'Populates initial hardware types'
    
    def handle(self, *args, **kwargs):
        hardware_types = [
            'Laptop',
            'Charger',
            'Firewall',
            'CADC Box',
            'Barcode Scanner',
            'L1 Device',
            'Tatwik',
            'Camera',
            'Router',
            'Switch',
            'Printer',
            'Tablet'
        ]
        
        for type_name in hardware_types:
            HardwareType.objects.get_or_create(name=type_name)
        
        self.stdout.write(self.style.SUCCESS('Successfully populated hardware types'))