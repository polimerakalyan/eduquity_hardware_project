from django.apps import AppConfig


class HardwareManagementConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "hardware_management"


# apps.py

from django.apps import AppConfig


class HardwareManagementConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'hardware_management'

    def ready(self):
        import hardware_management.signals  # Register signals