# cron_jobs.py

import os
import sys
import django

# Setup Django environment
sys.path.append('/path/to/your/project')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'your_project.settings')
django.setup()

# Import and run cleanup
from django.core.management import call_command
call_command('cleanup_audit_logs', days=30)