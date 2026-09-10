import openai
import json
import time
from datetime import datetime
from django.conf import settings
from django.db.models import Q
from ..models import Hardware, HardwareAssignment, CustomUser, Project

openai.api_key = settings.OPENAI_API_KEY

class HardwareAIAssistant:
    """Advanced AI assistant for hardware management"""
    
    def __init__(self, user):
        self.user = user
        self.conversation_history = []
        self.system_prompt = self._get_system_prompt()
    
    def _get_system_prompt(self):
        """Get system prompt for AI context"""
        return f"""You are an AI hardware management assistant for Eduquity. Your role is to help managers track hardware, assignments, and provide insights.

Current User: {self.user.get_full_name() or self.user.username}
User Role: Manager

CAPABILITIES:
1. Answer questions about hardware inventory
2. Provide assignment status and insights
3. Analyze verification progress
4. Generate reports and summaries
5. Predict maintenance needs
6. Suggest optimizations

RESPONSE FORMAT:
- Be concise but informative
- Use bullet points for lists
- Include emojis for visual appeal
- Provide actionable insights
- Ask clarifying questions when needed

DOMAIN KNOWLEDGE:
You have access to real-time data about hardware inventory, employee assignments, verification status, and project information.

Be helpful, professional, and efficient in your responses."""
    
    def get_hardware_stats(self):
        """Get real-time hardware statistics"""
        return {
            'total': Hardware.objects.filter(created_by=self.user).count(),
            'available': Hardware.objects.filter(created_by=self.user, status='available').count(),
            'assigned': Hardware.objects.filter(created_by=self.user, status='assigned').count(),
            'in_use': Hardware.objects.filter(created_by=self.user, status='in_use').count(),
            'maintenance': Hardware.objects.filter(created_by=self.user, status='maintenance').count(),
        }
    
    def get_assignment_stats(self):
        """Get assignment statistics"""
        today = timezone.now().date()
        assignments = HardwareAssignment.objects.filter(assigned_by=self.user)
        
        return {
            'total': assignments.count(),
            'active': assignments.filter(actual_return_date__isnull=True).count(),
            'overdue': assignments.filter(
                actual_return_date__isnull=True,
                expected_return_date__lt=today
            ).count(),
            'due_soon': assignments.filter(
                actual_return_date__isnull=True,
                expected_return_date__gte=today,
                expected_return_date__lte=today + timedelta(days=3)
            ).count(),
            'returned': assignments.filter(actual_return_date__isnull=False).count(),
        }
    
    def get_verification_stats(self):
        """Get verification statistics"""
        from ..models import SerialEntry
        
        entries = SerialEntry.objects.filter(
            assignment_item__assignment__assigned_by=self.user
        )
        
        return {
            'total': entries.count(),
            'verified': entries.filter(verified=True).count(),
            'pending': entries.filter(verified=False).count(),
        }
    
    def get_hardware_by_type(self):
        """Get hardware grouped by type"""
        from django.db.models import Count
        return Hardware.objects.filter(
            created_by=self.user
        ).values('hardware_type__name').annotate(
            count=Count('id')
        ).order_by('-count')
    
    def search_hardware(self, query):
        """Search hardware by serial or type"""
        return Hardware.objects.filter(
            Q(serial_number__icontains=query) |
            Q(model_name__icontains=query) |
            Q(hardware_type__name__icontains=query),
            created_by=self.user
        )[:10]
    
    def get_employee_hardware(self, employee_name):
        """Get hardware assigned to specific employee"""
        employees = CustomUser.objects.filter(
            user_type='employee',
            manager=self.user,
            username__icontains=employee_name
        ) | CustomUser.objects.filter(
            user_type='employee',
            manager=self.user,
            first_name__icontains=employee_name
        )
        
        if not employees.exists():
            return None
        
        employee = employees.first()
        assignments = HardwareAssignment.objects.filter(
            assigned_by=self.user,
            employee=employee,
            actual_return_date__isnull=True
        )
        
        hardware_list = []
        for assignment in assignments:
            for item in assignment.hardwareassignmentitem_set.all():
                hardware_list.append({
                    'type': item.hardware.hardware_type.name,
                    'serial': item.hardware.serial_number,
                    'model': item.hardware.model_name,
                    'exam_city': assignment.exam_city,
                    'assigned_date': assignment.assigned_date.strftime('%d/%m/%Y'),
                })
        
        return {
            'employee': employee,
            'hardware_count': len(hardware_list),
            'hardware_list': hardware_list,
        }
    
    def generate_response(self, user_message):
        """Generate AI response using OpenAI"""
        start_time = time.time()
        
        # Get real-time data for context
        hardware_stats = self.get_hardware_stats()
        assignment_stats = self.get_assignment_stats()
        verification_stats = self.get_verification_stats()
        hardware_by_type = list(self.get_hardware_by_type())
        
        # Build context for AI
        context = f"""
REAL-TIME DATA:
- Hardware: {hardware_stats['total']} total ({hardware_stats['available']} available, {hardware_stats['assigned']} assigned, {hardware_stats['in_use']} in use, {hardware_stats['maintenance']} maintenance)
- Assignments: {assignment_stats['total']} total ({assignment_stats['active']} active, {assignment_stats['overdue']} overdue, {assignment_stats['due_soon']} due soon)
- Verification: {verification_stats['total']} entries ({verification_stats['verified']} verified, {verification_stats['pending']} pending)
- Hardware by type: {', '.join([f"{h['hardware_type__name']}: {h['count']}" for h in hardware_by_type[:5]])}
"""
        
        # Prepare messages for OpenAI
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "system", "content": f"Current context:\n{context}"},
        ]
        
        # Add conversation history (last 5 exchanges)
        for msg in self.conversation_history[-5:]:
            messages.append(msg)
        
        messages.append({"role": "user", "content": user_message})
        
        try:
            response = openai.ChatCompletion.create(
                model=settings.OPENAI_MODEL,
                messages=messages,
                max_tokens=500,
                temperature=0.7,
            )
            
            ai_response = response.choices[0].message.content
            tokens_used = response.usage.total_tokens
            
            # Update conversation history
            self.conversation_history.append({"role": "user", "content": user_message})
            self.conversation_history.append({"role": "assistant", "content": ai_response})
            
            response_time = time.time() - start_time
            
            return {
                'message': ai_response,
                'tokens_used': tokens_used,
                'response_time': response_time,
                'success': True
            }
            
        except Exception as e:
            return {
                'message': f"Sorry, I encountered an error: {str(e)}. Please try again.",
                'success': False,
                'error': str(e)
            }


def process_ai_message(message, user):
    """Process user message with AI"""
    assistant = HardwareAIAssistant(user)
    
    # Check for specific commands first (faster than AI)
    msg_lower = message.lower()
    
    # Handle specific queries without AI
    if 'total hardware' in msg_lower or 'hardware count' in msg_lower:
        stats = assistant.get_hardware_stats()
        return {
            'message': f"""📊 **Hardware Inventory Summary**

━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 **Total Hardware:** {stats['total']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Available: **{stats['available']}**
📋 Assigned: **{stats['assigned']}**
💻 In Use: **{stats['in_use']}**
🔧 Maintenance: **{stats['maintenance']}**
━━━━━━━━━━━━━━━━━━━━━━━━━━━

Need breakdown by type? Ask for "hardware by type"!""",
            'intent': 'hardware_summary'
        }
    
    elif 'active assignments' in msg_lower:
        stats = assistant.get_assignment_stats()
        return {
            'message': f"""📋 **Assignment Status**

━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 **Total Assignments:** {stats['total']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟢 Active: **{stats['active']}**
🔴 Overdue: **{stats['overdue']}**
🟡 Due Soon: **{stats['due_soon']}**
✅ Returned: **{stats['returned']}**
━━━━━━━━━━━━━━━━━━━━━━━━━━━

Type "show overdue" to see detailed list!""",
            'intent': 'assignments'
        }
    
    elif 'verification' in msg_lower or 'verified' in msg_lower:
        stats = assistant.get_verification_stats()
        return {
            'message': f"""🔐 **Verification Status**

━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 **Total Entries:** {stats['total']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Verified: **{stats['verified']}**
⏳ Pending: **{stats['pending']}**
📈 Completion Rate: **{round((stats['verified']/stats['total']*100) if stats['total'] > 0 else 0, 1)}%**
━━━━━━━━━━━━━━━━━━━━━━━━━━━

Need to verify pending items? Use the verification dashboard!""",
            'intent': 'verification'
        }
    
    # For complex queries, use AI
    elif any(word in msg_lower for word in ['analyze', 'insight', 'recommend', 'predict', 'optimize', 'trend']):
        result = assistant.generate_response(message)
        return {
            'message': result['message'],
            'intent': 'ai_analysis'
        }
    
    else:
        # Use AI for general conversation
        result = assistant.generate_response(message)
        return {
            'message': result['message'],
            'intent': 'ai_chat'
        }