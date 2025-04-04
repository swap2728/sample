# models.py
from django.db import models
from django.utils import timezone
from django.utils.timezone import now

def default_trial_end():
    return timezone.now() + timezone.timedelta(days=3)

class UserSubscription(models.Model):
    user_id = models.IntegerField(unique=True)
    subscription_id = models.CharField(max_length=255, blank=True, null=True, unique=True)
    status = models.CharField(max_length=50, default='trial')
    trial_end = models.DateTimeField(default=default_trial_end)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    def is_valid(self):
        if self.status == 'active':
            return True
        if self.status == 'trial' and timezone.now() < self.trial_end:
            return True
        return False
