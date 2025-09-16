from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import hashlib


def generate_fingerprint(username: str, password: str) -> str:
    data = f"{username}:{password}".encode('utf-8')
    return hashlib.sha256(data).hexdigest()


class LoginFingerprint(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='login_fingerprint')
    fingerprint = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self) -> str:
        return f"LoginFingerprint(user={self.user.username})"

# Create your models here.
