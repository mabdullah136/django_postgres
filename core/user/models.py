from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    phone = models.CharField(
        max_length=15,
        default="",
        blank=True,
        validators=[
            RegexValidator(
                regex=r'^\+?\d{7,15}$',
                message='Phone number must be between 7 and 15 digits and can include a leading +.',
            )
        ],
    )
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def save(self, *args, **kwargs):
        if self.email:
            self.email = self.email.lower()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username