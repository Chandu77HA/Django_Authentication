from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.crypto import get_random_string

# Create your models here.

# Profile Model to create 
class Profile(models.Model):
    """Profile model that extends the default User model by with additional attribute reset_token"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    reset_token = models.CharField(max_length=32, blank=True, null=True)

    def __str__(self):
        return self.user.username

@receiver(post_save, sender=User)
def create_or_update_profile(sender, instance, created, **kwargs):
    """When User instance is saved, using post_save signal if will automatically create a Profile object for the User and generate token value"""
    if created:
        Profile.objects.create(user=instance)
    # Ensure profile exists and is linked to the user after each save
    instance.profile.save()

    # If you want to generate a reset token each time a user is saved (created or updated)
    if not instance.profile.reset_token:
        instance.profile.reset_token = get_random_string(length=32)
        instance.profile.save()
