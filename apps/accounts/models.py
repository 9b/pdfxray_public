from django.db import models
from django.contrib.auth.models import User

class user_profile(models.Model):
    user = models.ForeignKey(User, unique=True)
    api_key = models.CharField(max_length=100)
    company = models.CharField(max_length=100)
    
    def get_api_key(self):
        return self.api_key