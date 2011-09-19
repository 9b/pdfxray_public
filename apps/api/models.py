from django.db import models

class api_statistics(models.Model):
    api_key = models.CharField(max_length=100)
    remote_address = models.CharField(max_length=100)
    count = models.IntegerField(max_length=100)