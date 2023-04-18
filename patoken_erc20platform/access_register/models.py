from django.db import models


# Create your models here.

class Mnemonic (models.Model):
    mnemonic = models.CharField(max_length=120)
