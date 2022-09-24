from django.contrib import admin

# Register your models here.

from exchange_utility.models import Customer,FaucetPatoken

admin.site.register(Customer)
admin.site.register(FaucetPatoken)