from django.db import models
from django.contrib.auth.models import User
# Create your models here.


class Customer(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    patoken_wallet = models.FloatField(default=0)
    goerli_patoken_wallet = models.FloatField(default=0)
    user_ganache_Address = models.CharField(max_length=256, default='null')
    user_goerli_Address = models.CharField(max_length=256, default='null')
    encode_pk_goerli_User = models.CharField(max_length=256, default='null')


class FaucetPatoken(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    patoken_wallet = models.FloatField(default=0)
    goerli_patoken_wallet = models.FloatField(default=0)
    ganache_Address = models.CharField(max_length=256, default='null')
    goerli_Address = models.CharField(max_length=256, default='null')
    deploy_sm_address = models.CharField(
        max_length=256, default='null')  # SC token ERC20
    goerli_deploy_sm_address = models.CharField(max_length=256, default='null')
    piggyBankScGanacheAddress = models.CharField(
        max_length=256, default='null')
    piggyBankScGorliAddress = models.CharField(max_length=256, default='null')
    encode_pk_goerli_faucet = models.CharField(max_length=256, default='null')


class ExtractedEvent(models.Model):
    id = models.AutoField(primary_key=True)
    recipientAddress = models.CharField(max_length=256, default='null')
    senderAddress = models.CharField(max_length=256, default='null')
    amountErcTransfer = models.FloatField(default=0)
    transact = models.CharField(max_length=256, default='null')
    chain = models.CharField(max_length=256, default='Ganache')
