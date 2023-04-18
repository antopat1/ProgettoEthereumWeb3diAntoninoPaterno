from django import forms
from django.contrib.auth.models import User
from .models import Mnemonic
from exchange_utility.models import Customer, FaucetPatoken


class RegistrazionUserForm(forms.ModelForm):

    username = forms.CharField(widget=forms.TextInput())
    email = forms.CharField(widget=forms.EmailInput())
    password = forms.CharField(widget=forms.PasswordInput())
    conferma_password = forms.CharField(widget=forms.PasswordInput())

    class Meta():
        model = User
        fields = ["username", "email", "password", "conferma_password"]

    def clean(self):  # metodo per validare i dati, nello specifico le due password coincidenti
        super().clean()
        password = self.cleaned_data["password"]
        password_confirm = self.cleaned_data["conferma_password"]
        if password != password_confirm:
            raise forms.ValidationError("Le password non combaciano")
        return self.cleaned_data


class FormMnemonic(forms.ModelForm):
    class Meta():
        model = Mnemonic
        fields = "__all__"


class FormCustomer(forms.ModelForm):
    class Meta():
        model = Customer
        fields = "__all__"
        exclude = ["user", "goerli_patoken_wallet",
                   "user_goerli_Address", "encode_pk_goerli_User"]


class FormFaucet(forms.ModelForm):
    class Meta():
        model = FaucetPatoken
        fields = "__all__"
        exclude = ["user", "deploy_sm_address", "id", "goerli_patoken_wallet", "goerli_deploy_sm_address",
                   "encode_pk_goerli_faucet", "piggyBankScGanacheAddress", "piggyBankScGorliAddress"]
