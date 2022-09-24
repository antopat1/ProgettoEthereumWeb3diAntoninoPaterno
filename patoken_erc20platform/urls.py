"""patoken_erc20platform URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from access_register.views import registrazion, homepage, getMnemonic, showTokenBalances, getTotalSupply, showAddressTransferToken, showEvent

urlpatterns = [
    path(
        'admin/',
        admin.site.urls),
    path(
        '',
        homepage,
        name="homepage"),
    path(
        'registrazion/',
        registrazion,
        name="registrazion"),
    path(
        'getMnemonic/',
        getMnemonic,
        name="getMnemonic"),
    path(
        'showTokenBalances/',
        showTokenBalances,
        name="showTokenBalances"),
    path(
        'getTotalSupply/',
        getTotalSupply,
        name="getTotalSupply"),
    path(
        'showAddressTransferToken/',
        showAddressTransferToken,
        name="showAddressTransferToken"),
    path(
        'showEvent/',
        showEvent,
        name="showEvent"),
]

urlpatterns += [
    path('accounts/', include('django.contrib.auth.urls')),
]
