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
from access_register.views import registrazion, homepage, getMnemonic, showTokenBalances, getTotalSupply, showAddressTransferToken, showEvent, viewGoerli, updateGoerliETHBalance, updateGoerliERC20Balance, getBalanceOnMoneyBox, getWithdrawERC20view, boostEthOnCongestion

from django.contrib.staticfiles.urls import staticfiles_urlpatterns

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
        'showTokenBalances/<str:ganacheOrGoerli>/',
        showTokenBalances,
        name="showTokenBalances"),
    path(
        'getTotalSupply/<str:ganacheOrGoerli>',
        getTotalSupply,
        name="getTotalSupply"),
    path(
        'showAddressTransferToken/<str:ganacheOrGoerli>/',
        showAddressTransferToken,
        name="showAddressTransferToken"),
    path(
        'showEvent/',
        showEvent,
        name="showEvent"),
    path(
        'viewGoerli/',
        viewGoerli,
        name="viewGoerli"),
    path(
        'updateGoerliETHBalance/',
        updateGoerliETHBalance,
        name="updateGoerliETHBalance"),
    path(
        'updateGoerliERC20Balance/<str:singolOrAll>/',
        updateGoerliERC20Balance,
        name="updateGoerliERC20Balance"),
    path(
        'getBalanceOnMoneyBox/<str:ganacheOrGoerli>/',
        getBalanceOnMoneyBox,
        name="getBalanceOnMoneyBox"),
    path(
        'getWithdrawERC20view/<str:ganacheOrGoerli>/',
        getWithdrawERC20view,
        name="getWithdrawERC20view"),
    path(
        'boostEthOnCongestion/',
        boostEthOnCongestion,
        name="boostEthOnCongestion"),
]

urlpatterns += [
    path('accounts/', include('django.contrib.auth.urls')),
]

urlpatterns += staticfiles_urlpatterns()
