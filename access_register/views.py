from django.shortcuts import render, HttpResponseRedirect, redirect
from django.http import HttpResponse
from .forms import RegistrazionUserForm, FormMnemonic, FormCustomer, FormFaucet
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from exchange_utility.models import Customer, FaucetPatoken,ExtractedEvent
import requests
from django.contrib import messages
import random
from web3 import Web3
from web3.auto import Web3
import json
import os
import subprocess
from django.utils.safestring import mark_safe
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required



#verificare il setting locale Ganache
ganache_url ="http://127.0.0.1:7545" 
web3 = Web3(Web3.HTTPProvider(ganache_url))
parentdir = os.path.dirname(os.getcwd())

#individuazione root dei Json di gestione SC & PK
rootJsonContract = os.path.join(          
    parentdir, 'patoken_erc20platform\\contracts\\Patoken.json')
all_account = web3.eth._get_accounts()
rootJS = os.path.join(parentdir, 'patoken_erc20platform\\keys.json') 

#setting globale
MAX_USER_GANACHE = len(all_account)
FAUCET_ID = 0
GANACHE_MNMONIC = ""
BLOCKCHAIN_CONSISTENCY_CHECK = "False"
FAUCET_ADDRESS = all_account[FAUCET_ID].lower()
MAX_MINTABLE_SC_TOKEN = 10000 


# Create your views here.2

#procedura gestione Json dello SC
def getJsonCompile():
    with open(rootJsonContract) as f:
        info_json = json.load(f)
    return info_json

info_json = getJsonCompile()
abi = info_json["abi"]
bytecode = info_json['bytecode']

#procedura per Deploy SC
def deploySmartContract(adminPk):
    Patoken = web3.eth.contract(abi=abi, bytecode=bytecode)
    wallet_deploy = all_account[0]
    nonce = web3.eth.getTransactionCount(wallet_deploy)
    transaction = Patoken.constructor().buildTransaction(
        {
            "gasPrice": web3.eth.gasPrice,
            "gasPrice": web3.toWei('1', 'gwei'),
            "from": wallet_deploy,
            "nonce": nonce
        }
    )
    signedTx = web3.eth.account.signTransaction(transaction, adminPk)
    signedTx_hash = web3.eth.sendRawTransaction(signedTx.rawTransaction)
    trasaction_receipt = web3.eth.wait_for_transaction_receipt(signedTx_hash)
    contract_Address = trasaction_receipt['contractAddress']
    return contract_Address

#procedura generale per gestione Trasferimento Token
def transferToken(
        contract_ist,
        destination_address,
        sender_address,
        sender_pk,
        quantity_token):
    nonce = web3.eth.getTransactionCount(
        Web3.toChecksumAddress(sender_address))
    transaction = contract_ist.functions.transfer(
        Web3.toChecksumAddress(destination_address),
        web3.toWei(quantity_token, 'ether')).buildTransaction({
            'gas': 70000,
            'gasPrice': web3.toWei('1', 'gwei'),
            'from': sender_address,
            'nonce': nonce
        })
    

    signedTx = web3.eth.account.signTransaction(transaction, sender_pk)
    signedTx_hash = web3.eth.sendRawTransaction(signedTx.rawTransaction)
    encodeTX = Web3.toJSON(signedTx_hash).strip('"')

    return encodeTX

#ottenimento dizionario da interrogazione Blockchain con balance per account
def getAllBalance():
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    contractIstance = web3.eth.contract(
        address=faucet_ready.deploy_sm_address, abi=abi)
    address_balance = []
    faucet_balance = (
        faucet_ready.ganache_Address,
        web3.fromWei(
            contractIstance.functions.balanceOf(
                all_account[FAUCET_ID]).call(),
            'ether'))
    address_balance.append(faucet_balance)
    for ind in range(1, MAX_USER_GANACHE):
        tupleAddress_Balance = (
            all_account[ind].lower(), web3.fromWei(
                contractIstance.functions.balanceOf(
                    all_account[ind]).call(), 'ether'))
        address_balance.append(tupleAddress_Balance)
    return dict(address_balance)

#estrazione evento da singola Tx con parallela archiviazione in dB
def extractEventByTransaction(tx):
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    contractIstance = web3.eth.contract(
        address=faucet_ready.deploy_sm_address, abi=abi)
    receipt = web3.eth.getTransactionReceipt(tx)

    #puntamento agli eventi di Trasferimento token presenti sullo SC Patoken in standard ERC20 
    manage_eventTX = contractIstance.events.Transfer().processReceipt(receipt)
    sender = manage_eventTX[0]['args']['from']
    recipient = manage_eventTX[0]['args']['to']
    amount = str(web3.fromWei(manage_eventTX[0]['args']['value'], 'ether'))
    counter_EvIstance=ExtractedEvent.objects.all().count()
    istance_event = ExtractedEvent(id=counter_EvIstance,recipientAddress=recipient,senderAddress= sender,amountErcTransfer= amount,transact=tx)
    istance_event.save()
    return istance_event

#estrazione array degli eventi di tipo transfer Token dalle Tx in BC
def getTotalExtractedEvents():
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    actualBlock = web3.eth.get_block_number()
    allExtractEvent = []
    for i in range(1, actualBlock + 1):
        iterateTx = web3.eth.get_block(i, full_transactions=True)
        if faucet_ready.deploy_sm_address == iterateTx['transactions'][0]['to']:
            extractHexTx = iterateTx['transactions'][0]['hash']
            encodeTX = Web3.toHex(extractHexTx)
            eventOnTx = extractEventByTransaction(encodeTX)
            eventOnTx.transact = encodeTX
            allExtractEvent.append(eventOnTx)
            for row in ExtractedEvent.objects.all().reverse():
                row.delete()  #---#       
            i += 1
        else:
            i += 1
            continue
    
    #archiviazione su Db degli eventi
    for i in range(0,len(allExtractEvent)):
        istance_event=ExtractedEvent(id=i,recipientAddress=allExtractEvent[i].recipientAddress,senderAddress= allExtractEvent[i].senderAddress,amountErcTransfer= allExtractEvent[i].amountErcTransfer,transact=allExtractEvent[i].transact)
        istance_event.save() #---#

    return allExtractEvent


@staff_member_required()
def showEvent(request):
    if (len(getTotalExtractedEvents()) != 0):
        getEvent = getTotalExtractedEvents()
    else:
        messages.error(
            request,
            f'Occorre prima effettuare delle transazioni associate allo SmartContract PatokenERC20 deployato!')
        return redirect('/')

    context = {'getEvent': getEvent}
    return render(request, 'showevents.html', context)


@staff_member_required()
def showTokenBalances(request):
    if Customer.objects.filter().count() == 0:
        messages.error(
            request,
            f'Occorre registrare degli account associandone un indirizzo della Local Blockchain prima di procedere a questa funzionalità')
        return redirect('/')
    get_balance = getAllBalance()

    context = {'get_balance': get_balance}

    return render(request, 'showbalance.html', context)


@login_required()
def getTotalSupply(request):
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    contractIstance = web3.eth.contract(
        address=faucet_ready.deploy_sm_address, abi=abi)
    TOTALSUPPLY = web3.fromWei(
        contractIstance.functions.totalSupply().call(), 'ether')
    smDeployAdd = faucet_ready.deploy_sm_address
    context = {'TOTALSUPPLY': TOTALSUPPLY, 'smDeployAdd': smDeployAdd}
    return render(request, 'showtotalsupply.html', context)

#homepage condizionale alla corretta sincronizzazione Ganache local BC 
def homepage(request):
    global BLOCKCHAIN_CONSISTENCY_CHECK
    if request.user.is_authenticated and GANACHE_MNMONIC == "":
        messages.error(
            request,
            f'Per proseguire occorre inserire la MNEMONIC phrase della Local Blockchain Ganache! ')
        return redirect('/getMnemonic/')

    if request.user.is_authenticated and not request.user.is_superuser:
        current_customer = Customer.objects.get(user=request.user)
        patokenBalance = getAllBalance()[
            current_customer.user_ganache_Address.lower()]
        context = {'patokenBalance': patokenBalance}
        return render(request, "access_register/homepage.html", context)

    if request.user.is_superuser and BLOCKCHAIN_CONSISTENCY_CHECK == "False":

        admin = User.objects.filter(is_superuser=True)
        if FaucetPatoken.objects.filter().count() == 0:
            faucet = FaucetPatoken(
                user=admin[0],
                ganache_Address=all_account[FAUCET_ID].lower())
            getPk = getPrivatekey(faucet.ganache_Address, request)
            faucet.deploy_sm_address = deploySmartContract(getPk)
            faucet.patoken_wallet = MAX_MINTABLE_SC_TOKEN
            faucet.save()
        faucetAdminBalance = getAllBalance()[FAUCET_ADDRESS]
        context = {'faucetAdminBalance': faucetAdminBalance}
        return render(request, "access_register/homepage.html", context)

    if not request.user.is_authenticated:
        numberCustomers = Customer.objects.filter().count()
        numFaucet = FaucetPatoken.objects.filter().count()
        ceckFull = int(MAX_USER_GANACHE - numberCustomers - 1)
        context = {
            'MAX_USER_GANACHE': MAX_USER_GANACHE,
            'numberCustomers': numberCustomers,
            'ceckFull': ceckFull,
            'numFaucet': numFaucet}
        return render(request, "access_register/homepage.html", context)

    return render(request, "access_register/homepage.html")


def registrazion(request):
    n_user = User.objects.filter(is_superuser=True).count()

    if (GANACHE_MNMONIC == ""):
        messages.error(
            request,
            f'Attenzione, occorre prima sincronizzarsi con la blockchain locale in esecuizione attraverso la Mnemonic phrase Ganache')
        return redirect('/getMnemonic/')

    if n_user == 0:
        messages.error(
            request,
            f'Attenzione, creare prima dalla console sviluppatore un account Administrator! #python manage.py createsuperuser#')
        return redirect('/')

    else:
        admin = User.objects.filter(is_superuser=True)
        faucet = FaucetPatoken(
            user=admin[0],
            ganache_Address=all_account[FAUCET_ID].lower())
    
    #condizione iniziale che forza il deploy dello SC
    if (GANACHE_MNMONIC != ""):
        getPk = getPrivatekey(faucet.ganache_Address, request)
        if FaucetPatoken.objects.filter().count() == 0:
            faucet.deploy_sm_address = deploySmartContract(getPk)
            faucet.patoken_wallet = MAX_MINTABLE_SC_TOKEN
            faucet.save()
    else:
        print("Null")

    if request.method == "POST":
        form = RegistrazionUserForm(request.POST)
        try:
            if form.is_valid():
                username = form.cleaned_data["username"]
                email = form.cleaned_data["email"]
                password = form.cleaned_data["password"]
                new_user = User.objects.create_user(
                    username=username, password=password, email=email)

                numberCustomers = Customer.objects.filter().count()

                if (numberCustomers < MAX_USER_GANACHE -
                        1):  # '-1' per considerare il primo address associato al Faucet
                    new_customer = Customer(user=new_user)
                    new_customer.patoken_wallet = random.randrange(100, 200)

                    i = 0
                    while i < MAX_USER_GANACHE:
                        ganacheAddress = all_account[numberCustomers + 1 + i]
                        if (Customer.objects.filter(
                                user_ganache_Address=ganacheAddress).count() == 0):
                            new_customer.user_ganache_Address = ganacheAddress
                            new_customer.save()
                            break
                        else:
                            i += 1
                    #traferimento effettivo Erc20 Patoken rispetto all'attribuzione randomica implementata su Db 
                    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
                    getPk = getPrivatekey(
                        faucet_ready.ganache_Address, request)
                    contractIstance = web3.eth.contract(
                        address=faucet_ready.deploy_sm_address, abi=abi)
                    quantity_token = new_customer.patoken_wallet
                    faucet_ready.patoken_wallet -= quantity_token
                    faucet_ready.save()

                    Tx = transferToken(
                        contractIstance,
                        new_customer.user_ganache_Address,
                        all_account[FAUCET_ID],
                        getPk,
                        quantity_token)
                    new_user = authenticate(
                        username=username, password=password)
                    login(request, new_user)

                messages.success(
                    request,
                    f'Benvenuto/a! {new_customer.user.username}, la piattaforma attribuisce i seguenti patokenERC20 al tuo wallet : {new_customer.patoken_wallet} , di seguito il TX associato: {Tx}')
                return redirect('/')
        except BaseException:
            messages.error(
                request,
                f'Attenzione raggiunto il numero massimo di utenti registrabili, in relazione al setting Ganache N° Accounts su BlockChain Locale! Contattare Admin per eventuale cancellazione Account Obsoleto su dB')

    else:
        form = RegistrazionUserForm()
    context = {"form": form}
    return render(request, "registration/registrazione.html", context)

#automatismo per semplificare la customer experience e gestione Account/PK, limitando 
#la procedura di sincronizzazione dell'utente all'inserimento della MNEMONIC phrase del Ganache WORKSPACE local BC
def getPrivatekey(address, request):
    global BLOCKCHAIN_CONSISTENCY_CHECK
    timeout_s = 3
    try:
        subprocess.run(
            'ganache-cli -m ' +
            '"' +
            str(GANACHE_MNMONIC) +
            '"' +
            ' --account_keys_path keys.json',
            shell=True,
            timeout=timeout_s)

    except subprocess.TimeoutExpired:
        print('*-*')

    with open(rootJS) as js:
        json_data = json.load(js)
    couple_json = json_data["private_keys"]
    i = 0
    setKey = []

    while i != MAX_USER_GANACHE:
        try:
            couple = (all_account[i].lower(),
                      json_data["private_keys"][all_account[i].lower()])
            setKey.append(couple)
            i += 1
        
        except BaseException:
            BLOCKCHAIN_CONSISTENCY_CHECK = "True"
            os.remove(rootJS)
            return "ko"
            break

    dictSetKey = dict(setKey)

    #per sicurezza oltre a non archiviare le PK nel dB cancello il Json di supporto usato per lo scopo
    os.remove(rootJS)
    return dictSetKey[address]

#procedura di acquisizione Mnemonic per sincronizzazione istanza Ganache
def getMnemonic(request):
    global GANACHE_MNMONIC
    global BLOCKCHAIN_CONSISTENCY_CHECK
    if request.method == "POST":
        form_w = FormMnemonic(request.POST)
        if form_w.is_valid():
            choice = form_w.save(commit=False)
            GANACHE_MNMONIC = str(choice.mnemonic)
            getPrivatekey(FAUCET_ADDRESS, request)
            if BLOCKCHAIN_CONSISTENCY_CHECK == "True":
                BLOCKCHAIN_CONSISTENCY_CHECK = "False"
                messages.error(
                    request,
                    'Attenzione:la MNEMONIC phrase inserita non corrisponde all attuale ganache WORKSPACE local Blockchain! Riprova!')
                GANACHE_MNMONIC = ""
                return redirect('/getMnemonic/')
            else:
                address_account = ""
                for ind in range(0, MAX_USER_GANACHE):
                    address_account += all_account[ind] + " "

                messages.error(
                    request,
                    "Importati i seguenti address degli Account Ganache local BC: " +
                    mark_safe(address_account))  # + "----------Address corrente account loggato: " + all_account[0]
                return redirect('/')
    else:
        form_w = FormMnemonic()

    context = {"form_w": form_w}
    return render(request, "access_register/form4.html", context)

#gestione trasferimento Token con uso combinato features precedenti
@login_required()
def showAddressTransferToken(request):
    if Customer.objects.filter().count() == 0:
        messages.error(
            request,
            f'Occorre registrare degli account associandone un indirizzo della Local Blockchain prima di procedere a questa funzionalità')
        return redirect('/')

    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    customers = Customer.objects.filter()
    faucetAddress = faucet_ready.ganache_Address
    faucetUser = faucet_ready.user
    contractIstance = web3.eth.contract(
        address=faucet_ready.deploy_sm_address, abi=abi)
    user_current = None

    if request.user.is_superuser:
        currentBalance = getAllBalance()[FAUCET_ADDRESS]
        if request.method == "POST":
            form_w = FormFaucet(request.POST)
            if form_w.is_valid():
                form_w = form_w.save(commit=False)
                quantityToTransefer = form_w.patoken_wallet
                addressDestination = form_w.ganache_Address
                getPk = getPrivatekey(faucetAddress, request)
                extractBalance = getAllBalance()

                allowedAddress = ""
                i = 0
                while i < len(extractBalance):
                    allowedAddress += all_account[i]
                    i += 1

                if len(addressDestination) != 42 or allowedAddress.find(
                        addressDestination) == -1:
                    messages.success(
                        request, f'Attenzione, indirizzo inserito non corretto, riprova')
                    return redirect('/showAddressTransferToken/')

                if extractBalance[all_account[FAUCET_ID].lower()
                                  ] > quantityToTransefer:

                    Tx = transferToken(
                        contractIstance,
                        addressDestination,
                        all_account[FAUCET_ID],
                        getPk,
                        quantityToTransefer)
                    faucet_ready.patoken_wallet -= quantityToTransefer
                    faucet_ready.save()
                    messages.success(
                        request,
                        f'Richiesta trasferimento Token propagata correttamente in Blockchain! Di seguito identificatvo Tx: ' +Tx)
                    return redirect('/showAddressTransferToken/')
                else:
                    messages.error(
                        request, f'Non si dispone della quantità di token indicata')
                    return redirect('/showAddressTransferToken/')

        else:
            form_w = FormFaucet()

    else:
        current_customer = Customer.objects.get(user=request.user)
        user_current = current_customer.user
        currentBalance = getAllBalance()[
            current_customer.user_ganache_Address.lower()]
        if request.method == "POST":
            form_w = FormCustomer(request.POST)
            if form_w.is_valid():
                form_w = form_w.save(commit=False)
                quantityToTransefer = form_w.patoken_wallet
                addressDestination = form_w.user_ganache_Address

                getPk = getPrivatekey(
                    current_customer.user_ganache_Address.lower(), request)
                extractBalance = getAllBalance()

                allowedAddress = str(FAUCET_ADDRESS)
                i = 0
                while i < len(extractBalance):
                    allowedAddress += all_account[i]
                    i += 1

                if len(addressDestination) != 42 or allowedAddress.find(
                        addressDestination) == -1:
                    print(addressDestination.lower())
                    print(all_account[FAUCET_ID].lower())
                    messages.success(
                        request, f'Attenzione, indirizzo inserito non corretto, riprova')
                    return redirect('/showAddressTransferToken/')

                if extractBalance[current_customer.user_ganache_Address.lower(
                )] > quantityToTransefer:

                    Tx = transferToken(contractIstance, addressDestination, str(
                        current_customer.user_ganache_Address), getPk, quantityToTransefer)
                    current_customer.patoken_wallet -= quantityToTransefer

                    messages.success(
                        request,
                        f'Richiesta trasferimento Token propagata correttamente in Blockchain! Di seguito identificatvo Tx: ' +Tx)
                    return redirect('/showAddressTransferToken/')
                else:
                    messages.error(
                        request, f'Non si dispone della quantità di token indicata')
                    return redirect('/showAddressTransferToken/')

        else:
            form_w = FormCustomer()

    context = {
        "form_w": form_w,
        'customers': customers,
        'faucetAddress': faucetAddress,
        'faucetUser': faucetUser,
        'currentBalance': currentBalance,
        'user_current': user_current}
    return render(request, "balancesTransfer.html", context)
