from eth_utils import to_wei, from_wei
from django.shortcuts import render, HttpResponseRedirect, redirect
from django.http import HttpResponse
from .forms import RegistrazionUserForm, FormMnemonic, FormCustomer, FormFaucet
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from exchange_utility.models import Customer, FaucetPatoken, ExtractedEvent
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
from cryptography.fernet import Fernet
import pickle
import time
from django.contrib.auth.signals import user_logged_out
from django.dispatch import receiver
from web3.gas_strategies.time_based import medium_gas_price_strategy
from web3.middleware import geth_poa_middleware
from web3.gas_strategies.time_based import fast_gas_price_strategy

# Sincronizzazione ad API Key Etherscan per individuazione corretta strategia GAS
from ethereum_gasprice import GaspriceController, GaspriceStrategy, EthereumUnit
from ethereum_gasprice.providers import EtherscanProvider
ETHERSCAN_API_KEY = "8TR65Q8RYPJFI1I2DRWVCUJH2BS3728CQF"
controller = GaspriceController(
    settings={EtherscanProvider.title: ETHERSCAN_API_KEY},
)

# verificare il proprio setting locale Ganache
ganache_url = "http://127.0.0.1:8546"
web3 = Web3(Web3.HTTPProvider(ganache_url))
parentdir = os.path.dirname(os.getcwd())

# personal API Key --> Infura
w3g = Web3(Web3.HTTPProvider(
    'https://goerli.infura.io/v3/ab69f53ad93a4ba7bf63485df2a338d9',  request_kwargs={'timeout': 30}))

# individuazione root dei Json di: "gestione SmartContract" precedentemente compilati
# & "Meccanismo Gestione PK" EoA su Local Blockchain Ganache

rootJsonContract = os.path.join(
    parentdir, 'patoken_erc20platform\\contracts\\Patoken.json')
all_account = web3.eth._get_accounts()
rootJS = os.path.join(parentdir, 'patoken_erc20platform\\keys.json')

# puntamento SC distribuzione Test Eth
rootJsonFaucet = os.path.join(
    parentdir, 'patoken_erc20platform\\contracts\\BootFaucet.json')

# puntamento SC Salvadanaio custodia Token
rootJsonMoneyBox = os.path.join(
    parentdir, 'patoken_erc20platform\\contracts\\MoneyBoxErc20.json')

# setting globale
MAX_USER_GANACHE = len(all_account)
FAUCET_ID = 0
GANACHE_MNMONIC = ""
BLOCKCHAIN_CONSISTENCY_CHECK = "False"
FAUCET_ADDRESS = all_account[FAUCET_ID].lower()
MAX_MINTABLE_SC_TOKEN = 10000
FERNET_OBJECTS = []

# puntamento al file binario generato dalla libreria pickle contenente oggetto Fernet
# utilizzato per crittografare e decrittografare dati in modo sicuro
FernetFile = os.path.join(
    parentdir,
    'patoken_erc20platform\\systemFernet.pickle')
checkFernetExist = os.path.exists(FernetFile)
STARTLOOP = False
FIRST_ACCESS = True
GLOBAL_CONTEXT = None
BOOST_ETH = None

# dizionario per evitare tentativi di propagazione Tx multiple su Goerli
AVOID_MULTIMPLE_EOA_TX = {}

# SC precedentemente deployato e alimentato dallo sviluppatore con fondi
# Test allo scopo di distribuire EthTest agli EoA creati nel contesto
BOOT_FAUCETGoerliSC_Address = '0x982c1CFfdef5FabC5F9dCd3b7dAe8F8f9711955A'

# creazione EoA su BC Goerli EP INFURA

def creteGoerliEoA():
    eoa = w3g.eth.account.create()
    privateKey = eoa.privateKey.hex()
    address = eoa.address
    return address, privateKey


def createCryptographicKey():
    key = Fernet.generate_key()
    return key


# creazione oggetto Fernet dalla key prima generata serializzandolo con modulo pickle
# e salvandolo su File

def manageCryptPk():
    key = createCryptographicKey()
    f = Fernet(key)
    FERNET_OBJECTS.append(f)
    with open("systemFernet.pickle", "wb") as file_handle:
        pickle.dump(FERNET_OBJECTS, file_handle, pickle.HIGHEST_PROTOCOL)
    return f

# usa oggetto Fernet salvato su file per cifrare testo in Input

def goCript(text):
    with open("systemFernet.pickle", "rb") as file_handle:
        FERNET_OBJECTS = pickle.load(file_handle)
    fe = FERNET_OBJECTS[0]
    encryptedText = fe.encrypt(text.encode('utf-8')).decode('utf-8')
    return encryptedText

# usa oggetto Fernet salvato su file per decifrare testo in Input

def goDecript(cripText):
    with open("systemFernet.pickle", "rb") as file_handle:
        FERNET_OBJECTS = pickle.load(file_handle)
    fe = FERNET_OBJECTS[0]
    decrypted = fe.decrypt(cripText).decode()
    return decrypted


# Qualora il file Binario Fernet non esista lo crea essendo alla base delle altre funzioni crittografiche
if not checkFernetExist:
    manageCryptPk()


# reimposta principali variabili globali di controllo consistenza al loro
# valore iniziale in caso di LogOut

@receiver(user_logged_out)
def handle_user_logged_out(sender, user, request, **kwargs):
    BLOCKCHAIN_CONSISTENCY_CHECK = "False"
    FIRST_ACCESS = True
    AVOID_MULTIMPLE_EOA_TX = {}


# procedura gestione ed indentificazione Json dello SC

def getJsonCompile(identifirSourceContract):
    if identifirSourceContract == "erc20Token":
        with open(rootJsonContract) as fT:
            info_json = json.load(fT)
    elif identifirSourceContract == "faucetTestGoeliEth":
        with open(rootJsonFaucet) as fF:
            info_json = json.load(fF)
    elif identifirSourceContract == "MoneyBoxErc20":
        with open(rootJsonMoneyBox) as fM:
            info_json = json.load(fM)
    return info_json


# richiamo Json e da questi ABI e Bytecode dei 3 SmartContract
info_json = getJsonCompile("erc20Token")
abi = info_json["abi"]
bytecode = info_json['bytecode']

info_jsonFaucet = getJsonCompile("faucetTestGoeliEth")
abiFaucet = info_jsonFaucet["abi"]

info_jsonMoneyBox = getJsonCompile("MoneyBoxErc20")
abiMB = info_jsonMoneyBox["abi"]
bytecodeMB = info_jsonMoneyBox['bytecode']


# ritiro multichain Token con meccanismo di polling ricevuta conferma TX

def withdrawERC20fromMoneyBox(
        addressAccount,
        pkAccount,
        chain,
        piggyBankSc,
        amount):

    if chain == web3:  # ganache
        contract = web3.eth.contract(address=piggyBankSc, abi=abiMB)
        try:
            nonce = chain.eth.getTransactionCount(
                Web3.toChecksumAddress(addressAccount))
            transaction = contract.functions.withdrawERC20ForUser(amount).buildTransaction(
                {"gasPrice": chain.eth.gasPrice, "from": addressAccount, "nonce": nonce})
            gas_limit = chain.eth.estimateGas(transaction)
            transaction["gas"] = gas_limit
            signedTx = chain.eth.account.signTransaction(
                transaction, pkAccount)
            signedTx_hash = chain.eth.sendRawTransaction(
                signedTx.rawTransaction)
            encodeTX = Web3.toJSON(signedTx_hash).strip('"')
            while True:
                tx_info = chain.eth.getTransaction(signedTx_hash)
                if tx_info.blockNumber is not None:
                    tx_receipt = chain.eth.getTransactionReceipt(signedTx_hash)
                    break
                time.sleep(2)
            return encodeTX
        except Exception as e:
            error_message = str(e)
            error_message = error_message.split("revert ")[1]
            return error_message

    elif chain == w3g:  # gorli

        contract = chain.eth.contract(address=piggyBankSc, abi=abiMB)
        gas_price = controller.get_gasprice_by_strategy(GaspriceStrategy.FAST)
        gas_price += int(gas_price * 0.05)
        base_fee = w3g.eth.get_block("latest").baseFeePerGas
        max_fee_per_gas = int(gas_price * 1.5) + base_fee

        try:
            nonce = chain.eth.getTransactionCount(
                Web3.toChecksumAddress(addressAccount))
            transaction = contract.functions.withdrawERC20ForUser(amount).buildTransaction(
                {"gasPrice": max_fee_per_gas, "from": addressAccount, "nonce": nonce})  # ,'gas': gas_limit

            gas_limit = chain.eth.estimateGas(transaction)
            gas_limit += int(gas_limit * 0.2)
            transaction["gas"] = gas_limit

            signedTx = chain.eth.account.signTransaction(
                transaction, pkAccount)
            signedTx_hash = chain.eth.sendRawTransaction(
                signedTx.rawTransaction)
            encodeTX = Web3.toJSON(signedTx_hash).strip('"')
            return send_tx(chain, transaction, signedTx_hash, pkAccount)
        except Exception as e:
            error_message = str(e)
            error_message = error_message.split("revert ")[1]
            return error_message


# richiamo funzione SC MoneyBox per ceck deposito Token specifico EoA

def verifyERC20EoaBalanceOnMoneyBox(ceckAddress, chain, piggyBankSc):
    if chain == web3:
        contract = web3.eth.contract(address=piggyBankSc, abi=abiMB)
    elif chain == w3g:
        contract = w3g.eth.contract(address=piggyBankSc, abi=abiMB)
    balance = web3.fromWei(contract.functions.getERC20balanceForUser(
        ceckAddress).call({'from': ceckAddress}), 'ether')
    return balance

# controlla se un EoA possa usare ovvero sia in WhiteList su MoneyBox SC

def verifyEoAWhiteList(ceckAddress, chain, piggyBankSc):
    if chain == web3:
        contract = web3.eth.contract(address=piggyBankSc, abi=abiMB)
    elif chain == w3g:
        contract = w3g.eth.contract(address=piggyBankSc, abi=abiMB)
    verifyEoA = contract.functions.verifyUser(ceckAddress).call()
    return verifyEoA

# i depositi su SC MoneyBox richiedono che l'EOA approvi prima sullo SC ERC20 la spesa ( chain == web3 -> GANACHE ; chain == w3g -> Goerli )

def approveSpend(
        chooseChain,
        ercSC,
        sender_address,
        sender_pk,
        addressDelegateToSpend,
        quantity):
    chain = selectChain(chooseChain, sender_address)[0]
    contract = chain.eth.contract(address=ercSC, abi=abi)
    if chain == web3:
        try:
            nonce = chain.eth.getTransactionCount(
                Web3.toChecksumAddress(sender_address))
            transaction = contract.functions.approve(addressDelegateToSpend, chain.toWei(quantity, 'ether')).buildTransaction({
                "gasPrice": chain.eth.gasPrice, "from": sender_address, "nonce": nonce})
            gas_limit = chain.eth.estimateGas(transaction)
            transaction["gas"] = gas_limit
            signedTx = chain.eth.account.signTransaction(
                transaction, sender_pk)
            signedTx_hash = chain.eth.sendRawTransaction(
                signedTx.rawTransaction)
            encodeTX = Web3.toJSON(signedTx_hash).strip('"')
            while True:
                tx_info = chain.eth.getTransaction(signedTx_hash)
                if tx_info.blockNumber is not None:
                    tx_receipt = chain.eth.getTransactionReceipt(signedTx_hash)
                    break
                time.sleep(2)
            return encodeTX
        except Exception as e:
            error_message = str(e)
            error_message = error_message.split("revert ")[1]
            return error_message

    elif chain == w3g:
        gas_price = controller.get_gasprice_by_strategy(GaspriceStrategy.FAST)
        gas_price += int(gas_price * 0.05)
        base_fee = w3g.eth.get_block("latest").baseFeePerGas
        max_fee_per_gas = int(gas_price * 1.5) + base_fee

        try:
            nonce = chain.eth.getTransactionCount(
                Web3.toChecksumAddress(sender_address))
            transaction = contract.functions.approve(addressDelegateToSpend, chain.toWei(
                quantity, 'ether')).buildTransaction({"gasPrice": max_fee_per_gas, "from": sender_address, "nonce": nonce})
            gas_limit = chain.eth.estimateGas(transaction)
            gas_limit += int(gas_limit * 0.2)
            transaction["gas"] = gas_limit

            signedTx = chain.eth.account.signTransaction(
                transaction, sender_pk)
            signedTx_hash = chain.eth.sendRawTransaction(
                signedTx.rawTransaction)
            encodeTX = Web3.toJSON(signedTx_hash).strip('"')
            return send_tx(chain, transaction, signedTx_hash, sender_pk)
        except Exception as e:
            error_message = str(e)
            error_message = error_message.split("revert ")[1]
            return error_message

# implementazione effettivo deposito su MoneyBox previa approvazione spesa ( chain == web3 -> GANACHE ; chain == w3g -> Goerli )

def depositERC20onMoneyBox(
        chooseChain,
        ercSC,
        piggyBankSC,
        sender_address,
        sender_pk,
        quantity_token):

    chain = selectChain(chooseChain, sender_address)[0]

    approve_tx = approveSpend(
        chooseChain,
        ercSC,
        sender_address,
        sender_pk,
        piggyBankSC,
        quantity_token)

    while True:
        approve_tx_receipt = chain.eth.getTransactionReceipt(approve_tx)
        if approve_tx_receipt is not None and approve_tx_receipt.status == 1:
            break
        time.sleep(2)

    contract_ist = chain.eth.contract(address=piggyBankSC, abi=abiMB)

    if chain == web3:
        try:
            nonce = chain.eth.getTransactionCount(
                Web3.toChecksumAddress(sender_address))
            transaction = contract_ist.functions.depositErc20(chain.toWei(quantity_token, 'ether')).buildTransaction(
                {"gasPrice": chain.eth.gasPrice, "from": sender_address, "nonce": nonce})
            gas_limit = chain.eth.estimateGas(transaction)
            transaction["gas"] = gas_limit
            signedTx = chain.eth.account.signTransaction(
                transaction, sender_pk)
            signedTx_hash = chain.eth.sendRawTransaction(
                signedTx.rawTransaction)
            encodeTX = Web3.toJSON(signedTx_hash).strip('"')
            while True:
                tx_info = chain.eth.getTransaction(signedTx_hash)
                if tx_info.blockNumber is not None:
                    tx_receipt = chain.eth.getTransactionReceipt(signedTx_hash)
                    break
                time.sleep(2)
            return encodeTX
        except Exception as e:
            error_message = str(e)
            error_message = error_message.split("revert ")[1]
            return error_message

    elif chain == w3g:
        gas_price = controller.get_gasprice_by_strategy(GaspriceStrategy.FAST)
        gas_price += int(gas_price * 0.05)
        base_fee = w3g.eth.get_block("latest").baseFeePerGas
        max_fee_per_gas = int(gas_price * 1.5) + base_fee

        try:
            nonce = chain.eth.getTransactionCount(
                Web3.toChecksumAddress(sender_address))
            transaction = contract_ist.functions.depositErc20(chain.toWei(quantity_token, 'ether')).buildTransaction(
                {"gasPrice": max_fee_per_gas, "from": sender_address, "nonce": nonce})

            gas_limit = chain.eth.estimateGas(transaction)
            gas_limit += int(gas_limit * 0.2)
            transaction["gas"] = gas_limit

            signedTx = chain.eth.account.signTransaction(
                transaction, sender_pk)
            signedTx_hash = chain.eth.sendRawTransaction(
                signedTx.rawTransaction)
            encodeTX = Web3.toJSON(signedTx_hash).strip('"')
            return send_tx(chain, transaction, signedTx_hash, sender_pk)
        except Exception as e:
            error_message = str(e)
            error_message = error_message.split("revert ")[1]
            return error_message

# un EOA appena creato in Piattaforma può depositare su MoneyBox previa aggiunta in whiteLisy ( chain == web3 -> GANACHE ; chain == w3g -> Goerli )
def addWhiteList(
        chooseChain,
        newAddress,
        piggyBankSC,
        sender_address,
        sender_pk):

    chain = selectChain(chooseChain, sender_address)[0]
    contractIstance = chain.eth.contract(address=piggyBankSC, abi=abiMB)
    if chain == web3:
        try:
            nonce = chain.eth.getTransactionCount(
                chain.toChecksumAddress(sender_address))
            transaction = contractIstance.functions.addUserInPlatform(newAddress).buildTransaction(
                {"gasPrice": chain.eth.gasPrice, "from": sender_address, "nonce": nonce})
            gas_limit = chain.eth.estimateGas(transaction)
            transaction["gas"] = gas_limit
            signedTx = chain.eth.account.signTransaction(
                transaction, sender_pk)
            signedTx_hash = chain.eth.sendRawTransaction(
                signedTx.rawTransaction)
            encodeTX = Web3.toJSON(signedTx_hash).strip('"')
            while True:
                tx_info = chain.eth.getTransaction(signedTx_hash)
                if tx_info.blockNumber is not None:
                    tx_receipt = chain.eth.getTransactionReceipt(signedTx_hash)
                    break
                time.sleep(2)
            return encodeTX
        except Exception as e:
            error_message = str(e)
            error_message = error_message.split("revert ")[1]
            return error_message
    elif chain == w3g:
        gas_price = controller.get_gasprice_by_strategy(GaspriceStrategy.FAST)
        gas_price += int(gas_price * 0.05)
        base_fee = w3g.eth.get_block("latest").baseFeePerGas
        max_fee_per_gas = int(gas_price * 1.5) + base_fee
        try:
            nonce = chain.eth.getTransactionCount(
                Web3.toChecksumAddress(sender_address))
            transaction = contractIstance.functions.addUserInPlatform(newAddress).buildTransaction(
                {"gasPrice": max_fee_per_gas, "from": sender_address, "nonce": nonce})

            gas_limit = chain.eth.estimateGas(transaction)
            gas_limit += int(gas_limit * 0.2)
            transaction["gas"] = gas_limit

            signedTx = chain.eth.account.signTransaction(
                transaction, sender_pk)
            signedTx_hash = chain.eth.sendRawTransaction(
                signedTx.rawTransaction)
            encodeTX = Web3.toJSON(signedTx_hash).strip('"')
            return send_tx(chain, transaction, signedTx_hash, sender_pk)

        except Exception as e:
            error_message = str(e)
            error_message = error_message.split("revert ")[1]
            return error_message

# meccanismo per riuso codice sulle due chain
def selectChain(chooseChain, forwardingChainAddress):

    if chooseChain == "localGanache":
        chain = web3
        chainId = web3.eth.chain_id
        wallet_deploy = all_account[0]
    elif chooseChain == "gorli":
        chain = w3g
        chainId = 5
        wallet_deploy = forwardingChainAddress

    return chain, chainId, wallet_deploy

# Implementazione funzione per assegnare TestEth ai nuovi EoA reperendo i fondi dal BootFaucet
# necessari per pagare il Gas per operazioni quali il Trasferimento tra EoA o il Deposito in MoneyBox

def depositOrWithdrawalTestEth(
        depositOrWithdrawal,
        chooseChain,
        quantity,
        addressSender,
        pkSender,
        addressTo):
    chain, chainId, wallet_deploy = selectChain(chooseChain, addressSender)
    contractIstance = chain.eth.contract(
        address=chain.toChecksumAddress(BOOT_FAUCETGoerliSC_Address),
        abi=abiFaucet)
    if (depositOrWithdrawal == "deposit"):
        Tx = depositTx(
            chain,
            contractIstance,
            quantity,
            chain.toChecksumAddress(addressSender),
            pkSender)
    elif (depositOrWithdrawal == "Withdrawal"):
        Tx = withdrawalTx(
            chain,
            contractIstance,
            chain.toChecksumAddress(addressSender),
            pkSender,
            addressTo)

    while True:
        tx_info = chain.eth.getTransaction(Tx)
        if tx_info.blockNumber is not None:
            tx_receipt = chain.eth.getTransactionReceipt(Tx)
            break
        time.sleep(2)
    return Tx

# funzione specifica per uso in TestNet al fine di attendere che la generica Tx non venga elaborata con successo
# In caso positivo restituisce l'hash o l'address di deploy contratto, in caso contrario, la funzione ritenta
# l'invio della transazione in base all'errore specifico e riprova fino a un numero massimo di volte, con un intervallo di attesa

def send_tx(
        chain,
        transaction,
        signedTx_hash,
        sender_pk,
        addressDeployContract=None):
    retry_count = 1
    sleep_time = 2
    while True:
        try:
            receipt = chain.eth.getTransactionReceipt(signedTx_hash)
            if receipt:
                if 'status' in receipt and receipt['status'] == 1:
                    if addressDeployContract == "getAddressContract":
                        contract_Address = receipt['contractAddress']
                        return contract_Address
                    else:
                        encodeTX = chain.toJSON(signedTx_hash).strip('"')
                        return encodeTX
                else:
                    if retry_count >= 2:
                        if "nonce too low" in receipt.get(
                                "error", "Transaction failed"):
                            nonce += 1
                            transaction["nonce"] = nonce
                        elif "max fee per gas less than block base fee" in receipt.get("error", "Transaction failed"):
                            gas_price = transaction["gasPrice"] * 2
                            transaction["gasPrice"] = gas_price
                        else:
                            return receipt.get("error", "Transaction failed")
                    else:
                        retry_count += 1
                        signed_tx = chain.eth.account.signTransaction(
                            transaction, sender_pk)
                        signedTx_hash = chain.eth.sendRawTransaction(
                            signed_tx.rawTransaction)
        except BaseException:
            pass
        time.sleep(sleep_time)

# implementazione del withdrawal rispetto la funzione depositOrWithdrawalTestEth()
def withdrawalTx(
        chain,
        contract_ist,
        addressCallFunctions,
        sender_pk,
        addressToWithdrawal):
    nonce = chain.eth.getTransactionCount(
        chain.toChecksumAddress(addressCallFunctions))
    transaction = contract_ist.functions.withdrawalFromFaucet(
        addressToWithdrawal).buildTransaction({'nonce': nonce, 'gasPrice': chain.eth.gasPrice})

    if chain == w3g:  # se su BC pubblica applico strategia di opportuno calcolo GAS per rapidità e sicurezza progagazione TX
        gas_price = controller.get_gasprice_by_strategy(GaspriceStrategy.FAST)
        gas_price += int(gas_price * 0.05)
        base_fee = w3g.eth.get_block("latest").baseFeePerGas
        max_fee_per_gas = int(gas_price * 1.5) + base_fee
        transaction["gasPrice"] = max_fee_per_gas
        gas_limit = chain.eth.estimateGas(transaction)
        gas_limit += int(gas_limit * 0.2)
        transaction["gas"] = gas_limit
    else:
        gas_limit = chain.eth.estimateGas(transaction)
        transaction["gas"] = gas_limit

    signedTx = chain.eth.account.signTransaction(transaction, sender_pk)
    signedTx_hash = chain.eth.sendRawTransaction(signedTx.rawTransaction)

    encodeTX = chain.toJSON(signedTx_hash).strip('"')

    if chain == web3:
        return encodeTX
    elif chain == w3g:
        return send_tx(chain, transaction, signedTx_hash, sender_pk)

# implementazione del deposit rispetto la funzione depositOrWithdrawalTestEth()
def depositTx(chain, contract_ist, quantityTestEth, sender_address, sender_pk):
    nonce = chain.eth.getTransactionCount(
        chain.toChecksumAddress(sender_address))
    transaction = contract_ist.functions.donateTofaucet().buildTransaction({
        'nonce': nonce,
        'value': chain.toWei(quantityTestEth, 'ether'),
        'gasPrice': chain.eth.gasPrice
    })
    gas_limit = chain.eth.estimateGas(transaction)
    transaction["gas"] = gas_limit
    signedTx = chain.eth.account.signTransaction(transaction, sender_pk)
    signedTx_hash = chain.eth.sendRawTransaction(signedTx.rawTransaction)
    encodeTX = chain.toJSON(signedTx_hash).strip('"')

    if chain == web3:
        return encodeTX

    elif chain == w3g:
        return send_tx(chain, transaction, signedTx_hash, sender_pk)

# funzione di Deploy Multichain di generico SC
def deploySmartContract(
        adminPk,
        chooseChain,
        eoaInput,
        abiArg,
        bytecodeArg,
        optionalArgument=None):
    chain, chainId, wallet_deploy = selectChain(chooseChain, eoaInput)
    scToDeploy = chain.eth.contract(abi=abiArg, bytecode=bytecodeArg)
    nonce = chain.eth.getTransactionCount(wallet_deploy)

    # codice gas_strategy integrato per recenti problemi di congestione rete Goerli ( chain == web3 -> GANACHE ; chain == w3g -> Goerli )
    if chain == w3g:
        gas_price = controller.get_gasprice_by_strategy(GaspriceStrategy.FAST)
        gas_price += int(gas_price * 0.05)
        base_fee = w3g.eth.get_block("latest").baseFeePerGas
        max_fee_per_gas = int(gas_price * 1.5) + base_fee
        try:
            if optionalArgument is not None:
                transaction = scToDeploy.constructor(optionalArgument).buildTransaction({
                    "gasPrice": max_fee_per_gas,
                    "chainId": chainId,
                    "from": wallet_deploy,
                    "nonce": nonce
                })
            else:
                transaction = scToDeploy.constructor().buildTransaction({
                    "gasPrice": max_fee_per_gas,
                    "chainId": chainId,
                    "from": wallet_deploy,
                    "nonce": nonce
                })
            gas_limit = chain.eth.estimateGas(transaction)  # --
            gas_limit += int(gas_limit * 0.2)
            transaction["gas"] = gas_limit

            signedTx = chain.eth.account.signTransaction(transaction, adminPk)
            signedTx_hash = chain.eth.sendRawTransaction(
                signedTx.rawTransaction)
            getAddressContract = "getAddressContract"
            return send_tx(chain, transaction, signedTx_hash, adminPk, getAddressContract)

        except Exception as e:
            error_message = str(e)
            error_message = error_message.split("revert ")[1]
            return error_message

    elif chain == web3:
        if optionalArgument is not None:
            transaction = scToDeploy.constructor(optionalArgument).buildTransaction({
                "gasPrice": chain.eth.gasPrice,  # --
                "chainId": chainId,
                "from": wallet_deploy,
                "nonce": nonce
            })
        else:
            transaction = scToDeploy.constructor().buildTransaction({
                "gasPrice": chain.eth.gasPrice,  # --
                "chainId": chainId,
                "from": wallet_deploy,
                "nonce": nonce
            })

        signedTx = chain.eth.account.signTransaction(transaction, adminPk)
        signedTx_hash = chain.eth.sendRawTransaction(signedTx.rawTransaction)
        while True:
            tx_info = chain.eth.getTransaction(signedTx_hash)
            if tx_info.blockNumber is not None:
                tx_receipt = chain.eth.getTransactionReceipt(signedTx_hash)
                break
            time.sleep(2)
        contract_Address = tx_receipt['contractAddress']
        return contract_Address

# implementazione Trasferimento tra EoA o di Deposito verso SC MoneyBox di Token ERC20 ( chain == web3 -> GANACHE ; chain == w3g -> Goerli )
def transferToken(chooseChain,
                  contract_ist,
                  destination_address,
                  sender_address,
                  sender_pk,
                  quantity_token, tokenToContract=None):

    chain, chainId, wallet_deploy = selectChain(chooseChain, sender_address)
    if chain == web3:
        try:
            nonce = chain.eth.getTransactionCount(
                Web3.toChecksumAddress(sender_address))
            if tokenToContract is None:
                transaction = contract_ist.functions.transfer(Web3.toChecksumAddress(destination_address), chain.toWei(
                    quantity_token, 'ether')).buildTransaction({"gasPrice": chain.eth.gasPrice, "chainId": chainId, "from": sender_address, "nonce": nonce})
            else:
                transaction = contract_ist.functions.depositErc20(chain.toWei(tokenToContract, 'ether')).buildTransaction(
                    {"gasPrice": chain.eth.gasPrice, "chainId": chainId, "from": sender_address, "nonce": nonce})
            gas_limit = chain.eth.estimateGas(transaction)
            transaction["gas"] = gas_limit
            signedTx = chain.eth.account.signTransaction(
                transaction, sender_pk)
            signedTx_hash = chain.eth.sendRawTransaction(
                signedTx.rawTransaction)
            encodeTX = Web3.toJSON(signedTx_hash).strip('"')
            while True:
                tx_info = chain.eth.getTransaction(signedTx_hash)
                if tx_info.blockNumber is not None:
                    tx_receipt = chain.eth.getTransactionReceipt(signedTx_hash)
                    break
                time.sleep(2)
            return encodeTX
        except Exception as e:
            error_message = str(e)
            error_message = error_message.split("revert ")[1]
            return error_message
    elif chain == w3g:
        gas_price = controller.get_gasprice_by_strategy(GaspriceStrategy.FAST)
        gas_price += int(gas_price * 0.05)
        base_fee = w3g.eth.get_block("latest").baseFeePerGas
        max_fee_per_gas = int(gas_price * 1.5) + base_fee

        try:
            nonce = chain.eth.getTransactionCount(
                Web3.toChecksumAddress(sender_address))
            if tokenToContract is None:
                transaction = contract_ist.functions.transfer(Web3.toChecksumAddress(destination_address), chain.toWei(
                    quantity_token, 'ether')).buildTransaction({"gasPrice": max_fee_per_gas, "from": sender_address, "nonce": nonce})
            else:
                transaction = contract_ist.functions.depositErc20(chain.toWei(tokenToContract, 'ether')).buildTransaction(
                    {"gasPrice": max_fee_per_gas, "from": sender_address, "nonce": nonce})

            gas_limit = chain.eth.estimateGas(transaction)
            gas_limit += int(gas_limit * 0.2)
            transaction["gas"] = gas_limit

            signedTx = chain.eth.account.signTransaction(
                transaction, sender_pk)
            signedTx_hash = chain.eth.sendRawTransaction(
                signedTx.rawTransaction)
            encodeTX = Web3.toJSON(signedTx_hash).strip('"')
            return send_tx(chain, transaction, signedTx_hash, sender_pk)
        except Exception as e:
            error_message = str(e)
            error_message = error_message.split("revert ")[1]
            return error_message

# ottenimento dizionario da interrogazione Blockchain con balance per account

def getAllBalance(chooseChain, adminFaucetAddress):
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    chain, chainId, wallet_deploy = selectChain(
        chooseChain, adminFaucetAddress)
    address_balance = []

    if chooseChain == "localGanache":
        contractIstance = chain.eth.contract(
            address=faucet_ready.deploy_sm_address, abi=abi)
        faucet_balance = (faucet_ready.ganache_Address, chain.fromWei(
            contractIstance.functions.balanceOf(
                all_account[FAUCET_ID]).call(),
            'ether'))
        address_balance.append(faucet_balance)
        for ind in range(1, MAX_USER_GANACHE):
            tupleAddress_Balance = (all_account[ind].lower(), chain.fromWei(
                contractIstance.functions.balanceOf(
                    all_account[ind]).call(), 'ether'))
            address_balance.append(tupleAddress_Balance)

    elif chooseChain == "gorli":
        contractIstance = chain.eth.contract(
            address=faucet_ready.goerli_deploy_sm_address, abi=abi)
        faucet_balance = (
            faucet_ready.goerli_Address, chain.fromWei(
                contractIstance.functions.balanceOf(
                    faucet_ready.goerli_Address).call(), 'ether'))
        address_balance.append(faucet_balance)
        goerliEoA = Customer.objects.all()
        for eoa in goerliEoA.iterator():
            tupleAddress_Balance = (
                eoa.user_goerli_Address, chain.fromWei(
                    contractIstance.functions.balanceOf(
                        eoa.user_goerli_Address).call(), 'ether'))
            address_balance.append(tupleAddress_Balance)
    return dict(address_balance)

# restituisce istanze degli eventi di trasferimento o approvazione Token

def extractEventByTransaction(tx, ganacheOrGoerli, forwardingChainAddress):

    chain, chainId, wallet_deploy = selectChain(
        ganacheOrGoerli, forwardingChainAddress)

    faucet_ready = list(FaucetPatoken.objects.filter())[-1]

    if chain == web3:
        contractIstance = chain.eth.contract(
            address=faucet_ready.deploy_sm_address, abi=abi)
    elif chain == w3g:
        contractIstance = chain.eth.contract(
            address=faucet_ready.goerli_deploy_sm_address, abi=abi)

    receipt = chain.eth.getTransactionReceipt(tx)

    eventOnTx = None

    # Cerca gli eventi di Trasferimento token presenti sullo SC Patoken in
    # standard ERC20
    try:
        eventOnTx = contractIstance.events.Transfer().processReceipt(receipt)
        sender = eventOnTx[0]['args']['from']
        recipient = eventOnTx[0]['args']['to']
        amount = str(chain.fromWei(eventOnTx[0]['args']['value'], 'ether'))
    except BaseException:
        pass

    # Cerca gli eventi di Approvazione presenti sullo SC Patoken in standard
    # ERC20
    try:
        eventOnTx = contractIstance.events.Approval().processReceipt(receipt)
        sender = eventOnTx[0]['args']['owner']
        recipient = eventOnTx[0]['args']['spender']
        amount = str(chain.fromWei(eventOnTx[0]['args']['value'], 'ether'))
    except BaseException:
        pass

    # Se non ci sono eventi validi, restituisce None
    if eventOnTx is None:
        return None

    counter_EvIstance = ExtractedEvent.objects.all().count()

    if ExtractedEvent.objects.filter(transact=tx).exists():
        return counter_EvIstance

    if chain == web3:
        istance_event = ExtractedEvent(
            id=counter_EvIstance,
            recipientAddress=recipient,
            senderAddress=sender,
            amountErcTransfer=amount,
            transact=tx)
    elif chain == w3g:
        istance_event = ExtractedEvent(
            id=counter_EvIstance,
            recipientAddress=recipient,
            senderAddress=sender,
            amountErcTransfer=amount,
            chain="goerli")
    istance_event.save()
    return istance_event

# estrazione array degli eventi di tipo transfer Token dalle Tx in BC locale , scorrendo tutti i blocchi e iterando le TX
def getTotalExtractedEvents():
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]

    goerliEvent = []
    if ExtractedEvent.objects.filter(chain="goerli").count() > 0:
        for event in ExtractedEvent.objects.filter(chain="goerli"):
            goerliEvent.append(event)

    actualBlock = web3.eth.get_block_number()
    allExtractEvent = []
    for i in range(1, actualBlock + 1):
        iterateTx = web3.eth.get_block(i, full_transactions=True)
        if faucet_ready.deploy_sm_address == iterateTx['transactions'][0]['to']:
            extractHexTx = iterateTx['transactions'][0]['hash']
            encodeTX = Web3.toHex(extractHexTx)
            eventOnTx = extractEventByTransaction(
                encodeTX, "localGanache", faucet_ready.ganache_Address)

            if not isinstance(eventOnTx, int):
                eventOnTx.transact = encodeTX
                allExtractEvent.append(eventOnTx)

            for row in ExtractedEvent.objects.all().reverse():
                row.delete()
            i += 1
        else:
            i += 1
            continue

        for i in range(len(allExtractEvent)):
            instance_event = ExtractedEvent(
                id=i,
                recipientAddress=allExtractEvent[i].recipientAddress,
                senderAddress=allExtractEvent[i].senderAddress,
                amountErcTransfer=allExtractEvent[i].amountErcTransfer,
                transact=allExtractEvent[i].transact)
            instance_event.save()
        last_id = i

        if len(goerliEvent) > 0:
            for i in range(len(goerliEvent)):
                instance_event = ExtractedEvent(
                    id=last_id + 1 + i,
                    recipientAddress=goerliEvent[i].recipientAddress,
                    senderAddress=goerliEvent[i].senderAddress,
                    amountErcTransfer=goerliEvent[i].amountErcTransfer,
                    transact=goerliEvent[i].transact,
                    chain="goerli")
                instance_event.save()

    return allExtractEvent

# funzione per la View di richiamo tutti eventi di Trasferimento

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

# mostra i bilanci di ogni EoA

@staff_member_required()
def showTokenBalances(request, ganacheOrGoerli):
    if Customer.objects.filter().count() == 0:
        messages.error(
            request,
            f'Occorre registrare degli account associandone un indirizzo della Local Blockchain prima di procedere a questa funzionalità')
        return redirect('/')
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]

    if ganacheOrGoerli == "ganache":
        get_balance = getAllBalance(
            "localGanache", faucet_ready.ganache_Address)
    elif ganacheOrGoerli == "goerli":
        get_balance = getAllBalance("gorli", faucet_ready.goerli_Address)

    context = {'get_balance': get_balance,
               'ganacheOrGoerli': ganacheOrGoerli}

    return render(request, 'showbalance.html', context)

# mostra la TotalSuply dei Token Mintati sulle 2 chain

@login_required()
def getTotalSupply(request, ganacheOrGoerli):
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]

    if ganacheOrGoerli == "ganache":
        contractIstance = web3.eth.contract(
            address=faucet_ready.deploy_sm_address, abi=abi)
        TOTALSUPPLY = web3.fromWei(
            contractIstance.functions.totalSupply().call(), 'ether')
        smDeployAdd = faucet_ready.deploy_sm_address
    elif ganacheOrGoerli == "goerli":
        contractIstance = w3g.eth.contract(
            address=faucet_ready.goerli_deploy_sm_address, abi=abi)
        TOTALSUPPLY = w3g.fromWei(
            contractIstance.functions.totalSupply().call(), 'ether')
        smDeployAdd = faucet_ready.goerli_deploy_sm_address

    context = {
        'TOTALSUPPLY': TOTALSUPPLY,
        'smDeployAdd': smDeployAdd,
        'ganacheOrGoerli': ganacheOrGoerli}
    return render(request, 'showtotalsupply.html', context)

# mostra il Saldo dei Token depositati sul contratto Salvadanaio

@login_required()
def getBalanceOnMoneyBox(request, ganacheOrGoerli):
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    addressToFind = None
    if not request.user.is_superuser:
        current_customer = Customer.objects.get(user=request.user)
    else:
        current_customer = faucet_ready

    if ganacheOrGoerli == "ganache":
        try:
            addressToFind = current_customer.user_ganache_Address
        except BaseException:
            addressToFind = Web3.toChecksumAddress(
                current_customer.ganache_Address)
        contractIstance = web3.eth.contract(
            address=faucet_ready.piggyBankScGanacheAddress, abi=abiMB)
        CURRENTBALANCE = web3.fromWei(contractIstance.functions.getERC20balanceForUser(
            addressToFind).call({'from': addressToFind}), 'ether')
        messages.error(
            request,
            f"Current EoA address:" +
            addressToFind +
            " ha un saldo PaToken su MoneyBox SC: " +
            faucet_ready.piggyBankScGanacheAddress +
            " local Blockchain Ganache pari a: " +
            str(CURRENTBALANCE))
        return redirect('/')
    elif ganacheOrGoerli == "goerli":
        try:
            addressToFind = current_customer.user_goerli_Address
        except BaseException:
            addressToFind = Web3.toChecksumAddress(
                current_customer.goerli_Address)
        contractIstance = w3g.eth.contract(
            address=faucet_ready.piggyBankScGorliAddress, abi=abiMB)
        CURRENTBALANCE = w3g.fromWei(contractIstance.functions.getERC20balanceForUser(
            addressToFind).call({'from': addressToFind}), 'ether')
        messages.error(
            request,
            f"Current EoA address:" +
            addressToFind +
            " ha un saldo PaToken su MoneyBox SC: " +
            faucet_ready.piggyBankScGorliAddress +
            " TestNet Goerli pari a: " +
            str(CURRENTBALANCE))
        return redirect('/viewGoerli/')


GOERLI_FAUCET_ERC20, PK_FAUCET_ERC20 = creteGoerliEoA()
faucetCounter = FaucetPatoken.objects.all().count()

# individua il numero di Account in Piattaforma il cui Balance è nullo

def countZeroPatokenCustoumer():
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    goerliEoA = Customer.objects.all()
    countCustoumers = 0
    if faucet_ready.goerli_deploy_sm_address == "null":
        return "null"
    contractIstance = w3g.eth.contract(
        address=faucet_ready.goerli_deploy_sm_address, abi=abi)
    for eoa in goerliEoA.iterator():
        if w3g.fromWei(
                contractIstance.functions.balanceOf(
                    eoa.user_goerli_Address).call(),
                'ether') == 0:
            countCustoumers += 1
    return countCustoumers

# homepage condizionale alla corretta sincronizzazione Ganache local BC

def homepage(request):
    global BLOCKCHAIN_CONSISTENCY_CHECK
    global FIRST_ACCESS
    global GLOBAL_CONTEXT
    global BOOST_ETH
    COUNT_LOWETH_USER = countEmptyCustomers()
    COUNT_EVENT_TRANSFER = None

    if (ExtractedEvent.objects.filter().count()):
        COUNT_EVENT_TRANSFER = ExtractedEvent.objects.filter(
            chain="Ganache").count()

    if not request.user.is_authenticated and FIRST_ACCESS:
        FIRST_ACCESS = False
        messages.error(request, f" Di Default la piattaforma implementa le funzionalità su high performance Local Blockchain Ganache o in alternativa su TestNet pubblica Goerli. Quando si interagisce con quest ultima ci si interfaccia con lo smartContract di un Faucet precedentemente deployato all address:0x982c1CFfdef5FabC5F9dCd3b7dAe8F8f9711955A ed approvigionato di EthTest; Si consiglia di attendere ≈30 sec la completa conferma delle Tx prima di riproporre comandi attraverso link dei menu proposti, in modo da evitare errori in conferma TX ")
        return redirect('/')

    if request.user.is_authenticated and GANACHE_MNMONIC == "":
        messages.error(
            request,
            f'Per proseguire occorre inserire la MNEMONIC phrase della Local Blockchain Ganache! ')
        return redirect('/getMnemonic/')

    if request.user.is_authenticated and not request.user.is_superuser:
        current_customer = Customer.objects.get(user=request.user)
        faucet_ready = list(FaucetPatoken.objects.filter())[-1]
        patokenBalance = getAllBalance("localGanache", faucet_ready.ganache_Address)[
            current_customer.user_ganache_Address.lower()]
        faucetGoerliEthBalance = float(
            web3.fromWei(
                w3g.eth.getBalance(
                    Web3.toChecksumAddress(
                        faucet_ready.goerli_Address)),
                'ether'))
        goerliAddressFaucet = faucet_ready.goerli_Address
        CURRENT_EOA = current_customer.user_goerli_Address
        DEPLOY_GOERLI = faucet_ready.goerli_deploy_sm_address
        if DEPLOY_GOERLI == "null":
            DEPLOY_GOERLI = None
        if faucet_ready.goerli_deploy_sm_address == "null":
            COUNT_PATOKEN_EOA = None
        else:
            COUNT_PATOKEN_EOA = countZeroPatokenCustoumer()

        context = {'patokenBalance': patokenBalance,
                   'faucetGoerliEthBalance': faucetGoerliEthBalance,
                   'goerliAddressFaucet': goerliAddressFaucet,
                   'DEPLOY_GOERLI': DEPLOY_GOERLI,
                   'COUNT_PATOKEN_EOA': COUNT_PATOKEN_EOA,
                   'COUNT_LOWETH_USER': COUNT_LOWETH_USER,
                   'COUNT_EVENT_TRANSFER': COUNT_EVENT_TRANSFER
                   }
        return render(request, "access_register/homepage.html", context)

    if request.user.is_superuser and BLOCKCHAIN_CONSISTENCY_CHECK == "False":
        admin = User.objects.filter(is_superuser=True)
        if FaucetPatoken.objects.filter().count() == 0:
            faucet = FaucetPatoken(
                id=faucetCounter + 1,
                user=admin[0],
                ganache_Address=all_account[FAUCET_ID].lower(),
                goerli_Address=GOERLI_FAUCET_ERC20,
                encode_pk_goerli_faucet=goCript(PK_FAUCET_ERC20))
            getPk = getPrivatekey(faucet.ganache_Address, request)
            faucet.deploy_sm_address = deploySmartContract(
                getPk, "localGanache", all_account[FAUCET_ID].lower(), abi, bytecode)
            faucet.piggyBankScGanacheAddress = deploySmartContract(
                getPk,
                "localGanache",
                all_account[FAUCET_ID].lower(),
                abiMB,
                bytecodeMB,
                faucet.deploy_sm_address)
            faucet.patoken_wallet = MAX_MINTABLE_SC_TOKEN
            faucet.goerli_patoken_wallet = MAX_MINTABLE_SC_TOKEN
            faucet.save()
        faucet_ready = list(FaucetPatoken.objects.filter())[-1]
        if faucet_ready.goerli_deploy_sm_address == "null":
            COUNT_PATOKEN_EOA = None
        else:
            COUNT_PATOKEN_EOA = countZeroPatokenCustoumer()
        faucetAdminBalance = getAllBalance(
            "localGanache", all_account[FAUCET_ID].lower())[FAUCET_ADDRESS]
        DEPLOY_GOERLI = faucet_ready.goerli_deploy_sm_address
        if DEPLOY_GOERLI == "null":
            DEPLOY_GOERLI = None

        faucetGoerliEthBalance = float(
            web3.fromWei(
                w3g.eth.getBalance(
                    Web3.toChecksumAddress(
                        faucet_ready.goerli_Address)),
                'ether'))
        goerliAddressFaucet = faucet_ready.goerli_Address

        context = {'faucetAdminBalance': faucetAdminBalance,
                   'COUNT_LOWETH_USER': COUNT_LOWETH_USER,
                   'COUNT_PATOKEN_EOA': COUNT_PATOKEN_EOA,
                   'DEPLOY_GOERLI': DEPLOY_GOERLI,
                   'faucetGoerliEthBalance': faucetGoerliEthBalance,
                   'goerliAddressFaucet': goerliAddressFaucet,
                   'COUNT_EVENT_TRANSFER': COUNT_EVENT_TRANSFER,
                   'BOOST_ETH': BOOST_ETH
                   }
        GLOBAL_CONTEXT = context
        return render(request, "access_register/homepage.html", context)

    if not request.user.is_authenticated:
        numberCustomers = Customer.objects.filter().count()
        numFaucet = FaucetPatoken.objects.filter().count()
        ceckFull = int(MAX_USER_GANACHE - numberCustomers - 1)
        context = {
            'MAX_USER_GANACHE': MAX_USER_GANACHE,
            'numberCustomers': numberCustomers,
            'ceckFull': ceckFull,
            'numFaucet': numFaucet,
            'COUNT_EVENT_TRANSFER': COUNT_EVENT_TRANSFER
        }
        return render(request, "access_register/homepage.html", context)

    return render(request, "access_register/homepage.html")

# individua numero Custoumer che non hanno ancora EthTest e quindi non possono pagare il Gas
# per operazioni in piattaforma

def countEmptyCustomers():
    rechargeEthTestGoerliEoA = Customer.objects.all()
    needCustoumers = 0
    for eoa in rechargeEthTestGoerliEoA.iterator():
        if float(
            web3.fromWei(
                w3g.eth.getBalance(
                    Web3.toChecksumAddress(
                eoa.user_goerli_Address)),
                'ether')) < 0.045:  # 0.05 di margine per eventuale Fees di GAS
            needCustoumers += 1
    return needCustoumers

# view che mostra la versione HomePage per operazioni Goerli deployando i Contratti su questa chain
# o distribuendo EthTest o Token precedentemente assegnati in numero casuale in fase di creazione EoA
# Si richiede, da metamask dell'ADMIN un invio minimo effettivo di almeno 0.1, EthTest per richiamare
# le altre funzioni quali il trasferimento fondi dal BootFaucet ai nuovi Account o il deploySC.
# In caso di congestione anomala in BC rilevata al Deploy, si abilita un pulsante per Eth Boost aggiuntivo

@login_required()
def viewGoerli(request):
    global STARTLOOP
    global GLOBAL_CONTEXT
    global BOOST_ETH

    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    GOERLI_FAUCET_ERC20 = faucet_ready.goerli_Address
    GOERLI_FAUCET_ETH_BALANCE = float(
        web3.fromWei(
            w3g.eth.getBalance(
                Web3.toChecksumAddress(
                    faucet_ready.goerli_Address)),
            'ether'))
    ETH_NEED_CUSTOUMERS = (0.05 * countEmptyCustomers()) + 0.05
    COUNT_EVENT_TRANSFER_GORLI = None

    if (ExtractedEvent.objects.filter().count()):
        COUNT_EVENT_TRANSFER_GORLI = ExtractedEvent.objects.filter(
            chain="goerli").count()

    DEPLOY_GOERLI = faucet_ready.goerli_deploy_sm_address
    if DEPLOY_GOERLI == "null":
        DEPLOY_GOERLI = None
    if faucet_ready.goerli_deploy_sm_address == "null":
        COUNT_PATOKEN_EOA = None
    else:
        COUNT_PATOKEN_EOA = countZeroPatokenCustoumer()

    if faucet_ready.piggyBankScGorliAddress == "null":
        faucet_ready.piggyBankScGorliAddress = ""
        faucet_ready.save()

    if countEmptyCustomers() == 0:
        COUNT_LOWETH_USER = None
    else:
        COUNT_LOWETH_USER = countEmptyCustomers()

    if float(
        web3.fromWei(
            w3g.eth.getBalance(
            Web3.toChecksumAddress(BOOT_FAUCETGoerliSC_Address)),
            'ether')) < ETH_NEED_CUSTOUMERS:
        messages.error(
            request,
            f"Attenzione! Lo Smart Contract che distribuisce GoerliEthTest agli EoA per la fruizione funzionalità, è al momento con fondi nulli o insufficienti(inferiore" +
            str(ETH_NEED_CUSTOUMERS) +
            "Eth); Alimentarlo via Metamask all indirizzo:" +
            BOOT_FAUCETGoerliSC_Address +
            " e attendere circa 15 secondi prima di ricaricare la pagina")
        return redirect('/')

    if not request.user.is_superuser:
        current_customer = Customer.objects.get(user=request.user)
        USER_GOERLI_BALANCE = float(
            web3.fromWei(
                w3g.eth.getBalance(
                    Web3.toChecksumAddress(
                        current_customer.user_goerli_Address)),
                'ether'))
        CURRENT_EOA = current_customer.user_goerli_Address

        if faucet_ready.goerli_deploy_sm_address == "null":
            messages.error(
                request,
                f"Attenzione! è l admin della piattaforma a dover prima inizializzare il Faucet ed istanziare gli SmartContract per operare su Goerli BC")
            return redirect('/')
        else:
            contractIstance = w3g.eth.contract(
                address=faucet_ready.goerli_deploy_sm_address, abi=abi)
            GORLI_CURRENT_ERC_BALANCE = w3g.fromWei(
                contractIstance.functions.balanceOf(CURRENT_EOA).call(), 'ether')
            if GOERLI_FAUCET_ETH_BALANCE < 0.1:
                messages.error(
                    request,
                    f"Attenzione! Il Faucet ha un saldo nullo o minore di 0.15Eth; Per proseguire invia dal tuo Metamask a:" +
                    GOERLI_FAUCET_ERC20 +
                    " degli Ether di Test per superare la soglia indicata attendendo circa 15secondi prima di ricaricare")
                return redirect('/')
            else:
                if USER_GOERLI_BALANCE < 0.04:  # rispetto al limite 0.05 considero un margine di 0.01 per evitare ulteriori withdrawal a causa del seppur minimo gas pagato per eventuali trasferirimenti Token di user non Admin
                    if not AVOID_MULTIMPLE_EOA_TX or (
                            faucet_ready.goerli_Address in AVOID_MULTIMPLE_EOA_TX and AVOID_MULTIMPLE_EOA_TX[faucet_ready.goerli_Address] == "null"):
                        AVOID_MULTIMPLE_EOA_TX[faucet_ready.goerli_Address] = "busy"
                        tx = depositOrWithdrawalTestEth(
                            "Withdrawal",
                            "gorli",
                            0.05,
                            faucet_ready.goerli_Address,
                            goDecript(
                                faucet_ready.encode_pk_goerli_faucet),
                            current_customer.user_goerli_Address)  # 0.01 in più per eventuale gas di Transfer token
                        USER_GOERLI_BALANCE = float(
                            web3.fromWei(
                                w3g.eth.getBalance(
                                    Web3.toChecksumAddress(
                                        current_customer.user_goerli_Address)),
                                'ether'))
                        AVOID_MULTIMPLE_EOA_TX[faucet_ready.goerli_Address] = "null"
                        messages.error(
                            request,
                            f"Avviato processo di trasferimento EthTest verso address: " +
                            current_customer.user_goerli_Address +
                            "; attendere ≈30 secondi per la conferma della..TX:" +
                            tx)
                    else:
                        AVOID_MULTIMPLE_EOA_TX[faucet_ready.goerli_Address] = "null"
                        messages.error(
                            request,
                            "Lo stesso EoA ha già propagato un altra Tx, attendere il completamento della precedente prima di ripetere il comando(ricarica la pagina dal browser e riprova senza click multipli)")
                        time.sleep(4)
                        return redirect('/')
                BALANCE_FAUCET = "NotEmpity"
                context = {
                    'DEPLOY_GOERLI': DEPLOY_GOERLI,
                    'COUNT_PATOKEN_EOA': COUNT_PATOKEN_EOA,
                    'COUNT_LOWETH_USER': COUNT_LOWETH_USER,
                    'USER_GOERLI_BALANCE': USER_GOERLI_BALANCE,
                    'CURRENT_EOA': CURRENT_EOA,
                    'GOERLI_FAUCET_ETH_BALANCE': GOERLI_FAUCET_ETH_BALANCE,
                    'BALANCE_FAUCET': BALANCE_FAUCET,
                    'GOERLI_FAUCET_ERC20': GOERLI_FAUCET_ERC20,
                    'GORLI_CURRENT_ERC_BALANCE': GORLI_CURRENT_ERC_BALANCE,
                    'piggyBankScGorliAddress': faucet_ready.piggyBankScGorliAddress,
                    'COUNT_EVENT_TRANSFER_GORLI': COUNT_EVENT_TRANSFER_GORLI}
                COUNT_LOWETH_USER = countEmptyCustomers()
                if GORLI_CURRENT_ERC_BALANCE != 0:
                    return render(
                        request, "access_register/testNewFaucet.html", context)
                elif GORLI_CURRENT_ERC_BALANCE == 0:
                    return redirect('/', context)
    else:
        USER_GOERLI_BALANCE = None
        CURRENT_EOA = GOERLI_FAUCET_ERC20

    # Rispetto la soglia 0.15 suggerita all'User, considero ≈ 0.05 per non
    # andare subito sotto soglia per Gas associato ad eventuali ricaricamenti
    if GOERLI_FAUCET_ETH_BALANCE < 0.1:
        BALANCE_FAUCET = "Empity"

    elif GOERLI_FAUCET_ETH_BALANCE >= 0.1:
        BALANCE_FAUCET = "NotEmpity"

        if request.user.is_superuser:
            if faucet_ready.goerli_deploy_sm_address == "null":
                try:
                    faucet_ready.goerli_deploy_sm_address = deploySmartContract(
                        goDecript(
                            faucet_ready.encode_pk_goerli_faucet),
                        "gorli",
                        faucet_ready.goerli_Address,
                        abi,
                        bytecode)
                    faucet_ready.save()
                except BaseException:
                    BOOST_ETH = "request"
                    context = ({'BOOST_ETH': BOOST_ETH})
                    context.update(GLOBAL_CONTEXT)
                    context.update({'BOOST_ETH': BOOST_ETH})
                    messages.error(
                        request,
                        f'Le anomale condizioni di congestione su Goerli richiedono probabilmente maggior Gas per il Deploy degli SmartContract. Inviare fondi aggiuntivi dal proprio Metamask ad Address '+faucet_ready.goerli_Address + ' o clicca il pulsante appena renderizzato in basso a Destra per richiedere al BootFaucet un Boost di 0.05Eth fino a max 1 Eth; si consiglia di portare il Balance del Faucet Admin ad almeno a 0.5 Eth tramite richieste consecutive e attesa rispettivo codice TX prima del reinoltro')
                    return render(request, "access_register/homepage.html", context)

            if Customer.objects.filter().count() != 0:
                rechargeEthTestGoerliEoA = Customer.objects.all()
                for eoa in rechargeEthTestGoerliEoA.iterator():
                    if float(
                        web3.fromWei(
                            w3g.eth.getBalance(
                                Web3.toChecksumAddress(
                                    eoa.user_goerli_Address)),
                            'ether')) < 0.05:
                        if not AVOID_MULTIMPLE_EOA_TX or (
                                faucet_ready.goerli_Address in AVOID_MULTIMPLE_EOA_TX and AVOID_MULTIMPLE_EOA_TX[faucet_ready.goerli_Address] == "null"):
                            AVOID_MULTIMPLE_EOA_TX[faucet_ready.goerli_Address] = "busy"
                            tx = depositOrWithdrawalTestEth(
                                "Withdrawal", "gorli", 0.05, faucet_ready.goerli_Address, goDecript(
                                    faucet_ready.encode_pk_goerli_faucet), eoa.user_goerli_Address)
                            AVOID_MULTIMPLE_EOA_TX[faucet_ready.goerli_Address] = "null"
                            messages.error(
                                request,
                                f"Al momento risultano creati " +
                                str(
                                    countEmptyCustomers()) +
                                " utenti con bilancio sotto soglia;Avviato processo di trasferimento EthTest verso address: " +
                                eoa.user_goerli_Address +
                                "; attendere ≈ 30 secondi e ripetere operazione fino a completamento lista..TX:" +
                                tx)
                        else:
                            AVOID_MULTIMPLE_EOA_TX[faucet_ready.goerli_Address] = "null"
                            messages.error(
                                request,
                                "Lo stesso EoA ha già propagato un altra Tx, attendere il completamento della precedente prima di ripetere il comando(ricarica la pagina dal browser e riprova senza click multipli)")
                            time.sleep(4)
                            return redirect('/')
                        COUNT_LOWETH_USER = countEmptyCustomers()
                        if GOERLI_FAUCET_ETH_BALANCE < 0.1:
                            messages.error(
                                request,
                                f"Attenzione! Il Faucet ha un saldo nullo o minore di 0.15Eth; Per proseguire invia dal tuo Metamask a:" +
                                GOERLI_FAUCET_ERC20 +
                                " degli Ether di Test per superare la soglia indicata attendendo circa 15secondi prima di ricaricare")
                            return redirect('/')
                        return redirect('/', COUNT_LOWETH_USER)

            COUNT_PATOKEN_EOA = countZeroPatokenCustoumer()
            if GOERLI_FAUCET_ETH_BALANCE >= 0.1 and STARTLOOP:
                GOERLI_FAUCET_ETH_BALANCE = float(
                    web3.fromWei(
                        w3g.eth.getBalance(
                            Web3.toChecksumAddress(
                                faucet_ready.goerli_Address)),
                        'ether'))
                COUNT_LOWETH_USER = countEmptyCustomers()
                context = {
                    'GOERLI_FAUCET_ERC20': GOERLI_FAUCET_ERC20,
                    'GOERLI_FAUCET_ETH_BALANCE': GOERLI_FAUCET_ETH_BALANCE,
                    'BALANCE_FAUCET': BALANCE_FAUCET,
                    'USER_GOERLI_BALANCE': USER_GOERLI_BALANCE,
                    'COUNT_LOWETH_USER': COUNT_LOWETH_USER,
                    'CURRENT_EOA': CURRENT_EOA,
                    'DEPLOY_GOERLI': DEPLOY_GOERLI,
                    'COUNT_PATOKEN_EOA': COUNT_PATOKEN_EOA,
                    'piggyBankScGorliAddress': faucet_ready.piggyBankScGorliAddress,
                    'COUNT_EVENT_TRANSFER_GORLI': COUNT_EVENT_TRANSFER_GORLI}
                if GOERLI_FAUCET_ETH_BALANCE <= 0.2:
                    tx = depositOrWithdrawalTestEth(
                        "Withdrawal",
                        "gorli",
                        0.05,
                        faucet_ready.goerli_Address,
                        goDecript(
                            faucet_ready.encode_pk_goerli_faucet),
                        faucet_ready.goerli_Address)  # implementare meccanismo di TX non duplicate & message
                    messages.error(
                        request,
                        f"Avviato Withdrawal di ulteriori 0.05Eth verso il Faucet ripetibile fino alla soglia 0.2Eth ; propagata TX:" +
                        tx)
                    context.update({'GOERLI_FAUCET_ETH_BALANCE': float(web3.fromWei(
                        w3g.eth.getBalance(Web3.toChecksumAddress(faucet_ready.goerli_Address)), 'ether'))})
                    return render(
                        request, "access_register/testNewFaucet.html", context)
                else:
                    return render(
                        request, "access_register/testNewFaucet.html", context)

                if GOERLI_FAUCET_ETH_BALANCE < 0.1:
                    messages.error(
                        request,
                        f"Attenzione! Il Faucet ha un saldo nullo o minore di 0.15Eth; Per proseguire invia dal tuo Metamask a:" +
                        GOERLI_FAUCET_ERC20 +
                        " degli Ether di Test per superare la soglia indicata attendendo circa 15secondi prima di ricaricare")
                    return redirect('/')
                if COUNT_PATOKEN_EOA != 0:
                    return redirect('/')

    COUNT_LOWETH_USER = countEmptyCustomers()
    context = {
        'GOERLI_FAUCET_ERC20': GOERLI_FAUCET_ERC20,
        'GOERLI_FAUCET_ETH_BALANCE': GOERLI_FAUCET_ETH_BALANCE,
        'BALANCE_FAUCET': BALANCE_FAUCET,
        'USER_GOERLI_BALANCE': USER_GOERLI_BALANCE,
        'COUNT_LOWETH_USER': COUNT_LOWETH_USER,
        'CURRENT_EOA': CURRENT_EOA,
        'DEPLOY_GOERLI': DEPLOY_GOERLI,
        'COUNT_PATOKEN_EOA': COUNT_PATOKEN_EOA,
        'piggyBankScGorliAddress': faucet_ready.piggyBankScGorliAddress,
        'COUNT_EVENT_TRANSFER_GORLI': COUNT_EVENT_TRANSFER_GORLI
    }
    GOERLI_FAUCET_ETH_BALANCE = float(
        web3.fromWei(
            w3g.eth.getBalance(
                Web3.toChecksumAddress(
                    faucet_ready.goerli_Address)),
            'ether'))
    if GOERLI_FAUCET_ETH_BALANCE > 0.1:
        STARTLOOP = True
    else:
        STARTLOOP = False

    if GOERLI_FAUCET_ETH_BALANCE < 0.1:
        messages.error(
            request,
            f"Attenzione! Il Faucet ha un saldo nullo o minore di 0.15Eth; Per proseguire invia dal tuo Metamask a:" +
            GOERLI_FAUCET_ERC20 +
            " degli Ether di Test per superare la soglia indicata attendendo circa 15secondi prima di ricaricare")
        return redirect('/')
    print(faucet_ready.piggyBankScGorliAddress)
    return render(request, "access_register/testNewFaucet.html", context)

# funzione che assegna fondi necessari per pagare Gas in BC Goerli agli USER, tramite richiesta
# del Faucet (Admin) allo SmartContract BootFaucet con la funzione depositOrWithdrawalTestEth

def updateGoerliETHBalance(request):
    COUNT_LOWETH_USER = None
    COUNT_PATOKEN_EOA = countZeroPatokenCustoumer()
    rechargeEthTestGoerliEoA = Customer.objects.all()
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    for eoa in rechargeEthTestGoerliEoA.iterator():
        if float(
            web3.fromWei(
                w3g.eth.getBalance(
                    Web3.toChecksumAddress(
                eoa.user_goerli_Address)),
                'ether')) < 0.05:
            tx = depositOrWithdrawalTestEth(
                "Withdrawal", "gorli", 0.05, faucet_ready.goerli_Address, goDecript(
                    faucet_ready.encode_pk_goerli_faucet), eoa.user_goerli_Address)
            messages.error(
                request,
                f"Al momento " +
                str(
                    countEmptyCustomers()) +
                " utenti hanno bilancio nullo;Avviato processo di trasferimento EthTest verso address: " +
                eoa.user_goerli_Address +
                "; attendere ≈ 15sec e ripetere operazione fino a completamento lista..TX:" +
                tx)
            COUNT_PATOKEN_EOA = countZeroPatokenCustoumer()
            context = {'COUNT_LOWETH_USER': COUNT_LOWETH_USER,
                       'COUNT_PATOKEN_EOA': COUNT_PATOKEN_EOA
                       }
            return redirect('/', context)
    context = {
        'COUNT_LOWETH_USER': COUNT_LOWETH_USER,
        'COUNT_PATOKEN_EOA': COUNT_PATOKEN_EOA
    }
    return render(request, "access_register/homepage.html", context)


def boostEthOnCongestion(request):
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    if float(web3.fromWei(w3g.eth.getBalance(Web3.toChecksumAddress(faucet_ready.goerli_Address)), 'ether')) < 1:
        tx = depositOrWithdrawalTestEth("Withdrawal", "gorli", 0.05, faucet_ready.goerli_Address, goDecript(
            faucet_ready.encode_pk_goerli_faucet), faucet_ready.goerli_Address)
        messages.error(request, f" Avviato processo di trasferimento 0.05 EthTest verso address: " + faucet_ready.goerli_Address +
                       "; ripetere azione fino a bilancio di 0.5 Eth in quanto EoA Admin, Faucet della Piattaforma, necessita costi eccezionali di Gas per via dell attuale Congestione ..TX:" + tx)
        return redirect('/')
    else:
        messages.error(request, f" Saldo Faucet superiore a 1 Eth, dovresti già essere in grado di Deployare i contratti. Se vuoi versare ulteriori fondi inviali dal tuo Metamask a :  " + faucet_ready.goerli_Address)
        return redirect('/')

# funzione che verifica eventuali Account con Balance ERC nullo e assegna la quantità
# randomicamente determinata in fase di creazione e registrate sulle Collection DB

def updateGoerliERC20Balance(request, singolOrAll):
    COUNT_LOWETH_USER = None
    CURRENT_EOA = None
    COUNT_PATOKEN_EOA = countZeroPatokenCustoumer()
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    goerliEoA = Customer.objects.all()
    contractIstance = w3g.eth.contract(
        address=faucet_ready.goerli_deploy_sm_address, abi=abi)
    getPk = goDecript(faucet_ready.encode_pk_goerli_faucet)
    if not request.user.is_superuser:
        current_customer = Customer.objects.get(user=request.user)
        CURRENT_EOA = current_customer.user_goerli_Address
    DEPLOY_GOERLI = faucet_ready.goerli_deploy_sm_address
    goerliAddressFaucet = faucet_ready.goerli_Address
    faucetGoerliEthBalance = float(
        web3.fromWei(
            w3g.eth.getBalance(
                Web3.toChecksumAddress(
                    faucet_ready.goerli_Address)),
            'ether'))

    if DEPLOY_GOERLI == "null":
        DEPLOY_GOERLI = None
    if faucet_ready.goerli_deploy_sm_address == "null":
        COUNT_PATOKEN_EOA = None
    else:
        COUNT_PATOKEN_EOA = countZeroPatokenCustoumer()

    if not AVOID_MULTIMPLE_EOA_TX or (
            faucet_ready.goerli_Address in AVOID_MULTIMPLE_EOA_TX and AVOID_MULTIMPLE_EOA_TX[faucet_ready.goerli_Address] == "null"):
        AVOID_MULTIMPLE_EOA_TX[faucet_ready.goerli_Address] = "busy"
        if singolOrAll == "all":
            for eoa in goerliEoA.iterator():
                if w3g.fromWei(
                        contractIstance.functions.balanceOf(
                            eoa.user_goerli_Address).call(),
                        'ether') == 0:
                    quantity_token = eoa.patoken_wallet
                    faucet_ready.goerli_patoken_wallet -= quantity_token
                    eoa.goerli_patoken_wallet = quantity_token
                    tx = transferToken(
                        "gorli",
                        contractIstance,
                        eoa.user_goerli_Address,
                        faucet_ready.goerli_Address,
                        getPk,
                        quantity_token)
                    messages.error(
                        request,
                        f"Al momento " +
                        str(COUNT_PATOKEN_EOA) +
                        " utenti hanno bilancio PATOKEN_ERC20 nullo;Avviato processo di trasferimento verso address: " +
                        eoa.user_goerli_Address +
                        " ripetere operazione fino a completamento lista..TX:" +
                        tx)
                    deleteDuplicate = Customer.objects.filter(
                        user_id=eoa.user_id)
                    deleteDuplicate.delete()
                    eoa.save()
                    faucet_ready.save()
                    COUNT_PATOKEN_EOA = countZeroPatokenCustoumer()
                    context = {
                        'COUNT_LOWETH_USER': COUNT_LOWETH_USER,
                        'COUNT_PATOKEN_EOA': COUNT_PATOKEN_EOA,
                        'DEPLOY_GOERLI': DEPLOY_GOERLI,
                        'faucetGoerliEthBalance': faucetGoerliEthBalance,
                        'goerliAddressFaucet': goerliAddressFaucet}
                    return redirect('/', context)
        elif singolOrAll == "single":
            if w3g.fromWei(
                    contractIstance.functions.balanceOf(CURRENT_EOA).call(),
                    'ether') == 0:
                quantity_token = current_customer.patoken_wallet
                faucet_ready.patoken_wallet -= quantity_token
                faucet_ready.goerli_patoken_wallet = faucet_ready.patoken_wallet
                current_customer.goerli_patoken_wallet = quantity_token
                tx = transferToken(
                    "gorli",
                    contractIstance,
                    current_customer.user_goerli_Address,
                    faucet_ready.goerli_Address,
                    getPk,
                    quantity_token)
                messages.error(
                    request,
                    f"Avviato processo di trasferimento Patoken verso address: " +
                    current_customer.user_goerli_Address +
                    " propagata su chain Goerli TX:" +
                    tx)
                deleteDuplicate = Customer.objects.filter(
                    user_id=current_customer.user_id)
                deleteDuplicate.delete()
                current_customer.save()
                faucet_ready.save()
                COUNT_PATOKEN_EOA = countZeroPatokenCustoumer()
                context = {'COUNT_PATOKEN_EOA': COUNT_PATOKEN_EOA,
                           'DEPLOY_GOERLI': DEPLOY_GOERLI,
                           'COUNT_LOWETH_USER': COUNT_LOWETH_USER,
                           'faucetGoerliEthBalance': faucetGoerliEthBalance,
                           'goerliAddressFaucet': goerliAddressFaucet}
                return redirect('/', context)
        AVOID_MULTIMPLE_EOA_TX[faucet_ready.goerli_Address] = "null"
    else:
        AVOID_MULTIMPLE_EOA_TX[faucet_ready.goerli_Address] = "null"
        messages.error(
            request,
            "Già propagata altra Tx dallo stesso Account; attendere il completamento della precedente prima di ripetere il comando(ricarica la pagina dal browser e riprova senza click multipli)")
        time.sleep(4)
        return redirect('/')

    context = {
        'COUNT_LOWETH_USER': COUNT_LOWETH_USER,
        'COUNT_PATOKEN_EOA': COUNT_PATOKEN_EOA,
        'faucetGoerliEthBalance': faucetGoerliEthBalance,
        'goerliAddressFaucet': goerliAddressFaucet
    }
    return render(request, "access_register/homepage.html", context)

# Processo registazione User con controllo sincronizzazione Blockchain,e primi Deploy SC
# necessari per le funzioni essenziali(non tutti->scopo performance) della Piattaforma

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
        faucet = FaucetPatoken(id=faucetCounter + 1,
                               user=admin[0],
                               ganache_Address=all_account[FAUCET_ID].lower())

    # condizione iniziale che forza il deploy dello SC
    if (GANACHE_MNMONIC != ""):
        getPk = getPrivatekey(faucet.ganache_Address, request)
        if FaucetPatoken.objects.filter().count() == 0:
            faucet.deploy_sm_address = deploySmartContract(
                getPk, "localGanache", faucet.ganache_Address, abi, bytecode)
            faucet.piggyBankScGanacheAddress = deploySmartContract(
                getPk,
                "localGanache",
                faucet.ganache_Address,
                abiMB,
                bytecodeMB,
                faucet.deploy_sm_address)
            faucet.patoken_wallet = MAX_MINTABLE_SC_TOKEN
            faucet.goerli_patoken_wallet = MAX_MINTABLE_SC_TOKEN
            faucet.goerli_Address = GOERLI_FAUCET_ERC20
            faucet.encode_pk_goerli_faucet = goCript(PK_FAUCET_ERC20)
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

                        goerliEoAddress, keyEoAddress = creteGoerliEoA()

                        if (Customer.objects.filter(
                                user_ganache_Address=ganacheAddress).count() == 0):
                            new_customer.user_ganache_Address = ganacheAddress

                            new_customer.user_goerli_Address = goerliEoAddress
                            new_customer.encode_pk_goerli_User = goCript(
                                keyEoAddress)
                            new_customer.save()
                            break
                        else:
                            i += 1
                    # traferimento effettivo Erc20 Patoken rispetto
                    # all'attribuzione randomica implementata su Db
                    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
                    getPk = getPrivatekey(
                        faucet_ready.ganache_Address, request)
                    contractIstance = web3.eth.contract(
                        address=faucet_ready.deploy_sm_address, abi=abi)
                    quantity_token = new_customer.patoken_wallet
                    faucet_ready.patoken_wallet -= quantity_token
                    faucet_ready.save()
                    Tx = transferToken("localGanache",
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
                    f'Benvenuto/a! {new_customer.user.username}, la piattaforma attribuisce i seguenti patokenERC20 al tuo wallet : {new_customer.patoken_wallet} su Ganache local Blockchain, di seguito il TX associato: {Tx}')
                return redirect('/')
        except BaseException:
            messages.error(
                request,
                f'Attenzione raggiunto il numero massimo di utenti registrabili, in relazione al setting Ganache N° Accounts su BlockChain Locale! Contattare Admin per eventuale cancellazione Account Obsoleto su dB')

    else:
        form = RegistrazionUserForm()
    context = {"form": form}
    return render(request, "registration/registrazione.html", context)

# automatismo per semplificare la customer experience e gestione Account/PK, limitando
# la procedura di sincronizzazione dell'utente all'inserimento della
# MNEMONIC phrase del Ganache WORKSPACE local BC


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

    # per sicurezza oltre a non archiviare le PK nel dB si cancella il Json di
    # supporto usato per lo scopo
    os.remove(rootJS)
    return dictSetKey[address]

# procedura di acquisizione Mnemonic per sincronizzazione istanza Ganache


def getMnemonic(request):
    global GANACHE_MNMONIC
    global BLOCKCHAIN_CONSISTENCY_CHECK
    if request.method == "POST":
        form_w = FormMnemonic(request.POST)
        if form_w.is_valid():
            choice = form_w.save(commit=False)
            GANACHE_MNMONIC = str(choice.mnemonic)
            # per controllare la consistenza del MNMONIC rispetto all'attuale
            # istanza Ganache
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
                    mark_safe(address_account))
                return redirect('/')
    else:
        form_w = FormMnemonic()

    context = {"form_w": form_w}
    return render(request, "access_register/form4.html", context)

# gestione trasferimento Token con uso combinato features precedenti
# View che mostra multichain tutti gli Address degli Account Registrati e SC MoneyMox per
# operazioni di Deposito e/o Traferimento token


@login_required()
def showAddressTransferToken(request, ganacheOrGoerli):
    global BOOST_ETH
    global GLOBAL_CONTEXT
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    if Customer.objects.filter().count() == 0:
        messages.error(
            request,
            f'Occorre registrare degli account associandone un indirizzo della Local Blockchain prima di procedere a questa funzionalità')
        return redirect('/')

    COUNT_EVENT_TRANSFER = None
    if (ExtractedEvent.objects.filter().count()):
        COUNT_EVENT_TRANSFER = ExtractedEvent.objects.filter(
            chain="Ganache").count()

    COUNT_EVENT_TRANSFER_GORLI = None
    if (ExtractedEvent.objects.filter().count()):
        COUNT_EVENT_TRANSFER_GORLI = ExtractedEvent.objects.filter(
            chain="goerli").count()

    customers = Customer.objects.filter()
    faucetAddress = faucet_ready.ganache_Address
    faucetGorliAddress = faucet_ready.goerli_Address
    faucetUser = faucet_ready.user

    if ganacheOrGoerli == "ganache":
        contractIstance = web3.eth.contract(
            address=faucet_ready.deploy_sm_address, abi=abi)
        contractIstanceMB = web3.eth.contract(
            address=faucet_ready.piggyBankScGanacheAddress, abi=abiMB)
        user_current = None

        piggyBankScGanacheAddress = faucet_ready.piggyBankScGanacheAddress
        piggyBankScGorliAddress = None

        if request.user.is_superuser:
            currentBalance = getAllBalance(
                "localGanache", faucet_ready.ganache_Address)[FAUCET_ADDRESS]
            if request.method == "POST":
                form_w = FormFaucet(request.POST)
                if form_w.is_valid():
                    form_w = form_w.save(commit=False)
                    quantityToTransefer = form_w.patoken_wallet
                    addressDestination = form_w.ganache_Address
                    getPk = getPrivatekey(faucetAddress, request)
                    extractBalance = getAllBalance(
                        "localGanache", faucet_ready.ganache_Address)
                    allowedAddress = str(piggyBankScGanacheAddress)
                    i = 0
                    while i < len(extractBalance):
                        allowedAddress += all_account[i]
                        i += 1

                    if len(addressDestination) != 42 or allowedAddress.find(
                            addressDestination) == -1:
                        messages.success(
                            request, f'Attenzione, indirizzo inserito non corretto, riprova')
                        return redirect('/showAddressTransferToken/ganache/')

                    if extractBalance[all_account[FAUCET_ID].lower(
                    )] >= quantityToTransefer:
                        if addressDestination != piggyBankScGanacheAddress:
                            Tx = transferToken(
                                "localGanache",
                                contractIstance,
                                addressDestination,
                                all_account[FAUCET_ID],
                                getPk,
                                quantityToTransefer)
                        else:
                            # Admin in quanto Owner/Deployer già whitelistato
                            Tx = depositERC20onMoneyBox(
                                "localGanache",
                                faucet_ready.deploy_sm_address,
                                faucet_ready.piggyBankScGanacheAddress,
                                all_account[FAUCET_ID],
                                getPk,
                                quantityToTransefer)

                        updateEvents = extractEventByTransaction(
                            Tx, "localGanache", all_account[FAUCET_ID])

                        faucet_ready.patoken_wallet -= quantityToTransefer
                        ganacheEoA = Customer.objects.all()
                        for eoa in ganacheEoA.iterator():
                            if eoa.user_ganache_Address == addressDestination:
                                eoa.patoken_wallet += quantityToTransefer
                                deleteDuplicate = Customer.objects.filter(
                                    user_id=eoa.user_id)
                                deleteDuplicate.delete()
                                eoa.save()
                        faucet_ready.save()
                        messages.success(
                            request,
                            f'Richiesta trasferimento Token propagata correttamente in Blockchain locale Ganache! Di seguito identificatvo Tx: ' +
                            Tx)
                        return redirect('/showAddressTransferToken/ganache/')
                    else:
                        messages.error(
                            request, f'Non si dispone della quantità di token indicata')
                        return redirect('/showAddressTransferToken/ganache/')
            else:
                form_w = FormFaucet()
        else:
            current_customer = Customer.objects.get(user=request.user)
            user_current = current_customer.user
            currentBalance = getAllBalance("localGanache", faucet_ready.ganache_Address)[
                current_customer.user_ganache_Address.lower()]
            if request.method == "POST":
                form_w = FormCustomer(request.POST)
                if form_w.is_valid():
                    form_w = form_w.save(commit=False)
                    quantityToTransefer = form_w.patoken_wallet
                    addressDestination = form_w.user_ganache_Address
                    getPk = getPrivatekey(
                        current_customer.user_ganache_Address.lower(), request)
                    extractBalance = getAllBalance(
                        "localGanache", faucet_ready.ganache_Address)
                    allowedAddress = str(FAUCET_ADDRESS)
                    allowedAddress += str(piggyBankScGanacheAddress)
                    i = 0
                    while i < len(extractBalance):
                        allowedAddress += all_account[i]
                        i += 1

                    if len(addressDestination) != 42 or allowedAddress.find(
                            addressDestination) == -1:
                        messages.success(
                            request, f'Attenzione, indirizzo inserito non corretto, riprova')
                        return redirect('/showAddressTransferToken/ganache/')

                    if extractBalance[current_customer.user_ganache_Address.lower(
                    )] >= quantityToTransefer:
                        if addressDestination != piggyBankScGanacheAddress:
                            Tx = transferToken(
                                "localGanache", contractIstance, addressDestination, str(
                                    current_customer.user_ganache_Address), getPk, quantityToTransefer)
                        else:
                            if verifyEoAWhiteList(str(
                                    current_customer.user_ganache_Address), web3, piggyBankScGanacheAddress) == False:
                                ownerSC_PK = getPrivatekey(
                                    faucet_ready.ganache_Address, request)
                                addWhiteListTx = addWhiteList(
                                    "localGanache",
                                    Web3.toChecksumAddress(
                                        current_customer.user_ganache_Address),
                                    piggyBankScGanacheAddress,
                                    Web3.toChecksumAddress(
                                        faucet_ready.ganache_Address),
                                    ownerSC_PK)
                                while True:
                                    addWhiteListTx_receipt = web3.eth.getTransactionReceipt(
                                        addWhiteListTx)
                                    if addWhiteListTx_receipt is not None and addWhiteListTx_receipt.status == 1:
                                        break
                                    time.sleep(2)
                            Tx = depositERC20onMoneyBox(
                                "localGanache", faucet_ready.deploy_sm_address, faucet_ready.piggyBankScGanacheAddress, str(
                                    current_customer.user_ganache_Address), getPk, quantityToTransefer)

                        updateEvents = extractEventByTransaction(
                            Tx, "localGanache", all_account[FAUCET_ID])

                        current_customer.patoken_wallet -= quantityToTransefer
                        ganacheEoA = Customer.objects.all()
                        ceckTransfer = False
                        for eoa in ganacheEoA.iterator():
                            if eoa.user_ganache_Address == addressDestination:
                                eoa.patoken_wallet += quantityToTransefer
                                deleteDuplicate = Customer.objects.filter(
                                    user_id=eoa.user_id)
                                deleteDuplicate.delete()
                                eoa.save()
                                ceckTransfer = True
                        if ceckTransfer == False and addressDestination != piggyBankScGanacheAddress:
                            faucet_ready.patoken_wallet += quantityToTransefer
                            deleteDuplicate = FaucetPatoken.objects.filter(
                                user_id=faucet_ready.user_id)
                            deleteDuplicate.delete()
                            faucet_ready.save()

                        deleteDuplicate = Customer.objects.filter(
                            user_id=current_customer.user_id)
                        deleteDuplicate.delete()
                        current_customer.save()
                        messages.success(
                            request,
                            f'Richiesta trasferimento Token propagata correttamente in Blockchain! Di seguito identificatvo Tx: ' +
                            Tx)
                        return redirect('/showAddressTransferToken/ganache/')
                    else:
                        messages.error(
                            request, f'Non si dispone della quantità di token indicata')
                        return redirect('/showAddressTransferToken/ganache/')

            else:
                form_w = FormCustomer()

    elif ganacheOrGoerli == "gorli":
        contractIstance = w3g.eth.contract(
            address=faucet_ready.goerli_deploy_sm_address, abi=abi)
        user_current = None
        piggyBankScGorliAddress = faucet_ready.piggyBankScGorliAddress
        piggyBankScGanacheAddress = None

        # possibile miglioramento gestione tentativi Tx multiple dall'user
        if request.user.is_superuser:
            currentBalance = w3g.fromWei(
                contractIstance.functions.balanceOf(
                    faucet_ready.goerli_Address).call(), 'ether')
            if faucet_ready.piggyBankScGorliAddress == "null" or faucet_ready.piggyBankScGorliAddress == "":
                try:
                    faucet_ready.piggyBankScGorliAddress = deploySmartContract(
                        goDecript(
                            faucet_ready.encode_pk_goerli_faucet),
                        "gorli",
                        faucet_ready.goerli_Address,
                        abiMB,
                        bytecodeMB,
                        faucet_ready.goerli_deploy_sm_address)
                    faucet_ready.save()
                    context = {
                        'piggyBankScGorliAddress': faucet_ready.piggyBankScGorliAddress,
                        'COUNT_EVENT_TRANSFER_GORLI': COUNT_EVENT_TRANSFER_GORLI}
                    messages.success(
                        request,
                        f'Eseguito Deploy su Goerli dello SC Moneybox ,address {faucet_ready.piggyBankScGorliAddress}')
                    return redirect('/showAddressTransferToken/gorli/', context)
                except BaseException:
                    BOOST_ETH = "request"
                    context = ({'BOOST_ETH': BOOST_ETH})
                    context.update(GLOBAL_CONTEXT)
                    context.update({'BOOST_ETH': BOOST_ETH})
                    messages.error(
                        request,
                        f'Le anomale condizioni di congestione su Goerli richiedono probabilmente maggior Gas per il Deploy dello SmartContract. Inviare fondi aggiuntivi dal proprio Metamask ad Address '+faucet_ready.goerli_Address + ' o clicca il pulsante in basso a Destra sulla Home per richiedere al BootFaucet un Boost di 0.05Eth fino a max 1 Eth; Prima di riprovare il deploy MoneyBox SC,si consiglia di portare il Balance del Faucet Admin ad almeno a 0.5 Eth tramite richieste consecutive e attesa rispettivo codice TX prima del reinoltro')
                    return render(request, "access_register/homepage.html", context)

            if request.method == "POST":
                form_w = FormFaucet(request.POST)
                if form_w.is_valid():
                    form_w = form_w.save(commit=False)
                    gorliEoA = Customer.objects.all()
                    quantityToTransefer = form_w.patoken_wallet
                    addressDestination = form_w.goerli_Address
                    allowedAddress = str(faucet_ready.piggyBankScGorliAddress)
                    for eoa in gorliEoA.iterator():
                        allowedAddress += eoa.user_goerli_Address

                    if len(addressDestination) != 42 or allowedAddress.find(
                            addressDestination) == -1:
                        messages.success(
                            request, f'Attenzione, indirizzo inserito non corretto, riprova')
                        return redirect('/showAddressTransferToken/gorli/')

                    if currentBalance >= quantityToTransefer:
                        getPk = goDecript(faucet_ready.encode_pk_goerli_faucet)

                        counter_EvIstance = ExtractedEvent.objects.filter().count()

                        if addressDestination != str(
                                faucet_ready.piggyBankScGorliAddress):
                            Tx = transferToken(
                                "gorli",
                                contractIstance,
                                addressDestination,
                                faucet_ready.goerli_Address,
                                getPk,
                                quantityToTransefer)

                            istance_event = ExtractedEvent(
                                id=counter_EvIstance,
                                recipientAddress=addressDestination,
                                senderAddress=faucet_ready.goerli_Address,
                                amountErcTransfer=quantityToTransefer,
                                transact=Tx,
                                chain="goerli")  # +#
                        else:
                            Tx = depositERC20onMoneyBox(
                                "gorli",
                                faucet_ready.goerli_deploy_sm_address,
                                faucet_ready.piggyBankScGorliAddress,
                                faucet_ready.goerli_Address,
                                getPk,
                                quantityToTransefer)

                            istance_event = ExtractedEvent(
                                id=counter_EvIstance,
                                recipientAddress=faucet_ready.goerli_deploy_sm_address,
                                senderAddress=faucet_ready.goerli_Address,
                                amountErcTransfer=quantityToTransefer,
                                transact=Tx,
                                chain="goerli")  # +#

                        istance_event.save()

                        faucet_ready.goerli_patoken_wallet -= quantityToTransefer
                        for eoa in gorliEoA.iterator():
                            if eoa.user_goerli_Address == addressDestination:
                                eoa.goerli_patoken_wallet += quantityToTransefer
                                deleteDuplicate = Customer.objects.filter(
                                    user_id=eoa.user_id)
                                deleteDuplicate.delete()
                                eoa.save()
                        faucet_ready.save()
                        context = {
                            'piggyBankScGanacheAddress': faucet_ready.piggyBankScGorliAddress,
                            'piggyBankScGorliAddress': faucet_ready.piggyBankScGorliAddress,
                            'COUNT_EVENT_TRANSFER_GORLI': COUNT_EVENT_TRANSFER_GORLI}
                        messages.success(
                            request,
                            f'Richiesta trasferimento Token propagata correttamente in TestNet Gorli! Di seguito identificatvo Tx: ' +
                            Tx)
                        return redirect(
                            '/showAddressTransferToken/gorli/', context)

                    else:
                        messages.error(
                            request, f'Non si dispone della quantità di token indicata')
                        return redirect('/showAddressTransferToken/gorli/')
            else:
                form_w = FormFaucet()

        else:
            current_customer = Customer.objects.get(user=request.user)
            user_current = current_customer.user
            currentBalance = w3g.fromWei(
                contractIstance.functions.balanceOf(
                    current_customer.user_goerli_Address).call(), 'ether')
            if request.method == "POST":
                form_w = FormCustomer(request.POST)
                if form_w.is_valid():
                    form_w = form_w.save(commit=False)
                    quantityToTransefer = form_w.patoken_wallet
                    addressDestination = form_w.user_ganache_Address
                    gorliEoA = Customer.objects.all()
                    allowedAddress = str(faucet_ready.goerli_Address)
                    allowedAddress += str(faucet_ready.piggyBankScGorliAddress)
                    for eoa in gorliEoA.iterator():
                        allowedAddress += eoa.user_goerli_Address

                    if len(addressDestination) != 42 or allowedAddress.find(
                            addressDestination) == -1:
                        messages.success(
                            request, f'Attenzione, indirizzo inserito non corretto, riprova')
                        return redirect('/showAddressTransferToken/gorli/')

                    if currentBalance >= quantityToTransefer:
                        getPk = goDecript(
                            current_customer.encode_pk_goerli_User)

                        counter_EvIstance = ExtractedEvent.objects.filter().count()

                        if addressDestination != piggyBankScGorliAddress:
                            Tx = transferToken("gorli", contractIstance, addressDestination, str(
                                current_customer.user_goerli_Address), getPk, quantityToTransefer)
                            istance_event = ExtractedEvent(
                                id=counter_EvIstance,
                                recipientAddress=addressDestination,
                                senderAddress=str(
                                    current_customer.user_goerli_Address),
                                amountErcTransfer=quantityToTransefer,
                                transact=Tx,
                                chain="goerli")

                        else:
                            if verifyEoAWhiteList(str(
                                    current_customer.user_goerli_Address), w3g, piggyBankScGorliAddress) == False:
                                ownerSC_PK = goDecript(
                                    faucet_ready.encode_pk_goerli_faucet)
                                addWhiteListTx = addWhiteList(
                                    "gorli",
                                    Web3.toChecksumAddress(
                                        current_customer.user_goerli_Address),
                                    piggyBankScGorliAddress,
                                    Web3.toChecksumAddress(
                                        faucet_ready.goerli_Address),
                                    ownerSC_PK)

                                addWhiteListTx_receipt = None
                                while True:
                                    try:
                                        addWhiteListTx_receipt = w3g.eth.getTransactionReceipt(
                                            addWhiteListTx)
                                        if addWhiteListTx_receipt is not None:
                                            break
                                    except BaseException:
                                        time.sleep(15)

                                if addWhiteListTx_receipt.status == 1:
                                    Tx = depositERC20onMoneyBox(
                                        "gorli", faucet_ready.goerli_deploy_sm_address, faucet_ready.piggyBankScGorliAddress, str(
                                            current_customer.user_goerli_Address), getPk, quantityToTransefer)
                                    istance_event = ExtractedEvent(
                                        id=counter_EvIstance,
                                        recipientAddress=faucet_ready.piggyBankScGorliAddress,
                                        senderAddress=str(
                                            current_customer.user_goerli_Address),
                                        amountErcTransfer=quantityToTransefer,
                                        transact=Tx,
                                        chain="goerli")
                            else:
                                Tx = depositERC20onMoneyBox(
                                    "gorli", faucet_ready.goerli_deploy_sm_address, faucet_ready.piggyBankScGorliAddress, str(
                                        current_customer.user_goerli_Address), getPk, quantityToTransefer)
                                istance_event = ExtractedEvent(
                                    id=counter_EvIstance,
                                    recipientAddress=faucet_ready.piggyBankScGorliAddress,
                                    senderAddress=str(
                                        current_customer.user_goerli_Address),
                                    amountErcTransfer=quantityToTransefer,
                                    transact=Tx,
                                    chain="goerli")
                        istance_event.save()
                        current_customer.goerli_patoken_wallet -= quantityToTransefer
                        gorliEoA = Customer.objects.all()
                        ceckTransfer = False
                        for eoa in gorliEoA.iterator():
                            if eoa.user_goerli_Address == addressDestination:
                                eoa.goerli_patoken_wallet += quantityToTransefer
                                deleteDuplicate = Customer.objects.filter(
                                    user_id=eoa.user_id)
                                deleteDuplicate.delete()
                                eoa.save()
                                ceckTransfer = True
                        if ceckTransfer == False and addressDestination != piggyBankScGorliAddress:
                            faucet_ready.goerli_patoken_wallet += quantityToTransefer
                            deleteDuplicate = FaucetPatoken.objects.filter(
                                user_id=faucet_ready.user_id)
                            deleteDuplicate.delete()
                            faucet_ready.save()
                        deleteDuplicate = Customer.objects.filter(
                            user_id=current_customer.user_id)
                        deleteDuplicate.delete()
                        current_customer.save()
                        messages.success(
                            request,
                            f'Richiesta trasferimento Token propagata correttamente in Blockchain Goreli! Di seguito identificatvo Tx: ' +
                            Tx)
                        return redirect('/showAddressTransferToken/gorli/')
                    else:
                        messages.error(
                            request, f'Non si dispone della quantità di token indicata')
                        return redirect('/showAddressTransferToken/gorli/')
            else:
                form_w = FormCustomer()

    context = {
        "form_w": form_w,
        'customers': customers,
        'faucetAddress': faucetAddress,
        'faucetUser': faucetUser,
        'currentBalance': currentBalance,
        'user_current': user_current,
        'ganacheOrGoerli': ganacheOrGoerli,
        'faucetGorliAddress': faucetGorliAddress,
        'piggyBankScGanacheAddress': piggyBankScGanacheAddress,
        'piggyBankScGorliAddress': faucet_ready.piggyBankScGorliAddress,
        'COUNT_EVENT_TRANSFER': COUNT_EVENT_TRANSFER,
        'COUNT_EVENT_TRANSFER_GORLI': COUNT_EVENT_TRANSFER_GORLI
    }
    return render(request, "balancesTransfer.html", context)

# view multichain che consente il ritiro di Token precedentemente depositato sullo SC MoneyBox


def getWithdrawERC20view(request, ganacheOrGoerli):
    faucet_ready = list(FaucetPatoken.objects.filter())[-1]
    if not request.user.is_superuser:
        current_customer = Customer.objects.get(user=request.user)
        if ganacheOrGoerli == "ganache":
            balanceEoAToken = verifyERC20EoaBalanceOnMoneyBox(
                current_customer.user_ganache_Address,
                web3,
                faucet_ready.piggyBankScGanacheAddress)
        elif ganacheOrGoerli == "goerli":
            balanceEoAToken = verifyERC20EoaBalanceOnMoneyBox(
                current_customer.user_goerli_Address, w3g, faucet_ready.piggyBankScGorliAddress)
    else:
        if ganacheOrGoerli == "ganache":
            balanceEoAToken = verifyERC20EoaBalanceOnMoneyBox(Web3.toChecksumAddress(
                faucet_ready.ganache_Address), web3, faucet_ready.piggyBankScGanacheAddress)
        elif ganacheOrGoerli == "goerli":
            balanceEoAToken = verifyERC20EoaBalanceOnMoneyBox(Web3.toChecksumAddress(
                faucet_ready.goerli_Address), w3g, faucet_ready.piggyBankScGorliAddress)

    if request.method == "POST":
        form_w = FormCustomer(request.POST)
        if form_w.is_valid():
            choice = form_w.save(commit=False)
            quantityWithdraw = int(choice.patoken_wallet * 10**18)
            if not request.user.is_superuser:
                if ganacheOrGoerli == "ganache":
                    getPk = getPrivatekey(
                        current_customer.user_ganache_Address.lower(), request)
                    tx = withdrawERC20fromMoneyBox(
                        current_customer.user_ganache_Address,
                        getPk,
                        web3,
                        faucet_ready.piggyBankScGanacheAddress,
                        quantityWithdraw)
                    current_customer.patoken_wallet += int(
                        choice.patoken_wallet)
                    deleteDuplicate = Customer.objects.filter(
                        user_id=current_customer.user_id)
                    deleteDuplicate.delete()
                    current_customer.save()

                elif ganacheOrGoerli == "goerli":
                    getPk = goDecript(current_customer.encode_pk_goerli_User)
                    tx = withdrawERC20fromMoneyBox(
                        current_customer.user_goerli_Address,
                        getPk,
                        w3g,
                        faucet_ready.piggyBankScGorliAddress,
                        quantityWithdraw)
                    current_customer.goerli_patoken_wallet += int(
                        choice.patoken_wallet)
                    deleteDuplicate = Customer.objects.filter(
                        user_id=current_customer.user_id)
                    deleteDuplicate.delete()
                    current_customer.save()
            else:
                if ganacheOrGoerli == "ganache":
                    getPk = getPrivatekey(FAUCET_ADDRESS, request)
                    tx = withdrawERC20fromMoneyBox(
                        Web3.toChecksumAddress(
                            faucet_ready.ganache_Address),
                        getPk,
                        web3,
                        faucet_ready.piggyBankScGanacheAddress,
                        quantityWithdraw)
                    faucet_ready.patoken_wallet += int(choice.patoken_wallet)
                    faucet_ready.save()
                elif ganacheOrGoerli == "goerli":
                    getPk = goDecript(faucet_ready.encode_pk_goerli_faucet)
                    tx = withdrawERC20fromMoneyBox(
                        Web3.toChecksumAddress(
                            faucet_ready.goerli_Address),
                        getPk,
                        w3g,
                        faucet_ready.piggyBankScGorliAddress,
                        quantityWithdraw)
                    faucet_ready.goerli_patoken_wallet += int(
                        choice.patoken_wallet)
                    faucet_ready.save()
            if (tx == "You haven't enough funds deposited in the MoneyBox"):
                messages.error(
                    request, f"You haven t enough funds deposited in the MoneyBox")
                return redirect(
                    '/getWithdrawERC20view/' +
                    ganacheOrGoerli +
                    '/')
            messages.error(request, f'Propagata in Blockchain Tx: ' + tx)
            return redirect('/getWithdrawERC20view/' + ganacheOrGoerli + '/')
    else:
        form_w = FormCustomer()

    context = {"form_w": form_w,
               "balanceEoAToken": balanceEoAToken
               }
    return render(request, "access_register/form5.html", context)
