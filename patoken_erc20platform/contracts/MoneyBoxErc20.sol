//SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol"; 
import "contracts/Patoken.sol";

contract MoneyBoxErc20  {
    address owner;
    address delegateToUse;
    uint256 ethBalance;  
    IERC20 token;
    bool ledgerBalanceBroken;
    mapping(address => bool) whitelistedAddresses;
    mapping(address => uint256) ethBalanceForUser;
    mapping(address => uint256) erc20BalanceForUser;
    
    event TransferReceived(address _from, uint256 _amount);
    event ChangesDelegateTospend(address _initialAccount, address _finalAccount);   
    event TransferSent(address _from, address _destAddr, uint256 _amount);
    event TransferSentErc20(address _from, address _destAddr, uint256 _amount);
    event DepositERC20(address _from, uint256 _amount);

    constructor(IERC20 _scAddress) payable {
        owner = msg.sender;
        delegateToUse=msg.sender;
        ethBalanceForUser[msg.sender]=msg.value;
        ethBalance=msg.value;
        token=_scAddress;
        whitelistedAddresses[msg.sender] = true;
        ledgerBalanceBroken=false;
    }
    
    modifier onlyOwner() {
      require(msg.sender == owner, "Only owner can set who can Use the MoneyBox");
      _;
    }

    modifier checkEnoughEthBalance(uint256 _amountTransf,address _checkAddr) {
      require(getEthBalanceForUser(_checkAddr)>=_amountTransf && _amountTransf <= ethBalance,"You haven't enough funds deposited in the MoneyBox");
      _;
    }
 

    modifier checkWhiteList(address _checkAddr) {
        require(verifyUser(_checkAddr)==true,"operation not allowed, address not belonging to the platform/non-whitelisted");
      _;
    }

    modifier checkEnoughERC20Balance(address _checkAddr,uint256 _amountTransf) {
      require(getERC20balanceForUser(_checkAddr)>=_amountTransf && _amountTransf <=token.balanceOf(address(this)),"You haven't enough funds deposited in the MoneyBox");
      _;
    }

    modifier inconsistencyControll (){
        require(ledgerBalanceBroken==false,"Ledger of deposits has been broken by withdrawal of total balance from owner or his delegate; function not invokable");
        _;
    }


    function addUserInPlatform(address _addressToWhitelist) public onlyOwner inconsistencyControll{
      whitelistedAddresses[_addressToWhitelist] = true;
    }
    

    function verifyUser(address _whitelistedAddress) public view returns(bool) {
      bool userIsWhitelisted = whitelistedAddresses[_whitelistedAddress];
      return userIsWhitelisted;
    }

    function setDelegateToFullWithdraw(address _delegateToUse) public onlyOwner inconsistencyControll  {
        require (verifyUser(_delegateToUse)==true,"non-whitelisted address");
        emit ChangesDelegateTospend(delegateToUse, _delegateToUse); 
        delegateToUse=_delegateToUse;
    }
    
    function depositEth(uint256 _amount) public payable checkWhiteList(msg.sender) inconsistencyControll {
        require (_amount == msg.value,"Attention, set the same value in the 'amount' and 'value' transaction fields");
        ethBalance += msg.value;
        ethBalanceForUser[msg.sender]+=msg.value;
        emit TransferReceived(msg.sender, msg.value);
    }
    

    function depositErc20(uint256 _amount) public checkWhiteList(msg.sender) inconsistencyControll {
        token.transferFrom(msg.sender,address(this),_amount);
        erc20BalanceForUser[msg.sender]+=_amount;
        emit DepositERC20(msg.sender, _amount);
    }
    
    function getEthTotalBalance() view public returns (uint256) {
        return address(this).balance;
    }

    function getEthBalanceForUser(address _searchAddr) view public inconsistencyControll returns (uint256) {       
        require(_searchAddr==msg.sender,"you cannot check the balances of other addresses than yours");
        return ethBalanceForUser[_searchAddr];
    }

    function getOwner() view public returns (address) {
        return owner;
    }

    function viewDelegateToUse() view public returns (address) {
        return delegateToUse;
    }
    
    function checkLedgerInconsistency() view public returns (bool) {
        return ledgerBalanceBroken;
    }
    
    function reinitializeLedger() public onlyOwner(){
        require(ledgerBalanceBroken==true,"invokable function only if Ledger of deposits is broken by withdrawal from total balance");
        delegateToUse=owner;
        token.transfer(owner, getTotalERC20balance());
        payable(owner).transfer(ethBalance);
        ledgerBalanceBroken=false;
    }

    function transferERC20TotalBalance(address _to, uint256 _amount) public {
        require (verifyUser(_to)==true,"transfer not allowed, address not belonging to the platform/non-whitelisted");
        require(msg.sender == owner || msg.sender == delegateToUse, "Only owner or delegate can withdraw funds"); 
        uint256 erc20balance = getTotalERC20balance(); /*token.balanceOf(address(this));*/
        require(_amount <= erc20balance, "balance is low");
        token.transfer(_to, _amount);
        emit TransferSentErc20(msg.sender, _to, _amount);
        if (getTotalERC20balance()!= 0 && _amount!=0){
            ledgerBalanceBroken=true;
        }
    }  
    
    function withdrawEthTotalBalance(uint256 _amount, address payable _destAddr) public  {
        require (verifyUser(_destAddr)==true,"transfer not allowed, address not belonging to the platform/non-whitelisted");
        require(msg.sender == owner || msg.sender == delegateToUse, "Only owner or delegate can withdraw funds"); 
        require(_amount <= ethBalance, "Insufficient funds");  
        _destAddr.transfer(_amount);
        ethBalance -= _amount;
        emit TransferSent(msg.sender, _destAddr, _amount);
        if (ethBalance!= 0 && _amount!=0){
            ledgerBalanceBroken=true;
        }
    }

    function withdrawEthForUser(uint256 _amount, address payable _destAddr) public checkEnoughEthBalance(_amount,msg.sender) inconsistencyControll {
        require(_destAddr==msg.sender,"You can withdraw only your funds in your address!");
        require (verifyUser(msg.sender)==true,"transfer not allowed, address not belonging to the platform/non-whitelisted");
        require(_amount <= ethBalance, "Insufficient funds"); 
        _destAddr.transfer(_amount);
        ethBalance -= _amount;
        ethBalanceForUser[_destAddr]-=_amount;
        emit TransferSent(msg.sender, _destAddr, _amount);
    }
  
    function withdrawERC20ForUser(uint256 _amount) public checkEnoughERC20Balance(msg.sender,_amount) inconsistencyControll{
        require (verifyUser(msg.sender)==true,"transfer not allowed, address not belonging to the platform/non-whitelisted"); 
        token.transfer(msg.sender, _amount);
        erc20BalanceForUser[msg.sender]-=_amount;
        emit TransferSentErc20(msg.sender, msg.sender, _amount);
    }  


    function getTotalERC20balance() view public returns (uint256) {
        return token.balanceOf(address(this));
    } 
    
    function getERC20balanceForUser(address _searchAddr) view public inconsistencyControll returns (uint256) {
        require(_searchAddr==msg.sender,"you cannot check the balances of other addresses than yours");
        return erc20BalanceForUser[_searchAddr];
    } 
} 