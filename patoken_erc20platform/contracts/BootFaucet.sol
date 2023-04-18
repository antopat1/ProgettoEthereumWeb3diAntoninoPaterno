//SPDX-License-Identifier: MIT
pragma solidity ^0.8.3;

contract BootFaucet {
	

    //state variable to keep track of owner and amount of ETHER to dispense
    address public owner;
    uint public amountAllowed = 50000000000000000;

	constructor() payable {
		owner = msg.sender;
	}

    //function modifier
    modifier onlyOwner {
        require(msg.sender == owner, "Only owner can call this function.");
        _; 
    }

    //function to change the owner.  Only the owner of the contract can call this function
    function setOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }

    //function to set the amount allowable to be claimed. Only the owner can call this function
    function setAmountallowed(uint newAmountAllowed) public onlyOwner {
        amountAllowed = newAmountAllowed;
    }

    //function to donate funds to the faucet contract
	function donateTofaucet() public payable {
	}
    
    receive() external payable {
    donateTofaucet();
}

    //function to send tokens from faucet to an address
    /*function requestTokens(address payable _requestor) public payable {

        require(address(this).balance > amountAllowed, "Not enough funds in the faucet. Please donate");

        _requestor.transfer(amountAllowed);        

    }*/

    function withdrawalFromFaucet(address payable _requestor) external{
        
        require(address(this).balance >= amountAllowed, "This faucet is empty. Please check back later.");
  
        payable(_requestor).transfer(amountAllowed);

        
    }

}