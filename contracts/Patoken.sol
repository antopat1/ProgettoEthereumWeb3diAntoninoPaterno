//SPDX-License-Identifier:UNLICENSED
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract Patoken is ERC20, ERC20Burnable, Ownable{
    address public admin; //definisco un amministratore
    constructor() ERC20("patoken","PTK"){
        _mint(msg.sender, 10000 * 10 ** 18);
        admin = msg.sender;
    }
        function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

}
