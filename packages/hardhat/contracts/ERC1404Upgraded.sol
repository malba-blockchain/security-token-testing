//SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "hardhat/console.sol";

/**
 * @author Carlos Mario Alba Rodriguez
 */
contract ERC1404Upgraded is ERC20, ERC20Burnable, ERC20Pausable, AccessControl, ReentrancyGuard {

    ////////////////// SMART CONTRACT ROLES //////////////////
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant WHITELISTER_ROLE = keccak256("WHITELISTER_ROLE");

    ////////////////// SMART CONTRACT VARIABLES //////////////////
    uint256 public tokenPrice;

    uint256 public minimumInvestmentAllowedInUSD;

    uint256 public maximumInvestmentAllowedInUSD;

    uint256 public tokenTotalSupply;

    uint256 public maximumSupplyPerIssuance;

    uint8 public tokenOwnershipPercentageLimit;

    address public treasuryAddress;

    //Issuance date => amount of tokens to issue
    mapping(uint256 => uint256)[] public issuancePeriods;

    mapping(address => InvestorData) public investorsWhitelist;

    struct InvestorData {
        bool isAccreditedInvestor;
        bool isNonAccreditedInvestor;
        uint256 totalTokensBoughtByInvestor;
        uint256 totalUsdDepositedByInvestor;
        uint256 walletLockUpTime;
        bool isLocked;
    }

    /**
     * @dev Address of MATIC token price feed (Oracle) in the blockchain.
     */
    address public maticPriceFeedAddress;

    /**
     * @dev Aggregator that allows asking for the price of crypto tokens.
     */
    AggregatorV3Interface internal dataFeedMatic;
    

    ////////////////// SMART CONTRACT EVENTS //////////////////

    ////////////////// SMART CONTRACT CONSTRUCTOR //////////////////

    constructor(string memory name, string memory symbol, address defaultAdmin, address pauser, address minter, address whitelister) 
        ERC20(name, symbol) ReentrancyGuard() {
        
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(PAUSER_ROLE, pauser);
        _grantRole(MINTER_ROLE, minter);
        _grantRole(WHITELISTER_ROLE, whitelister);
      
    }

    ////////////////// SMART CONTRACT FUNCTIONS //////////////////

  
    function addToAccreditedInvestorWhitelist(address _investorAddress) external onlyRole(WHITELISTER_ROLE){
        
        // Ensure that the investor address to add is not the zero address
        require(_investorAddress != address(0), "Investor address to add to the accredited whitelist can not be the zero address");

        // Ensure that the investor address has not already been added to the accredited whitelist
        require(investorsWhitelist[_investorAddress].isAccreditedInvestor != true, "That investor address has already been added to the accredited whitelist");

        // Add the investor address to the accredited whitelist
        investorsWhitelist[_investorAddress].isAccreditedInvestor = true;
    }

    function removeFromAccreditedInvestorWhitelist(address _investorAddress) external onlyRole(WHITELISTER_ROLE) {

        // Ensure that the investor address is registered on the accredited whitelist
        require(investorsWhitelist[_investorAddress].isAccreditedInvestor == true, "That investor address is not registered on the accredited whitelist");

        // Remove the investor address from the accredited whitelist
        investorsWhitelist[_investorAddress].isAccreditedInvestor = false;
    }

    function addToNonAccreditedInvestorWhiteList(address _investorAddress) external onlyRole(WHITELISTER_ROLE){
        
        // Ensure that the investor address to add is not the zero address
        require(_investorAddress != address(0), "Investor address to add to the non accredited whitelist can not be the zero address");

        // Ensure that the investor address has not already been added to the non accredited whitelist
        require(investorsWhitelist[_investorAddress].isNonAccreditedInvestor != true, "That investor address has already been added to the non accredited whitelist");

        // Add the investor address to the non accredited whitelist
        investorsWhitelist[_investorAddress].isNonAccreditedInvestor = true;
    }

    function removeFromNonAccreditedInvestorWhitelist(address _investorAddress) external onlyRole(WHITELISTER_ROLE) {

        // Ensure that the investor address is registered on the non accredited whitelist
        require(investorsWhitelist[_investorAddress].isNonAccreditedInvestor == true, "That investor address is not registered on the non accredited whitelist");

        // Remove the investor address from the non accredited whitelist
        investorsWhitelist[_investorAddress].isNonAccreditedInvestor = false;
    }

    function updateTokenOwnershipPercentageLimit(uint8 _newTokenOwnershipPercentageLimit) external onlyRole(DEFAULT_ADMIN_ROLE) {

        require(_newTokenOwnershipPercentageLimit!= 0 && _newTokenOwnershipPercentageLimit<=100, "The new token ownership percentage limit must be between 1 and 100");

        tokenOwnershipPercentageLimit = _newTokenOwnershipPercentageLimit;
    }

    function lockInvestorAccount(address _investorAddress) external onlyRole(WHITELISTER_ROLE) {

        // Ensure that the investor address to lock is not the zero address
        require(_investorAddress != address(0), "Investor address to lock can not be the zero address");

        // Ensure that the investor address to lock is not currently locked
        require(investorsWhitelist[_investorAddress].isLocked == false, "The investor address is currently locked");

        investorsWhitelist[_investorAddress].isLocked = true;
    }

    function unlockInvestorAccount(address _investorAddress) external onlyRole(WHITELISTER_ROLE) {

        // Ensure that the investor address to unlock is not the zero address
        require(_investorAddress != address(0), "Investor address to unlock can not be the zero address");

        // Ensure that the investor address to unlock is not currently unlocked
        require(investorsWhitelist[_investorAddress].isLocked == true, "The investor address is currently unlocked");

        investorsWhitelist[_investorAddress].isLocked = false;
    }

    function calculateTotalTokensToReturn(uint256 _amount, uint256 _currentCryptocurrencyPrice) public view returns (uint256 totalInvestmentInUsd, uint256 totalTokensToReturn) {
        
        //Decimals in math operation. Because the cryptocurrency price feed and the token price comes with 8 decimals
        uint256 decimalsInMathOperation = 10 ** 8;

        //Calculate the total investment in USD and divide by 10**8
        totalInvestmentInUsd = SafeMath.div((SafeMath.mul(_amount, _currentCryptocurrencyPrice)), decimalsInMathOperation);

        //Calcuale the amount of tokens to return given the current token price and multiply it by 10**8
        totalTokensToReturn = SafeMath.mul((SafeMath.div(totalInvestmentInUsd, tokenPrice)), decimalsInMathOperation);

        //Validate that the amount to invest is equal or greater than the minimum investment established in USD
        require(totalInvestmentInUsd >= minimumInvestmentAllowedInUSD, "The amount to invest must be greater than the minimum established");

        //Validate that the amount of tokens to offer to the investor is equal or less than the amount that's left in the smart contract
        require(totalTokensToReturn <= balanceOf(address(this)), "The investment made returns an amount of tokens greater than the available");

        return (totalInvestmentInUsd, totalTokensToReturn);
    }

    /**
     * @dev Function to issue tokens as required.
     * @param _amount The amount of new tokens to issue.
     */
    function tokenIssuance(uint256 _amount) public onlyRole(MINTER_ROLE) nonReentrant {
        
        // Ensure that the amount to issue in this execution is at least 1 token
        require(_amount >= 1 * 10 ** decimals(), "Amount of tokens to issue must be at least 1 token");
        
        // Ensure that the amount to issue in this execution is below the maximum supply per issuance
        require(_amount <= maximumSupplyPerIssuance * 10 ** decimals(), "Amount of tokens to issue at a time must be below the maximum supply per issuance");
        
        // Validate the amount to issue doesn't go beyond the established total supply
        uint256 newTotalSupply = SafeMath.add(totalSupply(), _amount);
        
        require(newTotalSupply <= tokenTotalSupply * 10 ** decimals(), "Amount of HYAX tokens to issue surpases the 10,000 M tokens");

        // Mint the specified amount of tokens to the owner
        _mint(owner(), _amount);

    }


    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    // The following function is a override required by Solidity to inherit from ERC20 and ERC20Pausable
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override(ERC20, ERC20Pausable) {
        ERC20Pausable._beforeTokenTransfer(from, to, amount);
    }


}
