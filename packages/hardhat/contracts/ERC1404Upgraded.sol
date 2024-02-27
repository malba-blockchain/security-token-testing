//SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "hardhat/console.sol";

/**
 * @author Carlos Mario Alba Rodriguez
 */
contract ERC1404Upgraded is ERC20, ERC20Pausable, Ownable, AccessControl, ReentrancyGuard {

    ////////////////// SMART CONTRACT ROLES //////////////////
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant WHITELISTER_ROLE = keccak256("WHITELISTER_ROLE");

    ////////////////// SMART CONTRACT VARIABLES //////////////////

    string public officialDocumentationURL;

    string public officialWebsite;

    string public whitepaperURL;

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
        bool isLockedByInvestor;
        bool isLockedByIssuer;
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

    event AccreditedInvestorAddedToWhiteList(address sender, address _investorAddress);
    event AccreditedInvestorRemovedFromWhiteList(address sender, address _investorAddress);
    event NonAccreditedInvestorAddedToWhiteList(address sender, address _investorAddress);
    event NonAccreditedInvestorRemovedFromWhiteList(address sender, address _investorAddress);
    event UpdatedOfficialDocumentationURL(string _newOfficialDocumentationURL);
    event UpdatedOfficialWebsite(string _newOfficialWebsite);
    event UpdatedWhitepaperURL(string _newWhitepaperURL);
    event IssueTokens(address sender, uint256 amount);
    event InvestFromMatic(address sender, uint256 maticAmount, uint256 totalInvestmentInUSD, uint256 tokensAmount);
    event UpdatedTokenPrice(uint256 _newTokenPrice);
    event UpdatedMinimumInvestmentAllowedInUSD(uint256 _newMinimumInvestmentAllowedInUSD);
    event UpdatedMaximumInvestmentAllowedInUSD(uint256 _newMaximumInvestmentAllowedInUSD);
    event UpdatedTreasuryAddress(address _newTreasuryAddress);
    event TokensBurned(uint256 _amount);
    event UpdateTokenOwnershipPercentageLimit(uint256 _newTokenOwnershipPercentageLimit);
    event LockedInvestorAccount(address _investorAccount);
    event UnlockedInvestorAccount(address _investorAccount);
    event UpdatedLockupTimeAsInvestor(address sender, uint256 walletLockUpTime);
    event UpdatedLockupTimeAsIssuer(address sender, uint256 walletLockUpTime);
    event UpdatedMaticPriceFeedAddress(address _newMaticPriceFeedAddress);

    ////////////////// SMART CONTRACT CONSTRUCTOR //////////////////

    constructor(string memory name, string memory symbol, uint256 _tokensToIssue, address _defaultAdmin, address _pauser, 
        address _minter, address _burner, address _whitelister, address _treasuryAddress, address _maticPriceDataFeedMock, uint256 _tokenTotalSupply, 
        uint256 _maximumSupplyPerIssuance, uint256 _tokenPrice, string memory _officialWebsite, string memory _whitepaperURL,
        string memory _officialDocumentationURL, uint256 _minimumInvestmentAllowedInUSD, uint256 _maximumInvestmentAllowedInUSD,
        uint8 _tokenOwnershipPercentageLimit) 
        ERC20(name, symbol) AccessControl() Ownable() ReentrancyGuard() {
        
        _grantRole(DEFAULT_ADMIN_ROLE, _defaultAdmin);
        _grantRole(PAUSER_ROLE, _pauser);
        _grantRole(MINTER_ROLE, _minter);
        _grantRole(BURNER_ROLE, _burner);
        _grantRole(WHITELISTER_ROLE, _whitelister);

        _mint(address(this), _tokensToIssue * (10**decimals()));

        treasuryAddress = _treasuryAddress;

        maticPriceFeedAddress = _maticPriceDataFeedMock;

        tokenTotalSupply = _tokenTotalSupply * (10**decimals());

        maximumSupplyPerIssuance = _maximumSupplyPerIssuance;

        tokenPrice = _tokenPrice;

        officialWebsite = _officialWebsite;

        whitepaperURL = _whitepaperURL;

        officialDocumentationURL = _officialDocumentationURL;

        minimumInvestmentAllowedInUSD = _minimumInvestmentAllowedInUSD;

        maximumInvestmentAllowedInUSD = _maximumInvestmentAllowedInUSD;

        tokenOwnershipPercentageLimit = _tokenOwnershipPercentageLimit;

        // Oracle on MATIC network for MATIC / USD
        dataFeedMatic = AggregatorV3Interface(maticPriceFeedAddress);
    }

    ////////////////// SMART CONTRACT FUNCTIONS //////////////////

    function addToAccreditedInvestorWhitelist(address _investorAddress) external onlyRole(WHITELISTER_ROLE){
        
        // Ensure that the investor address to add is not the zero address
        require(_investorAddress != address(0), 
        "Investor address to add to the accredited whitelist can not be the zero address");

        // Ensure that the investor address has not already been added to the accredited whitelist
        require(investorsWhitelist[_investorAddress].isAccreditedInvestor != true, 
        "That investor address has already been added to the accredited whitelist");

        // Add the investor address to the accredited whitelist
        investorsWhitelist[_investorAddress].isAccreditedInvestor = true;

        emit AccreditedInvestorAddedToWhiteList(msg.sender, _investorAddress);
    }

    function removeFromAccreditedInvestorWhitelist(address _investorAddress) external onlyRole(WHITELISTER_ROLE) {

        // Ensure that the investor address is registered on the accredited whitelist
        require(investorsWhitelist[_investorAddress].isAccreditedInvestor == true, 
        "That investor address is not registered on the accredited whitelist");

        // Remove the investor address from the accredited whitelist
        investorsWhitelist[_investorAddress].isAccreditedInvestor = false;

        emit AccreditedInvestorRemovedFromWhiteList(msg.sender, _investorAddress);
    }

    function addToNonAccreditedInvestorWhiteList(address _investorAddress) external onlyRole(WHITELISTER_ROLE){
        
        // Ensure that the investor address to add is not the zero address
        require(_investorAddress != address(0), 
        "Investor address to add to the non accredited whitelist can not be the zero address");

        // Ensure that the investor address has not already been added to the non accredited whitelist
        require(investorsWhitelist[_investorAddress].isNonAccreditedInvestor != true, 
        "That investor address has already been added to the non accredited whitelist");

        // Add the investor address to the non accredited whitelist
        investorsWhitelist[_investorAddress].isNonAccreditedInvestor = true;

        emit NonAccreditedInvestorAddedToWhiteList(msg.sender, _investorAddress);
    }

    function removeFromNonAccreditedInvestorWhitelist(address _investorAddress) external onlyRole(WHITELISTER_ROLE) {

        // Ensure that the investor address is registered on the non accredited whitelist
        require(investorsWhitelist[_investorAddress].isNonAccreditedInvestor == true, 
        "That investor address is not registered on the non accredited whitelist");

        // Remove the investor address from the non accredited whitelist
        investorsWhitelist[_investorAddress].isNonAccreditedInvestor = false;

        emit NonAccreditedInvestorRemovedFromWhiteList(msg.sender, _investorAddress);
    }

    function updateTokenOwnershipPercentageLimit(uint8 _newTokenOwnershipPercentageLimit) external onlyRole(DEFAULT_ADMIN_ROLE) {

        require(_newTokenOwnershipPercentageLimit!= 0 && _newTokenOwnershipPercentageLimit<=100, 
        "The new token ownership percentage limit must be between 1 and 100");

        tokenOwnershipPercentageLimit = _newTokenOwnershipPercentageLimit;

        emit UpdateTokenOwnershipPercentageLimit(_newTokenOwnershipPercentageLimit);
    }

    function lockInvestorAccountByInvestor() external investorIsOnWhiteList {

        // Ensure that the investor address to lock is not currently locked
        require(investorsWhitelist[msg.sender].isLockedByInvestor == false, 
        "The investor address is currently locked");

        // Lock the account as investor
        investorsWhitelist[msg.sender].isLockedByInvestor = true;

        emit LockedInvestorAccount(msg.sender);
    }

    function unlockInvestorAccountByInvestor() external investorIsOnWhiteList {

        // Ensure that the investor address to unlock is not currently unlocked
        require(investorsWhitelist[msg.sender].isLockedByInvestor == true, 
        "The investor address is currently unlocked");

        // Unlock the account as investor
        investorsWhitelist[msg.sender].isLockedByInvestor = false;

        emit LockedInvestorAccount(msg.sender);
    }

    function lockInvestorAccountByIssuer(address _investorAddress) external onlyRole(WHITELISTER_ROLE) {

        // Ensure that the investor address to lock is not the zero address
        require(_investorAddress != address(0), "Investor address to lock can not be the zero address");

        // Ensure that the investor address to lock is not currently locked by the issuer
        require(investorsWhitelist[_investorAddress].isLockedByIssuer == false, 
        "The investor address is currently locked");

        // Lock the account as issuer
        investorsWhitelist[_investorAddress].isLockedByIssuer = true;

        emit LockedInvestorAccount(_investorAddress);
    }

    function unlockInvestorAccountByIssuer(address _investorAddress) external onlyRole(WHITELISTER_ROLE) {

        // Ensure that the investor address to unlock is not the zero address
        require(_investorAddress != address(0), "Investor address to unlock can not be the zero address");

        // Ensure that the investor address to unlock is not currently unlocked
        require(investorsWhitelist[_investorAddress].isLockedByIssuer == true, 
        "The investor address is currently unlocked");

        // Unlock the account as issuer
        investorsWhitelist[_investorAddress].isLockedByIssuer = false;

        emit UnlockedInvestorAccount(_investorAddress);
    }

    /**
     * @dev Function to update the official documentation URI of the token
     * @param _newOfficialDocumentationURL The new official documentation URI
     */
    function updateOfficialDocumentationURL(string memory _newOfficialDocumentationURL) external onlyRole(DEFAULT_ADMIN_ROLE) {

        // Update the official documentation URI
        officialDocumentationURL = _newOfficialDocumentationURL;

        emit UpdatedOfficialDocumentationURL(_newOfficialDocumentationURL);
    }

    /**
     * @dev Function to update the official website of the token
     * @param _newOfficialWebsite The new official website
     */
    function updateOfficialWebsite(string memory _newOfficialWebsite) external onlyRole(DEFAULT_ADMIN_ROLE) {

        // Update the official website URL
        officialWebsite = _newOfficialWebsite;

        emit UpdatedOfficialWebsite(_newOfficialWebsite);
    }

    /**
     * @dev Function to update the whitepaper URL
     * @param _newWhitepaperURL The new whitepaper URL
     */
    function updateWhitepaperURL(string memory _newWhitepaperURL) external onlyRole(DEFAULT_ADMIN_ROLE) {

        // Update the official website URL
        whitepaperURL = _newWhitepaperURL;

        emit UpdatedWhitepaperURL(_newWhitepaperURL);
    }

    /**
     * @dev Function to issue tokens as required.
     * @param _amount The amount of new tokens to issue.
     */
    function issueTokens(uint256 _amount) public onlyRole(MINTER_ROLE) nonReentrant {
        
        // Ensure that the amount to issue in this execution is at least 1 token
        require(_amount >= 1 * 10 ** decimals(), "Amount of tokens to issue must be at least 1 token");
        
        // Ensure that the amount to issue in this execution is below the maximum supply per issuance
        require(_amount <= maximumSupplyPerIssuance * 10 ** decimals(), 
        "Amount of tokens to issue at a time must be below the maximum supply per issuance");
        
        // Validate the amount to issue doesn't go beyond the established total supply
        uint256 newTotalSupply = SafeMath.add(totalSupply(), _amount);

        require(newTotalSupply <= tokenTotalSupply, 
        "Amount of tokens to issue surpases established total token supply");

        // Mint the specified amount of tokens to the owner
        _mint(owner(), _amount);

        emit IssueTokens(msg.sender, _amount);
    }

    /**
     * @dev Function to validate the maximum invested amount of an investor and the limit if it's not an accredited investor.
     * @param _totalInvestmentInUsd The total investment in USD for the current transaction.
     * @param _investorAddress The address of the investor making the investment.
     */
    function validateMaximumInvestedAmountAndInvestorLimit(uint256 _totalInvestmentInUsd, address _investorAddress) public view {
        
        // Calculate the new total amount invested in USD by adding the current transaction's investment to the investor's total
        uint256 newTotalAmountInvestedInUSD = _totalInvestmentInUsd + investorsWhitelist[_investorAddress].totalUsdDepositedByInvestor;
    
        //If the amount to buy in USD is greater than the maximum established, then validate if the investor is accredited
        if(newTotalAmountInvestedInUSD > maximumInvestmentAllowedInUSD) {
            require(investorsWhitelist[_investorAddress].isAccreditedInvestor == true, "To get that amount of tokens its required to be an accredited investor");
        }
    }

    modifier investorIsOnWhiteList {

        // Ensure that the sender's address is on the whitelist as accredited or non accredited investor
        require( 
            (investorsWhitelist[msg.sender].isAccreditedInvestor == true ||
            investorsWhitelist[msg.sender].isNonAccreditedInvestor == true), 
            "Investor address is not in the investor whitelist");
        _;
    }

    modifier investorWalletIsNotLocked {

        // Ensure that the sender's address is not locked by the investor
        require(investorsWhitelist[msg.sender].isLockedByInvestor == false, 
            "Investor wallet is currently locked by the investor");

        // Ensure that the sender's address is not locked by the issuer
        require(investorsWhitelist[msg.sender].isLockedByIssuer == false, 
            "Investor wallet is currently locked by the issuer");

        // Ensure that the sender's address is not under a current lock period
        require(investorsWhitelist[msg.sender].walletLockUpTime < block.timestamp, 
            "Investor wallet is currently under lock time");
        _;
    }

    function tokenOwnershipUnderPercentageLimit(uint256 _totalTokensToSend, address _tokenDestination) internal view returns (bool){

        uint256 newBalance = _totalTokensToSend + balanceOf(_tokenDestination);

        uint256 amountOfTokensLimit = (tokenTotalSupply * uint256(tokenOwnershipPercentageLimit)) /100;

        if(newBalance <= amountOfTokensLimit) {
            return true;
        }

        return false;
    }

    function calculateTotalTokensToReturn(uint256 _amount, uint256 _currentCryptocurrencyPrice) public view returns (uint256 totalInvestmentInUsd, uint256 totalTokensToReturn) {
        
        //Decimals in math operation. Because the cryptocurrency price feed and the token price comes with 8 decimals
        uint256 decimalsInMathOperation = 10 ** (8 + 18);

        //Calculate the total investment in USD and divide by 10**8
        totalInvestmentInUsd = SafeMath.div((SafeMath.mul(_amount, _currentCryptocurrencyPrice)), decimalsInMathOperation);

        //Calcuale the amount of tokens to return given the current token price and multiply it by 10**8
        totalTokensToReturn = SafeMath.div((SafeMath.mul(totalInvestmentInUsd, decimalsInMathOperation)), (tokenPrice));

        //Validate that the amount to invest is equal or greater than the minimum investment established in USD
        require(totalInvestmentInUsd >= minimumInvestmentAllowedInUSD, 
        "The amount to invest must be greater than the minimum established");

        //Validate that the amount of tokens the investor will get won't make him hold more tokens than the established percentage limit
        require(tokenOwnershipUnderPercentageLimit(totalTokensToReturn, tx.origin) == true, 
        "The investment makes the investor hold more tokens than the established percentage limit");
        
        //Validate that the amount of tokens to offer to the investor is equal or less than the amount that's left in the smart contract
        require(totalTokensToReturn <= balanceOf(address(this)), 
        "The investment made returns an amount of tokens greater than the available");

        return (totalInvestmentInUsd, totalTokensToReturn);
    }


    /////////////INVESTING FUNCTIONS//////////

    /**
     * @dev Function allowing an investor on the whitelist to invest using MATIC.
     * @notice The function is payable, and MATIC is automatically transferred to this contract with the payable tag.
     * @return A boolean indicating the success of the investment and token transfer.
    */
    function investFromMatic() external investorIsOnWhiteList payable nonReentrant returns (bool){

        //Calculate total tokens to return while validating minimum investment and if there are tokens left to sell
        (uint256 totalInvestmentInUsd, uint256 totalTokensToReturn) = calculateTotalTokensToReturn(msg.value, getCurrentMaticPrice());

        //If the amount of tokens to buy is greater than the maximum established, then validate if the investor is accredited
        validateMaximumInvestedAmountAndInvestorLimit(totalInvestmentInUsd, msg.sender);

        //Transfer MATIC to the treasury address
        bool successSendingMatic = payable(treasuryAddress).send(msg.value);
        require (successSendingMatic, "There was an error on sending the MATIC investment to the treasury");

        //Transfer the token to the investor wallet
        bool successSendingTokens = this.transfer(msg.sender, totalTokensToReturn);
        require (successSendingTokens, "There was an error on sending back the tokens to the investor");

        //Update the total amount of USD that a investor has deposited
        investorsWhitelist[msg.sender].totalUsdDepositedByInvestor = totalInvestmentInUsd;

        //Update the total amount of tokens that a investor has bought
        investorsWhitelist[msg.sender].totalTokensBoughtByInvestor = totalTokensToReturn;

        emit InvestFromMatic(msg.sender, msg.value, totalInvestmentInUsd, totalTokensToReturn);

        return successSendingTokens;
    }

    /**
     * @dev Function to update the lockup time of a wallet as the investor
     * @param _newLockedUpTimeInHours The time a investor wallet is going to be locked up
     */
    function updateLockupTimeAsInvestor(uint256 _newLockedUpTimeInHours) external investorIsOnWhiteList {

        //Ensure that the lockup time is not zero
        require(_newLockedUpTimeInHours != 0, "Locking time must be greater than zero");

        //Get the hour format from solidity
        uint256 hour = 1 hours;

        //Calculate the lock up time to add in ours
        uint256 lockedUpTimeToAdd = _newLockedUpTimeInHours * hour;

        //Initialize the current locked time left in zero
        uint256 currentlockedTimeLeft = 0;

        //Verify is there is any current locked time Left
        if(investorsWhitelist[msg.sender].walletLockUpTime > block.timestamp) {
            
            //If that's the case, calculate the current locked time Left
            currentlockedTimeLeft = investorsWhitelist[msg.sender].walletLockUpTime - block.timestamp;
        }

        //Update the wallet lock up time based on the new lock time and the previous one, if there was none then that value is zero
        investorsWhitelist[msg.sender].walletLockUpTime = block.timestamp + lockedUpTimeToAdd + currentlockedTimeLeft;
    
        emit UpdatedLockupTimeAsInvestor(msg.sender, investorsWhitelist[msg.sender].walletLockUpTime);
    }

    /**
     * @dev Function to update the lockup time of a wallet as the issuer
     * @param _investorAdddress The address of the investor wallet that will be locked up 
     @param _newLockedUpTimeInHours The time a investor wallet is going to be locked up
     */
    function updateLockupTimeAsIssuer(address _investorAdddress, uint256 _newLockedUpTimeInHours) external onlyRole(DEFAULT_ADMIN_ROLE) {

        //Ensure that the lockup time is not zero
        require(_newLockedUpTimeInHours != 0, "Locking time must be greater than zero");

        //Get the hour format from solidity
        uint256 hour = 1 hours;

        //Calculate the lock up time to add in ours
        uint256 lockedUpTimeToAdd = _newLockedUpTimeInHours * hour;

        //Initialize the current locked time left in zero
        uint256 currentlockedTimeLeft = 0;

        //Verify is there is any current locked time Left
        if(investorsWhitelist[_investorAdddress].walletLockUpTime > block.timestamp) {
            
            //If that's the case, calculate the current locked time Left
            currentlockedTimeLeft = investorsWhitelist[_investorAdddress].walletLockUpTime - block.timestamp;
        }

        //Update the wallet lock up time based on the new lock time and the previous one, if there was none then that value is zero
        investorsWhitelist[_investorAdddress].walletLockUpTime = block.timestamp + lockedUpTimeToAdd + currentlockedTimeLeft;
    
        emit UpdatedLockupTimeAsIssuer(_investorAdddress, investorsWhitelist[msg.sender].walletLockUpTime);
    }

    /**
     * @dev Function to update the price in USD of each token. Using 8 decimals.
     * @param _newTokenPrice The new price of each token in USD.
     */
    function updateTokenPrice(uint256 _newTokenPrice) external onlyRole(DEFAULT_ADMIN_ROLE) {

        //Ensure that the update is not repeated for the same parameter, just as a good practice
        require(_newTokenPrice != tokenPrice, "Token price has already been modified to that value");

        // Ensure that new token price is over a minimum of USD 0.001
        require(_newTokenPrice >= 100000, 
        "Price of token must be at least USD 0.001, that is 100000 with (8 decimals)");
        
        // Ensure that new token price is under a maximum of USD 10000 
        require(_newTokenPrice <= 1000000000000, 
        "Price of token must be at maximum USD 10000, that is 1000000000000 (8 decimals)");
        
        // Update the token price
        tokenPrice = _newTokenPrice;

        emit UpdatedTokenPrice(_newTokenPrice);
    }

    /**
     * @dev Function to update the minimum investment allowed for an investor to make in USD.
     * @param _newMinimumInvestmentAllowedInUSD The new minimum amount allowed for investment in USD.
     */
    function updateMinimumInvestmentAllowedInUSD(uint256 _newMinimumInvestmentAllowedInUSD) external onlyRole(DEFAULT_ADMIN_ROLE) {
        
        // Ensure the new minimum investment is greater than zero
        require(_newMinimumInvestmentAllowedInUSD > 0, 
        "New minimun amount to invest, must be greater than zero");
        
        //Ensure that the update transaction is not repeated for the same parameter, just as a good practice
        require(_newMinimumInvestmentAllowedInUSD != minimumInvestmentAllowedInUSD, 
        "Minimum investment allowed in USD has already been modified to that value");

        // Ensure the new minimum investment is less or equal than the maximum
        require(_newMinimumInvestmentAllowedInUSD <= maximumInvestmentAllowedInUSD, 
        "New minimun amount to invest, must be less than the maximum investment allowed");

        // Update the minimum investment allowed in USD
        minimumInvestmentAllowedInUSD = _newMinimumInvestmentAllowedInUSD;

        emit UpdatedMinimumInvestmentAllowedInUSD(_newMinimumInvestmentAllowedInUSD);
    }

    /**
     * @dev Function to update the maximum investment allowed for an investor to make in USD, without being a accredited investor.
     * @param _newMaximumInvestmentAllowedInUSD The new maximum amount allowed for investment in USD.
     */
    function updateMaximumInvestmentAllowedInUSD(uint256 _newMaximumInvestmentAllowedInUSD) external onlyRole(DEFAULT_ADMIN_ROLE)  {

        // Ensure the new maximum investment is greater than zero
        require(_newMaximumInvestmentAllowedInUSD > 0, 
        "New maximum amount to invest, must be greater than zero");

        //Ensure that the update transaction is not repeated for the same parameter, just as a good practice
        require(_newMaximumInvestmentAllowedInUSD != maximumInvestmentAllowedInUSD, 
        "New maximum amount to invest, has already been modified to that value");

        // Ensure the new maximum investment is greater or equal than the minimum
        require(_newMaximumInvestmentAllowedInUSD >= minimumInvestmentAllowedInUSD, 
        "New maximum amount to invest, must be greater than the minimum investment allowed");

        // Update the maximum investment allowed in USD
        maximumInvestmentAllowedInUSD = _newMaximumInvestmentAllowedInUSD;

        emit UpdatedMaximumInvestmentAllowedInUSD(_newMaximumInvestmentAllowedInUSD);
    }


    /**
     * @dev Function to update the address of the treasury.
     * @param _newTreasuryAddress The new address of the treasury.
     */
    function updateTreasuryAddress(address _newTreasuryAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {

        // Ensure the new treasury address is not the zero address
        require(_newTreasuryAddress != address(0), "The treasury address can not be the zero address");

        //Ensure that the update transaction is not repeated for the same parameter, just as a good practice
        require(_newTreasuryAddress != treasuryAddress, 
        "Treasury address has already been modified to that value");

        // Update the treasury address
        treasuryAddress = _newTreasuryAddress;

        emit UpdatedTreasuryAddress(_newTreasuryAddress);
    }

    /**
     * @dev Function to update the address of the oracle that provides the MATIC price feed.
     * @param _newMaticPriceFeedAddress The new address of the MATIC price feed oracle.
     */
    function updateMaticPriceFeedAddress(address _newMaticPriceFeedAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        
        // Ensure the new MATIC price feed address is not the zero address
        require(_newMaticPriceFeedAddress != address(0), 
        "The price data feed address can not be the zero address");
        
        //Ensure that the update transaction is not repeated for the same parameter, just as a good practice
        require(_newMaticPriceFeedAddress != maticPriceFeedAddress, 
        "MATIC price feed address has already been modified to that value");
        
        //Temporary data feed to perform the validation of the data feed descriptions
        AggregatorV3Interface tempDataFeedMatic = AggregatorV3Interface(_newMaticPriceFeedAddress);

        //Validate if the new address is actually a price feed address. Attempt to call the description function 
        try tempDataFeedMatic.description() returns (string memory descriptionValue) {

            //Get the hash value of the MATIC/USD string
            bytes32 hashOfExpectedMaticFeedDescription = keccak256(abi.encodePacked('MATIC / USD'));

            //Get the hash value of the description of the price data feed
            bytes32 hashOfCurrentMaticFeedDescription = keccak256(abi.encodePacked(descriptionValue));
            
            //Validate the data feed is actually the address of a MATIC/USD oracle by comparing the hashes of the expected description and temporal description
            require(hashOfExpectedMaticFeedDescription == hashOfCurrentMaticFeedDescription, 
            "The new address does not seem to belong to a MATIC price data feed");
        
        } catch  {
            //In case there is an error obtaining the description of the data feed, revert the transaction
            revert("The new address does not seem to belong to a MATIC price data feed");
        }

        // Update the MATIC price feed address
        maticPriceFeedAddress = _newMaticPriceFeedAddress;

        // Update the MATIC price feed interface
        dataFeedMatic = AggregatorV3Interface(maticPriceFeedAddress);

        emit UpdatedMaticPriceFeedAddress(_newMaticPriceFeedAddress);
    }

    function burnTokens(uint256 _amount) public virtual onlyRole(BURNER_ROLE) {
        _burn(_msgSender(), _amount);

        emit TokensBurned(_amount);
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /////////////Overwrites to be ERC 1400 compliant/////////////

    function transferFrom(address from, address to, uint256 amount) public virtual override investorWalletIsNotLocked returns (bool) {

        //Validate the destination address in on the whitelist before doing the transfer
        require( 
            (investorsWhitelist[to].isAccreditedInvestor == true ||
            investorsWhitelist[to].isNonAccreditedInvestor == true), 
            "Destination address is not in the investor whitelist");

        //Validate that the amount of tokens the destination will get won't make him hold more tokens than the established percentage limit
        require(tokenOwnershipUnderPercentageLimit(amount, to) == true, 
        "The investment makes the destination hold more tokens than the established percentage limit");

        //If the amount of tokens to transfer is greater than the maximum established, then validate if the investor is accredited
        uint256 totalTokenValueInUsd = amount * tokenPrice;
        validateMaximumInvestedAmountAndInvestorLimit(totalTokenValueInUsd, to);

        //Original transfer function code
        address spender = _msgSender();
        _spendAllowance(from, spender, amount);
        _transfer(from, to, amount);
        
        return true;
    }

    function transfer(address to, uint256 amount) public virtual override investorWalletIsNotLocked returns (bool) {
        
        //Validate the destination address in on the whitelist before doing the transfer
        require( 
            (investorsWhitelist[to].isAccreditedInvestor == true ||
            investorsWhitelist[to].isNonAccreditedInvestor == true), 
            "Destination address is not in the investor whitelist");

        //Validate that the amount of tokens the destination will get won't make him hold more tokens than the established percentage limit
        require(tokenOwnershipUnderPercentageLimit(amount, to) == true, 
        "The investment makes the destination hold more tokens than the established percentage limit");

        //If the amount of tokens to transfer is greater than the maximum established, then validate if the investor is accredited
        uint256 totalTokenValueInUsd = amount * tokenPrice;
        validateMaximumInvestedAmountAndInvestorLimit(totalTokenValueInUsd, to);

        //Original transfer function code
        address owner = _msgSender();
        _transfer(owner, to, amount);

        return true;
    }

    function approve(address spender, uint256 amount) public virtual override investorWalletIsNotLocked returns (bool) {

        //Validate the destination address in on the whitelist before doing the approval
        require( 
            (investorsWhitelist[spender].isAccreditedInvestor == true ||
            investorsWhitelist[spender].isNonAccreditedInvestor == true), 
            "Destination address is not in the investor whitelist");

        //Validate that the amount of tokens the destination will get won't make him hold more tokens than the established percentage limit
        require(tokenOwnershipUnderPercentageLimit(amount, spender) == true, 
        "The investment makes the destination hold more tokens than the established percentage limit");

        //Original transfer function code
        address owner = _msgSender();
        _approve(owner, spender, amount);

        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual override investorWalletIsNotLocked returns (bool) {

        //Validate the destination address in on the whitelist before doing the increase of allowance
        require( 
            (investorsWhitelist[spender].isAccreditedInvestor == true ||
            investorsWhitelist[spender].isNonAccreditedInvestor == true), 
            "Destination address is not in the investor whitelist");

        //Validate that the amount of tokens the destination will get won't make him hold more tokens than the established percentage limit
        require(tokenOwnershipUnderPercentageLimit(addedValue, spender) == true, 
        "The investment makes the destination hold more tokens than the established percentage limit");

        address owner = _msgSender();
        _approve(owner, spender, allowance(owner, spender) + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual override investorWalletIsNotLocked returns (bool) {

        //Validate the destination address in on the whitelist before doing the decrease of allowance
        require( 
            (investorsWhitelist[spender].isAccreditedInvestor == true ||
            investorsWhitelist[spender].isNonAccreditedInvestor == true), 
            "Destination address is not in the investor whitelist");

        address owner = _msgSender();
        uint256 currentAllowance = allowance(owner, spender);
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");
        unchecked {
            _approve(owner, spender, currentAllowance - subtractedValue);
        }

        return true;
    }

    /////////////ORACLE PRICE FEED FUNCTIONS//////////

    /**
     * @dev Function to get the current price of MATIC in USD.
     * @return The current price of MATIC in USD with 8 decimals.
     */
    function getCurrentMaticPrice() public view returns (uint256) {

        try dataFeedMatic.latestRoundData() returns (
            uint80 /*roundID*/, 
            int256 answer,
            uint /*startedAt*/,
            uint /*timeStamp*/,
            uint80 /*answeredInRound*/
        ) 
        {
            return uint256(answer);

        } catch  {
            revert("There was an error obtaining the MATIC price from the oracle");
        }
        
    }

    // The following function is a override required by Solidity to inherit from ERC20 and ERC20Pausable
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override(ERC20, ERC20Pausable) {
        ERC20Pausable._beforeTokenTransfer(from, to, amount);
    }

}
