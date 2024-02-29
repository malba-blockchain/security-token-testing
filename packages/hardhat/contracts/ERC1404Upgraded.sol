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

    // Stores the official documentation URL for the security token.
    string public officialDocumentationURL;

    // Stores the official website URL for the token.
    string public officialWebsite;

    // Stores the whitepaper URL for the token.
    string public whitepaperURL;

    // Stores the token price in USD with 8 decimals
    uint256 public tokenPrice;

    // Stores the minimum investment amount allowed in USD with no decimals
    uint256 public minimumInvestmentAllowedInUSD;

    // Stores the maximum investment amount allowed in USD with no decimals
    uint256 public maximumInvestmentAllowedInUSD;

    // Stores the total supply of tokens that can be minted, with the default decinals of totalSupply
    uint256 public tokenTotalSupply;

    // Stores the maximum number of tokens that can be minted in a single issuance event with no decimals
    uint256 public maximumSupplyPerIssuance;

    // Stores the maximum percentage of tokens a single address can hold with no decimals
    uint8 public tokenOwnershipPercentageLimit;

    // Stores the address of the wallet that holds the project's funds.
    address public treasuryAddress;

    // A mapping that associates an investor's address (address) with their `InvestorData` struct information. 
    mapping(address => InvestorData) public investorsWhitelist;

    struct InvestorData {
        //Flag indicating whether the investor is accredited (true) or not (false).
        bool isAccreditedInvestor;
        // Flag indicating whether the investor is non-accredited (true) or not (false).
        bool isNonAccreditedInvestor;
        // Total number of tokens purchased by the investor.
        uint256 totalTokensBoughtByInvestor;
        // Total amount of USD deposited by the investor at the time of each buy
        uint256 totalUsdDepositedByInvestor;
        // Timestamp specifying when the investor's tokens are unlocked. Used to enforce lockup period for investors.
        uint256 walletLockUpTime;
        // Flag indicating whether the investor has voluntarily locked their tokens (true) or not (false). Can be used for additional investment strategies.
        bool isLockedByInvestor;
        // Flag indicating whether the issuer has locked the investor's tokens (true) or not (false). Used for compliance or security reasons.
        bool isLockedByIssuer;
    }

 
    // Address of MATIC token price feed (Oracle) in the blockchain.
    address public maticPriceFeedAddress;

    // Aggregator that allows asking for the price of crypto tokens.
    AggregatorV3Interface internal dataFeedMatic;
    

    ////////////////// SMART CONTRACT EVENTS //////////////////

    event AccreditedInvestorAddedToWhiteList(address sender, address _investorAddress);
    event AccreditedInvestorRemovedFromWhiteList(address sender, address _investorAddress);
    event InvestFromMatic(address sender, uint256 maticAmount, uint256 totalInvestmentInUSD, uint256 tokensAmount);
    event IssueTokens(address sender, uint256 amount);
    event LockedInvestorAccount(address _investorAccount);
    event NonAccreditedInvestorAddedToWhiteList(address sender, address _investorAddress);
    event NonAccreditedInvestorRemovedFromWhiteList(address sender, address _investorAddress);
    event TokensBurned(uint256 _amount);
    event UnlockedInvestorAccount(address _investorAccount);
    event UpdatedLockupTimeAsInvestor(address sender, uint256 walletLockUpTime);
    event UpdatedLockupTimeAsIssuer(address sender, uint256 walletLockUpTime);
    event UpdatedMaticPriceFeedAddress(address _newMaticPriceFeedAddress);
    event UpdatedMaximumInvestmentAllowedInUSD(uint256 _newMaximumInvestmentAllowedInUSD);
    event UpdatedMinimumInvestmentAllowedInUSD(uint256 _newMinimumInvestmentAllowedInUSD);
    event UpdatedOfficialDocumentationURL(string _newOfficialDocumentationURL);
    event UpdatedOfficialWebsite(string _newOfficialWebsite);
    event UpdatedTokenOwnershipPercentageLimit(uint256 _newTokenOwnershipPercentageLimit);
    event UpdatedTokenPrice(uint256 _newTokenPrice);
    event UpdatedTreasuryAddress(address _newTreasuryAddress);
    event UpdatedWhitepaperURL(string _newWhitepaperURL);

    ////////////////// SMART CONTRACT CONSTRUCTOR //////////////////

    constructor(string memory name, string memory symbol, uint256 _tokensToIssue, address _defaultAdmin, address _pauser, 
        address _minter, address _burner, address _whitelister, address _treasuryAddress, address _maticPriceDataFeed, uint256 _tokenTotalSupply, 
        uint256 _maximumSupplyPerIssuance, uint256 _tokenPrice, string memory _officialWebsite, string memory _whitepaperURL,
        string memory _officialDocumentationURL, uint256 _minimumInvestmentAllowedInUSD, uint256 _maximumInvestmentAllowedInUSD,
        uint8 _tokenOwnershipPercentageLimit) 
        ERC20(name, symbol) AccessControl() Ownable() ReentrancyGuard() {
        
        _grantRole(DEFAULT_ADMIN_ROLE, _defaultAdmin);
        _grantRole(PAUSER_ROLE, _pauser);
        _grantRole(MINTER_ROLE, _minter);
        _grantRole(BURNER_ROLE, _burner);
        _grantRole(WHITELISTER_ROLE, _whitelister);

        //Minting initial tokens for the contract itself
        _mint(address(this), _tokensToIssue * (10**decimals()));

        // Assigns the address that will hold project funds.
        treasuryAddress = _treasuryAddress;

        // Sets the address providing MATIC price data
        maticPriceFeedAddress = _maticPriceDataFeed;

        //Updates total token supply with provided value in base units.
        tokenTotalSupply = _tokenTotalSupply * (10**decimals());

        // Sets the maximum tokens allowed in a single issuance.
        maximumSupplyPerIssuance = _maximumSupplyPerIssuance;

        // Sets the price of a single token in USD
        tokenPrice = _tokenPrice;

        // Sets the official website URL for the token.
        officialWebsite = _officialWebsite;

        // Sets the whitepaper URL for the token.
        whitepaperURL = _whitepaperURL;

        // Sets the official documentation URL for the token.
        officialDocumentationURL = _officialDocumentationURL;

        // Sets the minimum investment amount in USD cents.
        minimumInvestmentAllowedInUSD = _minimumInvestmentAllowedInUSD;

        // Sets the maximum investment amount in USD cents.
        maximumInvestmentAllowedInUSD = _maximumInvestmentAllowedInUSD;

        // Sets the maximum percentage of tokens a single address can hold.
        tokenOwnershipPercentageLimit = _tokenOwnershipPercentageLimit;

        // Oracle on MATIC network for MATIC / USD
        dataFeedMatic = AggregatorV3Interface(maticPriceFeedAddress);
    }

    ////////////////// SMART CONTRACT FUNCTIONS //////////////////


    /**
    * @dev Adds an investor address to the accredited whitelist. Only addresses with the WHITELISTER_ROLE can call this function.
    * @param _investorAddress The address of the investor to be added to the accredited whitelist.
    */
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

    /**
    * @dev Removes an investor address from the accredited whitelist. Only addresses with the WHITELISTER_ROLE can call this function.
    * @param _investorAddress The address of the investor to be removed from the accredited whitelist.
    */
    function removeFromAccreditedInvestorWhitelist(address _investorAddress) external onlyRole(WHITELISTER_ROLE) {

        // Ensure that the investor address is registered on the accredited whitelist
        require(investorsWhitelist[_investorAddress].isAccreditedInvestor == true, 
        "That investor address is not registered on the accredited whitelist");

        // Remove the investor address from the accredited whitelist
        investorsWhitelist[_investorAddress].isAccreditedInvestor = false;

        emit AccreditedInvestorRemovedFromWhiteList(msg.sender, _investorAddress);
    }

    /**
    * @dev Adds an investor address to the non-accredited whitelist. Only addresses with the WHITELISTER_ROLE can call this function.
    * @param _investorAddress The address of the investor to be added to the non-accredited whitelist.
    */
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

    /**
    * @dev Removes an investor address from the non-accredited whitelist. Only addresses with the WHITELISTER_ROLE can call this function.
    * @param _investorAddress The address of the investor to be removed from the non-accredited whitelist.
    */
    function removeFromNonAccreditedInvestorWhitelist(address _investorAddress) external onlyRole(WHITELISTER_ROLE) {

        // Ensure that the investor address is registered on the non accredited whitelist
        require(investorsWhitelist[_investorAddress].isNonAccreditedInvestor == true, 
        "That investor address is not registered on the non accredited whitelist");

        // Remove the investor address from the non accredited whitelist
        investorsWhitelist[_investorAddress].isNonAccreditedInvestor = false;

        emit NonAccreditedInvestorRemovedFromWhiteList(msg.sender, _investorAddress);
    }

    /**
    * @dev Updates the token ownership percentage limit. Only addresses with the DEFAULT_ADMIN_ROLE can call this function.
    * @param _newTokenOwnershipPercentageLimit The new percentage limit to set (between 1 and 100).
    */
    function updateTokenOwnershipPercentageLimit(uint8 _newTokenOwnershipPercentageLimit) external onlyRole(DEFAULT_ADMIN_ROLE) {

        // Ensure that the new ownershop percentage limit is not zero and is less or equal than 100
        require(_newTokenOwnershipPercentageLimit!= 0 && _newTokenOwnershipPercentageLimit<=100, 
        "The new token ownership percentage limit must be between 1 and 100");

        // Update the value of the token ownership percentage limit
        tokenOwnershipPercentageLimit = _newTokenOwnershipPercentageLimit;

        emit UpdatedTokenOwnershipPercentageLimit(_newTokenOwnershipPercentageLimit);
    }

    /**
    * @dev Locks the investor's own account. Only whitelisted investors can call this function.
    * @role investorIsOnWhiteList Only whitelisted investors can call this function.
    */
    function lockInvestorAccountByInvestor() external investorIsOnWhiteList {

        // Ensure that the investor address to lock is not currently locked
        require(investorsWhitelist[msg.sender].isLockedByInvestor == false, 
        "The investor address is currently locked");

        // Lock the account as investor
        investorsWhitelist[msg.sender].isLockedByInvestor = true;

        emit LockedInvestorAccount(msg.sender);
    }

    /**
    * @dev Unlocks the investor's own account, which was previously locked by the investor themself.
    * @role investorIsOnWhiteList Only whitelisted investors can call this function.
    */
    function unlockInvestorAccountByInvestor() external investorIsOnWhiteList {

        // Ensure that the investor address to unlock is not currently unlocked
        require(investorsWhitelist[msg.sender].isLockedByInvestor == true, 
        "The investor address is currently unlocked");

        // Unlock the account as investor
        investorsWhitelist[msg.sender].isLockedByInvestor = false;

        emit LockedInvestorAccount(msg.sender);
    }

    /**
    * @dev Locks an investor account by the issuer.
    * @param _investorAddress The address of the investor account to lock.
    * @role WHITELISTER_ROLE Only addresses with the WHITELISTER_ROLE can call this function.
    */
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

    /**
    * @dev Unlocks an investor account that was previously locked by the issuer.
    * @param _investorAddress The address of the investor account to unlock.
    * @role WHITELISTER_ROLE Only addresses with the WHITELISTER_ROLE can call this function.
    */
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

    /**
    * @dev Restricts function execution to whitelisted investors (accredited or non-accredited).
    */
    modifier investorIsOnWhiteList {

        // Ensure that the sender's address is on the whitelist as accredited or non accredited investor
        require( 
            (investorsWhitelist[msg.sender].isAccreditedInvestor == true ||
            investorsWhitelist[msg.sender].isNonAccreditedInvestor == true), 
            "Investor address is not in the investor whitelist");
        _;
    }    
    
    /**
    * @dev Ensures the message sender's (investor's) wallet is not locked before proceeding with a function call.
    */
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

    /**
     * @dev Checks if transferring a certain amount of tokens to a specific address would exceed the allowed ownership percentage limit.
     * @param _totalInvestmentInUsd The total amount of tokens to be sent.
     * @param _investorAddress The address of the recipient.
     */
    function tokenOwnershipUnderPercentageLimit(uint256 _totalTokensToSend, address _tokenDestination) internal view returns (bool){

        //Calculate the new balance based on the tokens to send plus the current balance of tokens of that address
        uint256 newBalance = _totalTokensToSend + balanceOf(_tokenDestination);

        //Calculate the specific limit amount of tokens that an address can hold
        uint256 amountOfTokensLimit = (tokenTotalSupply * uint256(tokenOwnershipPercentageLimit)) /100;

        //Validate if the new balance is under that limit, return true
        if(newBalance <= amountOfTokensLimit) {
            return true;
        }

        //If the new balance is not under that limit, return false
        return false;
    }

    /**
    * @dev Calculates the total tokens to return based on the investment amount and current cryptocurrency price, enforcing various restrictions.
    * @param _amount The amount of cryptocurrency to invest.
    * @param _currentCryptocurrencyPrice The current price of the cryptocurrency in USD cents (with 8 decimals).
    * @return totalInvestmentInUsd The total investment in USD cents (with 18 decimals).
    * @return totalTokensToReturn The total number of tokens to be returned to the investor.
   */
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
     * @param _newLockedUpTimeInHours The time a investor wallet is going to be locked up
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

    /**
    * @dev Burns a specified amount of tokens from the message sender's address. Only accounts with the BURNER_ROLE can call this function.
    * @param _amount The amount of tokens to be burned.
     */
    function burnTokens(uint256 _amount) public virtual onlyRole(BURNER_ROLE) {
        _burn(_msgSender(), _amount);

        emit TokensBurned(_amount);
    }

    /**
    * @dev Pauses the contract's functionality. Only accounts with the PAUSER_ROLE can call this function.
     */
    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
    *@dev Unpauses the contract's functionality. Only accounts with the PAUSER_ROLE can call this function.
    */
    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /////////////Overwrites to be ERC 1400 compliant/////////////

    /**
    * @dev Transfers tokens on behalf of another address (`from`) to a recipient (`to`), enforcing various restrictions.
    * @param from The address of the token sender.
    * @param to The address of the token recipient.
    * @param amount The amount of tokens to be transferred.
    * @return true if the transfer was successful, false otherwise.
    */
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

    /**
    * @dev Transfers tokens from the message sender (`owner`) to a recipient (`to`), enforcing various restrictions.
    * @param to The address of the token recipient.
    * @param amount The amount of tokens to be transferred.
    * @return true if the transfer was successful, false otherwise.
    */
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

    /**
    * @dev Approves an address (`spender`) to spend a specified amount of tokens on behalf of the message sender (`owner`), enforcing whitelist and ownership limit restrictions.
    * @param spender The address to be approved to spend tokens.
    * @param amount The amount of tokens the spender will be allowed to spend.
    * @return true if the approval was successful, false otherwise.
    */
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

    /**
    * @dev Increases the allowance of an address (`spender`) to spend tokens on behalf of the message sender (`owner`), enforcing whitelist and ownership limit restrictions.
    * @param spender The address to be approved for increased spending.
    * @param addedValue The additional amount of tokens the spender is allowed to spend.
    * @return true if the allowance increase was successful, false otherwise.
    */
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

    /**
    * @dev Decreases the allowance of an address (`spender`) to spend tokens on behalf of the message sender (`owner`), enforcing whitelist restrictions.
    * @param spender The address whose spending allowance is being decreased.
    * @param subtractedValue The amount of tokens to be removed from the spender's allowance.
    * @return true if the allowance decrease was successful, false otherwise.
    */
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