import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
const { ethers } = require("hardhat");

/**
 * Deploys a contract named "ERC1404Upgraded" using the deployer account and
 * constructor arguments set to the deployer address
 *
 * @param hre HardhatRuntimeEnvironment object.
 */
const deployERC1404Upgraded: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  /*
    On localhost, the deployer account is the one that comes with Hardhat, which is already funded.

    When deploying to live networks (e.g `yarn deploy --network goerli`), the deployer account
    should have sufficient balance to pay for the gas fees for contract creation.

    You can generate a random account with `yarn generate` which will fill DEPLOYER_PRIVATE_KEY
    with a random private key in the .env file (then used on hardhat.config.ts)
    You can run the `yarn account` command to check your balance in every network.
  */
  const { deployer } = await hre.getNamedAccounts();
  const { deploy } = hre.deployments;

  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
  await sleep(1000);

  const newOwnerAddress = "0x350441F8a82680a785FFA9d3EfEa60BB4cA417f8";

  //Deploy the MATIC price data feed mock
  const MaticPriceDataFeedMock = await ethers.getContractFactory('MaticPriceDataFeedMock');

  //Deploy smart contract with established parameters
  const maticPriceDataFeedMock = await MaticPriceDataFeedMock.deploy();

  const addressMaticPriceDataFeedMock = await maticPriceDataFeedMock.target;

  console.log("\nMatic Price Data Feed Mock: ", addressMaticPriceDataFeedMock );

  await deploy("ERC1404Upgraded", {
    from: deployer,
    // Contract constructor arguments
    args: [/*name:string*/"SecurityToken", 
    /*symbol:string*/"STO",
    /*address:defaultAdmin*/newOwnerAddress, 
    /*address:pauser*/newOwnerAddress,
    /*address:minter*/newOwnerAddress,
    /*address:burner*/newOwnerAddress,
    /*address:whitelister*/newOwnerAddress,
    /*address:maticPriceDataFeedMock*/addressMaticPriceDataFeedMock,
    /*uint256:tokenTotalSupply*/100000000,
    /*uint256:maximumSupplyPerIssuance*/10000000],
    log: true,
    // autoMine: can be passed to the deploy function to make the deployment process faster on local networks by
    // automatically mining the contract deployment transaction. There is no effect on live networks.
    autoMine: true,
  });

  // Get the deployed contract
  const erc1404Upgraded = await hre.ethers.getContract("ERC1404Upgraded", deployer);

  await erc1404Upgraded.transferOwnership(newOwnerAddress);

  console.log("\nDeployer address: ",  deployer);
  console.log("\nSmart contract name: ", await erc1404Upgraded.name());
};

export default deployERC1404Upgraded;

// Tags are useful if you have multiple deploy files and only want to run one of them.
// e.g. yarn deploy --tags YourContract
deployERC1404Upgraded.tags = ["ERC1404Upgraded", "MaticPriceDataFeedMock"];
