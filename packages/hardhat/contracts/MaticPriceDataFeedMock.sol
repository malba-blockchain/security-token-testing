// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MaticPriceDataFeedMock {

  uint80 roundID;
  int256 answer;
  uint startedAt;
  uint timeStamp;
  uint80 answeredInRound;
    
  constructor( ) {
      roundID = 36893488147419307389;
      answer = 90387255;
      startedAt = 1700085165;
      timeStamp = 1700085165;
      answeredInRound = 36893488147419307389;
  }

  function latestRoundData() public view
    returns (
      uint80 _roundId,
      int256 _answer,
      uint256 _startedAt,
      uint _updatedAt,
      uint80 _answeredInRound
    )
  {
    return (roundID, answer, startedAt, timeStamp, answeredInRound);
  }

  function description() external pure returns (string memory) {
    return 'MATIC / USD';
  }
 
}