// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../src/validator/ECDSAValidator.sol";

contract DeployECDSAValidator is Script {
    function run() external {
        // Load private key from environment variable
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        // Start broadcasting transactions
        vm.startBroadcast(deployerPrivateKey);

        // Deploy the ECDSAValidator contract
        ECDSAValidator validator = new ECDSAValidator();

        console.log("ECDSAValidator deployed at:", address(validator));

        // Stop broadcasting
        vm.stopBroadcast();
    }
}