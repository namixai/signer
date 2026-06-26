// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {UsenamiAttestationRegistry} from "../src/UsenamiAttestationRegistry.sol";

/// Deploy + (optionally) register the current production PCR0 in one tx.
///
/// Usage:
///   PRIVATE_KEY=0x... \
///   forge script script/Deploy.s.sol --rpc-url base --broadcast --verify
contract Deploy is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        // 48-byte production PCR0
        // Reference: STATUS.md `**Deterministic PCR0:**`
        bytes memory pcr0 = vm.envOr(
            "PCR0_HEX",
            bytes(
                hex"7c9e8b26a8f6af6e6109faeff1ed4313f332735f6b7aacce7795461de656c84a70f3761d806738121accaf171f329375"
            )
        );
        require(pcr0.length == 48, "PCR0_HEX must be 48 bytes");

        vm.startBroadcast(deployerKey);

        UsenamiAttestationRegistry registry = new UsenamiAttestationRegistry();
        console2.log("Registry deployed at:", address(registry));

        // Register the live production PCR0.
        registry.registerPCR0(
            pcr0,
            bytes32(0), // buildHash TBD: sha256(Cargo.lock + source tarball) — add when reproducible-build manifest stabilises
            "Phase 1 Stage 2: 5 exchanges (KuCoin/Binance/Bybit/OKX HMAC + Hyperliquid_main EIP-712) post serde_json preserve_order fix"
        );
        console2.log("Registered PCR0 for deployer:", vm.addr(deployerKey));

        vm.stopBroadcast();
    }
}
