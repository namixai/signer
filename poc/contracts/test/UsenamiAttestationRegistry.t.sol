// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {UsenamiAttestationRegistry} from "../src/UsenamiAttestationRegistry.sol";

contract UsenamiAttestationRegistryTest is Test {
    UsenamiAttestationRegistry registry;
    address alice = address(0xA11CE);
    address bob   = address(0xB0B);

    // 48-byte test PCR0 values
    bytes constant PCR_A = hex"111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
    bytes constant PCR_B = hex"222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";
    bytes constant PCR_C = hex"333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333";

    // Real production PCR0 для reference
    bytes constant PCR_PROD = hex"9f6f512f81c3b533333fb53098e9df45aaa0fb31d4536a4b39ab690e056839814ab6a2595859885cc6327c544cf059ab";

    function setUp() public {
        registry = new UsenamiAttestationRegistry();
    }

    function test_RegisterPCR0() public {
        vm.prank(alice);
        registry.registerPCR0(PCR_A, bytes32(0), "build v1");

        (bool active, address owner) = registry.isPCR0Active(PCR_A);
        assertTrue(active);
        assertEq(owner, alice);

        UsenamiAttestationRegistry.PCR0Record memory r = registry.getActivePCR0(alice);
        assertEq(r.pcr0, PCR_A);
        assertEq(r.deprecatedAt, 0);
        assertEq(r.description, "build v1");
    }

    function test_RegisterProductionPCR0() public {
        vm.prank(alice);
        registry.registerPCR0(PCR_PROD, bytes32(uint256(0xc0de)), "Phase 1 Stage 2: 5 exchanges");
        (bool active, ) = registry.isPCR0Active(PCR_PROD);
        assertTrue(active);
    }

    function test_RegisterAutoDeprecatesPrevious() public {
        vm.startPrank(alice);
        registry.registerPCR0(PCR_A, bytes32(0), "v1");
        registry.registerPCR0(PCR_B, bytes32(0), "v2");
        vm.stopPrank();

        (bool aActive, ) = registry.isPCR0Active(PCR_A);
        (bool bActive, address bOwner) = registry.isPCR0Active(PCR_B);
        assertFalse(aActive, "old PCR0 should be auto-deprecated");
        assertTrue(bActive);
        assertEq(bOwner, alice);

        UsenamiAttestationRegistry.PCR0Record[] memory history = registry.getOwnerHistory(alice);
        assertEq(history.length, 2);
        assertGt(history[0].deprecatedAt, 0);
        assertEq(history[1].deprecatedAt, 0);
    }

    function test_DeprecatePCR0() public {
        vm.prank(alice);
        registry.registerPCR0(PCR_A, bytes32(0), "v1");

        vm.prank(alice);
        registry.deprecatePCR0(PCR_A);

        (bool active, ) = registry.isPCR0Active(PCR_A);
        assertFalse(active);
    }

    function test_RevertWhen_NonOwnerDeprecates() public {
        vm.prank(alice);
        registry.registerPCR0(PCR_A, bytes32(0), "v1");

        vm.prank(bob);
        vm.expectRevert(UsenamiAttestationRegistry.NotOwnerOfPCR0.selector);
        registry.deprecatePCR0(PCR_A);
    }

    function test_RevertWhen_DeprecateNonExistent() public {
        vm.prank(alice);
        vm.expectRevert(UsenamiAttestationRegistry.PCR0NotFound.selector);
        registry.deprecatePCR0(PCR_C);
    }

    function test_RevertWhen_RegisterDuplicateActive() public {
        vm.prank(alice);
        registry.registerPCR0(PCR_A, bytes32(0), "v1");

        vm.prank(bob);
        vm.expectRevert(UsenamiAttestationRegistry.PCR0AlreadyRegistered.selector);
        registry.registerPCR0(PCR_A, bytes32(0), "v1");
    }

    function test_RevertWhen_WrongLength() public {
        bytes memory tooShort = hex"1111";
        vm.prank(alice);
        vm.expectRevert(UsenamiAttestationRegistry.InvalidPCR0Length.selector);
        registry.registerPCR0(tooShort, bytes32(0), "v1");
    }

    function test_MultipleOwners() public {
        vm.prank(alice);
        registry.registerPCR0(PCR_A, bytes32(0), "alice v1");

        vm.prank(bob);
        registry.registerPCR0(PCR_B, bytes32(0), "bob v1");

        (, address ownerA) = registry.isPCR0Active(PCR_A);
        (, address ownerB) = registry.isPCR0Active(PCR_B);
        assertEq(ownerA, alice);
        assertEq(ownerB, bob);
    }

    function test_GetActivePCR0_RevertsIfNone() public {
        vm.expectRevert(UsenamiAttestationRegistry.PCR0NotFound.selector);
        registry.getActivePCR0(alice);
    }

    function test_HistoryOrderPreserved() public {
        vm.startPrank(alice);
        registry.registerPCR0(PCR_A, bytes32(uint256(1)), "v1");
        vm.warp(block.timestamp + 100);
        registry.registerPCR0(PCR_B, bytes32(uint256(2)), "v2");
        vm.warp(block.timestamp + 100);
        registry.registerPCR0(PCR_C, bytes32(uint256(3)), "v3");
        vm.stopPrank();

        UsenamiAttestationRegistry.PCR0Record[] memory history = registry.getOwnerHistory(alice);
        assertEq(history.length, 3);
        assertEq(history[0].pcr0, PCR_A);
        assertEq(history[1].pcr0, PCR_B);
        assertEq(history[2].pcr0, PCR_C);
        assertGt(history[0].deprecatedAt, 0);
        assertGt(history[1].deprecatedAt, 0);
        assertEq(history[2].deprecatedAt, 0);
    }

    function testFuzz_RegisterAndQuery(bytes calldata seed, address owner) public {
        vm.assume(owner != address(0));

        // Generate a 48-byte unique PCR0 from seed
        bytes memory pcr0 = abi.encodePacked(
            keccak256(seed),                                       // 32 bytes
            bytes16(uint128(uint256(keccak256(abi.encode(seed, "_")))))  // 16 bytes
        );

        // Need to ensure no collision (very unlikely with random seed)
        (bool existing, ) = registry.isPCR0Active(pcr0);
        vm.assume(!existing);

        vm.prank(owner);
        registry.registerPCR0(pcr0, bytes32(uint256(uint160(owner))), "fuzz");

        (bool active, address ret) = registry.isPCR0Active(pcr0);
        assertTrue(active);
        assertEq(ret, owner);
    }

    function test_GasSnapshot_Register() public {
        vm.prank(alice);
        registry.registerPCR0(PCR_A, bytes32(uint256(42)), "production v1");
    }
}
