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
        // Wire up the invariant handler. Foundry only fuzzes contracts
        // registered via targetContract(); allocating one per test setUp()
        // adds ~30k gas but keeps the invariant test self-contained.
        handler = new RegistryHandler(registry);
        targetContract(address(handler));
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

    /// @notice Documents the v1 squatter vulnerability — H-1 finding from the
    ///         2026-05-13 AI security team dogfood audit. After alice deprecates
    ///         her PCR0, the `activePCR0OwnerByHash` mapping clears to zero, and
    ///         bob can register the IDENTICAL 48 bytes and become the new owner
    ///         of that hash. Customers who only check `active == true` (and not
    ///         `owner == hardcoded_usenami_address`) will accept bob's
    ///         attestation as canonical.
    ///
    ///         This test PINS v1 behaviour. The v2 contract MUST flip this test
    ///         to revert on bob's register (via a permanent `retired` mapping).
    ///         Tracking: namixai/signer issue #4.
    ///
    ///         Operational mitigation for v1: customer SDKs strict-compare the
    ///         returned owner against the canonical Usenami address published
    ///         out-of-band. The OSS README "How to verify" section documents
    ///         the required SDK pattern.
    function test_V1_SquatterAfterDeprecateRecycle() public {
        // Alice — the legitimate registrant — registers and then deprecates.
        vm.startPrank(alice);
        registry.registerPCR0(PCR_A, bytes32(uint256(1)), "v1 alice");
        registry.deprecatePCR0(PCR_A);
        vm.stopPrank();

        // Mapping cleared.
        (bool stillActive, address stillOwner) = registry.isPCR0Active(PCR_A);
        assertFalse(stillActive);
        assertEq(stillOwner, address(0));

        // Bob (the squatter) registers the same 48 bytes. v1 lets him through.
        vm.prank(bob);
        registry.registerPCR0(PCR_A, bytes32(uint256(2)), "v1 squatted by bob");

        // Now the registry's answer is "yes, this PCR0 is active — and bob owns it."
        (bool active, address owner) = registry.isPCR0Active(PCR_A);
        assertTrue(active);
        assertEq(owner, bob);

        // The naive customer who just checks `active` would accept bob.
        // The disciplined customer who strict-compares `owner == ALICE_CANONICAL`
        // would reject. Both behaviours pinned here so v2 work doesn't silently
        // break either expectation.

        // Blast-radius assertions — Alice (legitimate prior owner) is now
        // completely locked out of this PCR0 hash:
        //   - cannot re-register: bob owns it, registerPCR0 reverts.
        //   - cannot deprecate:   she's not msg.sender for this hash anymore.
        // These two reverts demonstrate why "registry consistency" alone is
        // not a substitute for the strict-owner check in customer SDKs —
        // even if Alice tries to reclaim her own previously-registered PCR0,
        // the contract correctly refuses (it doesn't know Alice was first).
        vm.startPrank(alice);
        vm.expectRevert(UsenamiAttestationRegistry.PCR0AlreadyRegistered.selector);
        registry.registerPCR0(PCR_A, bytes32(uint256(3)), "alice retake attempt");
        vm.expectRevert(UsenamiAttestationRegistry.NotOwnerOfPCR0.selector);
        registry.deprecatePCR0(PCR_A);
        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────
    // I-6 dogfood coverage gaps — added 2026-05-13 per AI security audit
    // report `_audit/AI-AGENT-DOGFOOD-PR16-2026-05-13.md` (Item I-6 #2/#3/#4).
    // ─────────────────────────────────────────────────────────────────────

    /// I-6 #2 — Document the v1 fact that `description` has no length cap.
    ///
    /// The current contract accepts arbitrarily-long descriptions and stores
    /// them untruncated. This is a state-bloat surface; v2 will add a
    /// `MAX_DESCRIPTION_LENGTH = 256` constant and reject longer strings.
    /// This test pins v1 behaviour as a regression check — when v2 lands,
    /// this test MUST flip to `vm.expectRevert(DescriptionTooLong)` and the
    /// `assertEq(...).length, 4096, ...)` assertion gets deleted.
    ///
    /// 4096-char description chosen to be well beyond any reasonable use
    /// (typical PCR0 description: ~30 chars like "build v1 rust-1.95 5 exch")
    /// while staying within a single calldata-gas-safe transaction.
    function test_GasSnapshot_LongDescription() public {
        // 4096-byte string filled with 'a'..'z' rotating — defeats any
        // potential string-interning optimisation that might mask the
        // real storage gas.
        bytes memory raw = new bytes(4096);
        for (uint256 i = 0; i < raw.length; i++) {
            raw[i] = bytes1(uint8(0x61 + (i % 26))); // a..z
        }
        string memory longDesc = string(raw);

        vm.prank(alice);
        registry.registerPCR0(PCR_A, bytes32(0), longDesc);

        // Sanity: the description came back untruncated. v2 changes this.
        UsenamiAttestationRegistry.PCR0Record memory r =
            registry.getActivePCR0(alice);
        assertEq(
            bytes(r.description).length,
            4096,
            "v1 stores description untruncated; v2 will flip this assertion"
        );
    }

    /// I-6 #4 — Documented legitimate flow: owner can re-register their own
    /// previously-deprecated PCR0. Distinct from the H-1 squatter scenario
    /// (where a DIFFERENT party claims a deprecated PCR0).
    ///
    /// Real-world use case: operator deploys enclave build v1 → registers
    /// PCR0 X → later deprecates after rotation to v2 → toolchain regression
    /// forces a rollback to v1 → operator wants to re-register the same X.
    /// The contract correctly allows this because activePCR0OwnerByHash[X]
    /// was cleared during deprecate and the squatter-protection check only
    /// blocks `!= address(0)`, not "X was ever active before."
    ///
    /// In v2 with the permanent `retired` mapping, this flow STILL needs to
    /// succeed — the retired check should only apply when a NEW owner tries
    /// to register. The v2 implementation must distinguish "previously
    /// retired by this same owner" (allowed) from "previously retired by
    /// anyone" (blocked) — OR provide a separate `unretireOwn` entry point.
    /// This test documents the v1 baseline for that v2 design decision.
    function test_OwnReRegisterAfterDeprecate() public {
        // Round 1: alice registers + deprecates. Use startPrank/stopPrank to
        // group calls from the same actor — matches the style used in
        // test_V1_SquatterAfterDeprecateRecycle elsewhere in this file.
        vm.startPrank(alice);
        registry.registerPCR0(PCR_A, bytes32(uint256(1)), "build v1");
        registry.deprecatePCR0(PCR_A);
        vm.stopPrank();

        (bool active1, address owner1) = registry.isPCR0Active(PCR_A);
        assertFalse(active1);
        assertEq(owner1, address(0));

        // Round 2: alice re-registers the same PCR0 with a new buildHash.
        vm.prank(alice);
        registry.registerPCR0(PCR_A, bytes32(uint256(2)), "build v1 redeploy");

        (bool active2, address owner2) = registry.isPCR0Active(PCR_A);
        assertTrue(active2);
        assertEq(owner2, alice);

        // History records both lifecycles, in order.
        UsenamiAttestationRegistry.PCR0Record[] memory hist =
            registry.getOwnerHistory(alice);
        assertEq(hist.length, 2, "history records both lifecycles");
        assertGt(hist[0].deprecatedAt, 0, "first record deprecated");
        assertEq(hist[1].deprecatedAt, 0, "second record active");
        assertEq(
            hist[1].buildHash,
            bytes32(uint256(2)),
            "second uses new buildHash; documents legitimate redeploy flow"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // I-6 #3 — Invariant: for every owner, the latest record's deprecation
    // status agrees with `activePCR0OwnerByHash`. Foundry handler-based fuzz.
    // ─────────────────────────────────────────────────────────────────────

    /// Handler wraps registry with bounded fuzz-targets; allocated in
    /// `setUp()` above and registered via `targetContract()`. Foundry
    /// picks public functions on the handler and calls them in random
    /// sequences, then checks every `invariant_*` function.
    RegistryHandler internal handler;

    /// Invariant (v1-realistic version): for every owner with history,
    /// the latest record's deprecation status agrees with
    /// `activePCR0OwnerByHash`:
    ///   - `deprecatedAt == 0`  =>  `mapping[h] == owner`  (active record)
    ///   - `deprecatedAt > 0`   =>  `mapping[h] != owner`  (deprecated OR
    ///                              squatted by someone else; the mapping
    ///                              just must no longer claim the original
    ///                              owner)
    ///
    /// NOTE on the second case: the strict reading
    /// (`deprecatedAt > 0 ⟹ mapping[h] == address(0)`) does NOT hold in v1
    /// because of the H-1 squatter scenario — after the owner deprecates,
    /// the mapping clears to zero, but a third party can then re-register
    /// the same PCR0 and the mapping flips to point at them. v1 only
    /// guarantees the WEAKER "no longer points to the original owner."
    /// v2 with the permanent `retired` mapping will make the strict
    /// reading hold — at that point this invariant should be tightened
    /// to `assertEq(owner, address(0))` to enforce the stronger property.
    ///
    /// See `_audit/AI-AGENT-DOGFOOD-PR16-2026-05-13.md` Section H-1 for
    /// the full squatter analysis and v2 fix design.
    ///
    /// Foundry runs this with the configured `runs` and `depth` from
    /// foundry.toml (default 256 runs × 15 depth). If this fails IN A WAY
    /// THAT IS NOT H-1 — i.e. `deprecatedAt == 0` but mapping disagrees,
    /// or `deprecatedAt > 0` but mapping STILL points to the original
    /// owner — that's a new and serious finding.
    function invariant_ActiveOwnerMatchesUndeprecatedRecord() public view {
        address[] memory actorList = handler.getActors();
        for (uint256 i = 0; i < actorList.length; i++) {
            UsenamiAttestationRegistry.PCR0Record[] memory hist =
                registry.getOwnerHistory(actorList[i]);
            if (hist.length == 0) continue;

            // Last record in history is the most recently registered for
            // this owner. The mapping must agree with its deprecation
            // status. v1-realistic predicate (see NatSpec above and the
            // H-1 squatter regression test for full context):
            //   - deprecatedAt == 0  =>  mapping points to this owner
            //   - deprecatedAt > 0   =>  mapping does NOT claim this owner
            //                            (zero OR a different squatter address)
            // The strict reading (mapping == zero in the deprecated case)
            // does not hold in v1 because the squatter scenario can flip
            // the mapping to another address after deprecation.
            UsenamiAttestationRegistry.PCR0Record memory last =
                hist[hist.length - 1];
            bytes32 h = keccak256(last.pcr0);
            address owner = registry.activePCR0OwnerByHash(h);

            if (last.deprecatedAt == 0) {
                assertEq(
                    owner,
                    actorList[i],
                    "invariant break (active branch): active record but mapping points elsewhere"
                );
            } else {
                // v1-realistic: mapping either is zero (no one squatted)
                // OR points to a DIFFERENT address (squatter took over).
                // Either way, it must NOT still claim the original owner.
                // See NatSpec above for H-1 context.
                assertNotEq(
                    owner,
                    actorList[i],
                    "invariant break (deprecated branch): deprecated record but mapping still claims original owner - would indicate a non-H-1 state drift"
                );
            }
        }
    }
}

/// Foundry invariant handler. Wraps the registry with bounded actions
/// the fuzzer can call in arbitrary sequences. Each public function
/// must succeed-or-noop (never revert) so the fuzzer can keep advancing
/// state — we wrap state-changing calls in `try` to absorb expected
/// reverts (e.g. duplicate PCR0).
///
/// Tracks all actors that successfully registered at least once so the
/// invariant function can iterate over them and check the mapping/array
/// agreement (see `invariant_ActiveOwnerMatchesUndeprecatedRecord`).
contract RegistryHandler is Test {
    UsenamiAttestationRegistry public registry;
    address[] internal _actors;
    /// Dedup guard: prevents `_actors` from growing with duplicates when the
    /// same actor's `registerNew` succeeds multiple times (the registry's
    /// auto-deprecate semantics let that happen). Gemini Code Assist catch
    /// on PR #20 / OSS #6: without this, `invariant_*` does redundant work
    /// proportional to the duplicate count, slowing fuzz runs noticeably.
    mapping(address => bool) internal _isActor;

    constructor(UsenamiAttestationRegistry _registry) {
        registry = _registry;
    }

    /// Read-only accessor for the invariant function. Returns a memory
    /// snapshot of the actor list at call time.
    function getActors() external view returns (address[] memory) {
        return _actors;
    }

    /// Fuzz target: register a fresh PCR0. The fuzzer chooses both the
    /// PCR0 seed and the actor address; we derive a 48-byte PCR0 from
    /// the seed and skip if it collides with an existing registration.
    function registerNew(uint256 seed, address actor) public {
        // Ensure non-zero address. Bitwise-or with 1 guarantees it.
        actor = address(uint160(uint256(keccak256(abi.encode(actor))) | 1));

        // Build a 48-byte PCR0 from the seed: 32 bytes keccak + 16 bytes
        // derived. Total = 48 bytes exactly.
        // Build a 48-byte PCR0: abi.encodePacked of bytes32 (32) + bytes16
        // (16) is guaranteed by the type system to produce exactly 48 bytes,
        // so no runtime length check is needed here. (Gemini Code Assist
        // catch on PR #20 — removed redundant `if (pcr.length != 48) return`.)
        bytes memory pcr = abi.encodePacked(
            keccak256(abi.encode(seed)),
            bytes16(keccak256(abi.encode(seed, "_lo")))
        );

        // Skip if already registered (the validPCR0 modifier would still
        // accept, but registerPCR0 would revert PCR0AlreadyRegistered —
        // we'd rather not waste a fuzz call).
        (bool taken, ) = registry.isPCR0Active(pcr);
        if (taken) return;

        vm.prank(actor);
        try registry.registerPCR0(pcr, bytes32(0), "") {
            // Dedup: only push if we haven't seen this actor before.
            // Foundry's invariant fuzzer can call registerNew for the same
            // derived actor multiple times across runs; the registry's
            // auto-deprecate semantics allow it to succeed each time. Without
            // dedup `_actors` grows unboundedly and slows invariant checks.
            if (!_isActor[actor]) {
                _isActor[actor] = true;
                _actors.push(actor);
            }
        } catch {
            // Swallow expected reverts (e.g. fresh-actor double-register
            // race within the same fuzz run).
        }
    }

    /// Fuzz target: deprecate the active record for an existing actor.
    /// Indexed into the actor list by modulo so the fuzzer can hit any
    /// previously-registered actor.
    function deprecateLast(uint256 actorIdx) public {
        if (_actors.length == 0) return;
        address actor = _actors[actorIdx % _actors.length];

        try registry.getActivePCR0(actor) returns (
            UsenamiAttestationRegistry.PCR0Record memory r
        ) {
            vm.prank(actor);
            try registry.deprecatePCR0(r.pcr0) {} catch {
                // Already deprecated by a previous fuzz step.
            }
        } catch {
            // Actor has no active record (already deprecated everything).
        }
    }
}
