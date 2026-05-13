// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title UsenamiAttestationRegistry
/// @notice On-chain registry of Usenami Signer enclave measurements (PCR0).
///         Customers and third parties can verify that a Verifiable Policy
///         Proof was produced by a specific, openly-registered enclave
///         build — without trusting Usenami's website.
/// @dev    PCR0 is a 48-byte AWS Nitro measurement. Solidity has fixed-size
///         types only up to `bytes32`, so we store as dynamic `bytes` with
///         length-48 validation at register time. Lookup keyed by
///         keccak256(pcr0) so the mapping fits standard storage.
contract UsenamiAttestationRegistry {
    /// @notice One record in an owner's history.
    /// @dev    Stored chronologically; the most recent record with
    ///         `deprecatedAt == 0` is the active measurement.
    struct PCR0Record {
        bytes   pcr0;                 // 48 bytes (validated at register time)
        uint64  registeredAt;         // block.timestamp on creation
        uint64  deprecatedAt;         // 0 = active; timestamp on rotation
        bytes32 buildHash;            // optional: sha256(source tarball + Cargo.lock)
        string  description;          // human-readable, audit-only
    }

    /// @notice Per-owner revision history (append-only).
    mapping(address => PCR0Record[]) public records;

    /// @notice Global lookup: which owner currently controls this PCR0?
    ///         Keyed by keccak256(pcr0). Returns the zero address if the
    ///         measurement is deprecated or never registered.
    mapping(bytes32 => address) public activePCR0OwnerByHash;

    event PCR0Registered(
        address indexed owner,
        bytes32 indexed pcr0Hash,     // keccak256(pcr0) — indexed-friendly
        bytes   pcr0,                 // full 48 bytes for off-chain consumers
        bytes32 buildHash,
        string  description
    );
    event PCR0Deprecated(
        address indexed owner,
        bytes32 indexed pcr0Hash,
        bytes   pcr0
    );

    error PCR0AlreadyRegistered();
    error PCR0NotFound();
    error NotOwnerOfPCR0();
    error InvalidPCR0Length();        // not exactly 48 bytes

    /// @dev Enforce the 48-byte PCR0 measurement length. Centralizes the
    ///      check so every entry point fails fast and uniformly. Note that
    ///      bytes48 is not a valid Solidity type — we accept dynamic `bytes`
    ///      and validate at the boundary via this modifier.
    modifier validPCR0(bytes calldata pcr0) {
        if (pcr0.length != 48) revert InvalidPCR0Length();
        _;
    }

    /// @notice Register a fresh PCR0 measurement. The caller becomes the
    ///         owner. If the caller already has an active PCR0, that
    ///         measurement is auto-deprecated.
    /// @param  pcr0        the 48-byte enclave measurement
    /// @param  buildHash   optional supply-chain anchor (sha256 of source);
    ///                     pass bytes32(0) if not used
    /// @param  description free-form human-readable label
    function registerPCR0(
        bytes calldata pcr0,
        bytes32 buildHash,
        string calldata description
    ) external validPCR0(pcr0) {
        bytes32 h = keccak256(pcr0);
        if (activePCR0OwnerByHash[h] != address(0)) revert PCR0AlreadyRegistered();

        PCR0Record[] storage ownerRecords = records[msg.sender];

        // Auto-deprecate previous active PCR0 (if any).
        uint256 n = ownerRecords.length;
        if (n > 0) {
            PCR0Record storage last = ownerRecords[n - 1];
            if (last.deprecatedAt == 0) {
                last.deprecatedAt = uint64(block.timestamp);
                bytes32 prevH = keccak256(last.pcr0);
                activePCR0OwnerByHash[prevH] = address(0);
                emit PCR0Deprecated(msg.sender, prevH, last.pcr0);
            }
        }

        // Append new record.
        ownerRecords.push(
            PCR0Record({
                pcr0: pcr0,
                registeredAt: uint64(block.timestamp),
                deprecatedAt: 0,
                buildHash: buildHash,
                description: description
            })
        );
        activePCR0OwnerByHash[h] = msg.sender;

        emit PCR0Registered(msg.sender, h, pcr0, buildHash, description);
    }

    /// @notice Mark a PCR0 measurement as deprecated. Only callable by
    ///         the address that registered it. Once deprecated, the
    ///         measurement remains in history but is no longer queryable
    ///         as "active" via `isPCR0Active`.
    function deprecatePCR0(bytes calldata pcr0) external validPCR0(pcr0) {
        bytes32 h = keccak256(pcr0);
        address owner = activePCR0OwnerByHash[h];
        if (owner == address(0)) revert PCR0NotFound();
        if (owner != msg.sender) revert NotOwnerOfPCR0();

        // Walk owner records, find the matching entry, set deprecatedAt.
        PCR0Record[] storage ownerRecords = records[msg.sender];
        for (uint256 i = ownerRecords.length; i > 0; i--) {
            PCR0Record storage r = ownerRecords[i - 1];
            if (keccak256(r.pcr0) == h && r.deprecatedAt == 0) {
                r.deprecatedAt = uint64(block.timestamp);
                break;
            }
        }
        activePCR0OwnerByHash[h] = address(0);
        emit PCR0Deprecated(msg.sender, h, pcr0);
    }

    /// @notice Returns true and the owner address if the PCR0 is
    ///         currently active. Returns (false, address(0)) otherwise.
    function isPCR0Active(bytes calldata pcr0)
        external
        view
        validPCR0(pcr0)
        returns (bool active, address owner)
    {
        owner = activePCR0OwnerByHash[keccak256(pcr0)];
        active = (owner != address(0));
    }

    /// @notice Returns the full history (active + deprecated) for an owner.
    function getOwnerHistory(address owner) external view returns (PCR0Record[] memory) {
        return records[owner];
    }

    /// @notice Returns the most recent ACTIVE record for an owner.
    ///         Reverts if the owner has no active PCR0.
    function getActivePCR0(address owner) external view returns (PCR0Record memory) {
        PCR0Record[] storage ownerRecords = records[owner];
        uint256 n = ownerRecords.length;
        for (uint256 i = n; i > 0; i--) {
            PCR0Record storage r = ownerRecords[i - 1];
            if (r.deprecatedAt == 0) {
                return r;
            }
        }
        revert PCR0NotFound();
    }
}
