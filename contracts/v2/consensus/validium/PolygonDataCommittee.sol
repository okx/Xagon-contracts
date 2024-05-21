// SPDX-License-Identifier: AGPL-3.0
pragma solidity 0.8.20;

import "../../interfaces/IDataAvailabilityProtocol.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/*
 * Contract responsible managing the data committee that will verify that the data sent for a validium is singed by a committee
 * It is advised to give the owner of the contract to a timelock contract once the data committee is set
 */
contract PolygonDataCommittee is
    IDataAvailabilityProtocol,
    OwnableUpgradeable
{

    // Name of the data availability protocol
    string internal constant _PROTOCOL_NAME = "Celestia";

    /**
     * Disable initalizers on the implementation following the best practices
     */
    constructor() {
        _disableInitializers();
    }

    function initialize() external initializer {
        // Initialize OZ contracts
        __Ownable_init_unchained();
    }

    /**
     * @notice Verifies that the given signedHash has been signed by requiredAmountOfSignatures committee members
     * @param signedHash Hash that must have been signed by requiredAmountOfSignatures of committee members
     * @param signaturesAndAddrs Byte array containing the signatures and all the addresses of the committee in ascending order
     * [signature 0, ..., signature requiredAmountOfSignatures -1, address 0, ... address N]
     * note that each ECDSA signatures are used, therefore each one must be 65 bytes
     */
    function verifyMessage(
        bytes32 signedHash,
        bytes calldata signaturesAndAddrs
    ) external view {

    }


    /**
     * @notice Return the protocol name
     */
    function getProcotolName() external pure override returns (string memory) {
        return _PROTOCOL_NAME;
    }
}
