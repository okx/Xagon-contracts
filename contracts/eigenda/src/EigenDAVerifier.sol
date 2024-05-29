// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import {EigenDARollupUtils} from "eigenda/EigenDARollupUtils.sol";
import "../interfaces/IDataAvailabilityProtocol.sol";

contract EigenDAVerifier is IDataAvailabilityProtocol {
    // Name of the data availability protocol
    string internal constant _PROTOCOL_NAME = "DataAvailabilityCommittee";

    /**
     * @notice Verifies that the given signedHash has been signed by requiredAmountOfSignatures committee members
     * @param hash Hash that must have been signed by requiredAmountOfSignatures of committee members
     * @param dataAvailabilityMessage Byte array containing the signatures and all the addresses of the committee in ascending order
     * [signature 0, ..., signature requiredAmountOfSignatures -1, address 0, ... address N]
     * note that each ECDSA signatures are used, therefore each one must be 65 bytes
     */
    function verifyMessage(
        bytes32 hash,
        bytes calldata dataAvailabilityMessage
    ) external view {
    }

    /**
     * @notice Return the protocol name
     */
    function getProcotolName() external pure override returns (string memory) {
        return _PROTOCOL_NAME;
    }
}
