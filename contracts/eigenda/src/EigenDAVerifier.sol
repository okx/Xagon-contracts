// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {EigenDARollupUtils} from "eigenda/libraries/EigenDARollupUtils.sol";
import {IEigenDAServiceManager} from "eigenda/interfaces/IEigenDAServiceManager.sol";
import "../interfaces/IDataAvailabilityProtocol.sol";
import "../interfaces/IPolygonZkEVMVEtrogErrors.sol";

/*
 * Contract responsible for on-chain data availability verification of L2 batch data submitted to the EigenDA
 * layer using the blob verification proofs. The contract serves as an adaptor pattern for the existing DA
 * interface on the PolygonValidium data availability protocol to interact with the EigenDAServiceManager.
 */
contract EigenDAVerifier is
    IDataAvailabilityProtocol,
    IPolygonZkEVMVEtrogErrors
{
    /**
     * @notice Struct which will store the blob verification data
     * @param blobHeader stores the header of the blob containing the relevant attributes of the blob
     * @param blobVerificationProof stores the relevant data needed to prove inclusion of the blob on EigenDA layer
     */
    struct BlobData {
        IEigenDAServiceManager.BlobHeader blobHeader;
        EigenDARollupUtils.BlobVerificationProof blobVerificationProof;
    }

    // Name of the data availability protocol
    string internal constant _PROTOCOL_NAME = "EigenDA";

    // Address of the EigenDA service manager
    IEigenDAServiceManager dataAvailabilityProtocol;

    // Address that will be able to adjust contract parameters
    address public admin;

    // This account will be able to accept the admin role
    address public pendingAdmin;

    /**
     * @dev Emitted when the admin updates the data availability protocol address
     */
    event SetDataAvailabilityProtocol(IEigenDAServiceManager newTrustedSequencer);

    /**
     * @dev Emitted when the admin starts the two-step transfer role setting a new pending admin
     */
    event TransferAdminRole(address newPendingAdmin);

    /**
     * @dev Emitted when the pending admin accepts the admin role
     */
    event AcceptAdminRole(address newAdmin);

    /**
     * @param _eigenDAServiceManager EigenDA service manager address
     */
    constructor(
        address _admin,
        IEigenDAServiceManager _eigenDAServiceManager
    ) {
        admin = _admin;
        dataAvailabilityProtocol = _eigenDAServiceManager;
    }

    modifier onlyAdmin() {
        if (admin != msg.sender) {
            revert OnlyAdmin();
        }
        _;
    }

    /**
     * @notice Return the protocol name
     */
    function getProcotolName() external pure returns (string memory) {
        return _PROTOCOL_NAME;
    }

    /**
     * @notice Return the data availability protocol address
     */
    function getDataAvailabilityProtocol() external view returns (address) {
        return address(dataAvailabilityProtocol);
    }

    /////////////////////////////////////////////
    // Data availability message decode functions
    /////////////////////////////////////////////

    /**
     * @notice Decodes the data availaiblity message to the EigenDA blob data
     * @param data The encoded data availability message bytes
     */
    function decodeBlobData(bytes calldata data) public pure returns (BlobData memory blobData) {
        return abi.decode(data, (BlobData));
    }

    //////////////////
    // Admin functions
    //////////////////

    /**
     * @notice Allow the admin to set a new data availability protocol
     * @param newDataAvailabilityProtocol Address of the new trusted sequencer
     */
    function setDataAvailabilityProtocol(
        IEigenDAServiceManager newDataAvailabilityProtocol
    ) external onlyAdmin {
        dataAvailabilityProtocol = newDataAvailabilityProtocol;

        emit SetDataAvailabilityProtocol(newDataAvailabilityProtocol);
    }

    /**
     * @notice Starts the admin role transfer
     * This is a two step process, the pending admin must accepted to finalize the process
     * @param newPendingAdmin Address of the new pending admin
     */
    function transferAdminRole(address newPendingAdmin) external onlyAdmin {
        pendingAdmin = newPendingAdmin;
        emit TransferAdminRole(newPendingAdmin);
    }

    /**
     * @notice Allow the current pending admin to accept the admin role
     */
    function acceptAdminRole() external {
        if (pendingAdmin != msg.sender) {
            revert OnlyPendingAdmin();
        }

        admin = pendingAdmin;
        emit AcceptAdminRole(pendingAdmin);
    }

    /////////////////////////////////
    // Data availability verification
    /////////////////////////////////

    /**
     * @notice Verifies that the given blob verification proof has been signed by EigenDA operators and verified
     * on-chain to be to be available
     * @param data Byte array containing the abi-encoded EigenDA blob verification proof to be used for on-chain
     * verification with the EigenDAServiceManager
     */
    function verifyMessage(bytes32, bytes calldata data) external view {
        BlobData memory blob = decodeBlobData(data);
        EigenDARollupUtils.verifyBlob(blob.blobHeader, dataAvailabilityProtocol, blob.blobVerificationProof);
    }
}
