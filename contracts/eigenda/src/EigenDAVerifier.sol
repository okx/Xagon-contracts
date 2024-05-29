// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import {EigenDARollupUtils} from "eigenda/libraries/EigenDARollupUtils.sol";
import {IEigenDAServiceManager} from "eigenda/interfaces/IEigenDAServiceManager.sol";
import {BN254} from "eigenlayer-middleware/libraries/BN254.sol";
import "../interfaces/IDataAvailabilityProtocol.sol";

/*
 * Contract responsible for on-chain data availability verificationof L2 batch data submitted to the EigenDA
 * layer using the blob verification proofs. The contract serves as an adaptor pattern for the existing DA
 * interface on the PolygonValidium data availability protocol to interact with the EigenDAServiceManager.
 */
contract EigenDAVerifier is IDataAvailabilityProtocol {
    // Name of the data availability protocol
    string internal constant _PROTOCOL_NAME = "EigenDA";

    /**
     * @notice Struct which will store the blob verification data
     * @param blobHeader stores the header of the blob containing the relevant attributes of the blob
     * @param blobVerificationProof stores the relevant data needed to proove inclusion of the blob and that the trust
     * assumption were as expected
     */
    struct BlobData {
        IEigenDAServiceManager.BlobHeader blobHeader;
        EigenDARollupUtils.BlobVerificationProof blobVerificationProof;
    }

    IEigenDAServiceManager dataAvailabilityProtocol;

    /**
     * @param _eigenDAServiceManager EigenDA service manager address
     */
    constructor(IEigenDAServiceManager _eigenDAServiceManager) {
        dataAvailabilityProtocol = _eigenDAServiceManager;
    }

    function decodeBlobData(bytes memory data) internal pure returns (BlobData memory blobData) {
        uint256 offset = 0;

        // Decode BlobHeader
        blobData.blobHeader.commitment = toG1Point(data, offset);
        offset += 64;
        blobData.blobHeader.dataLength = toUint32(data, offset);
        offset += 32;
        uint256 quorumBlobParamsLength = toUint32(data, offset);
        offset += 32;
        blobData.blobHeader.quorumBlobParams = new IEigenDAServiceManager.QuorumBlobParam[](quorumBlobParamsLength);
        for (uint256 i = 0; i < quorumBlobParamsLength; i++) {
            blobData.blobHeader.quorumBlobParams[i] = toQuorumBlobParam(data, offset);
            offset += 7 + 32; // 3 * uint8 + uint32
        }

        // Decode BlobVerificationProof
        blobData.blobVerificationProof = decodeProof(data, offset);
    }

    function decodeProof(bytes memory data, uint256 offset)
        internal
        pure
        returns (EigenDARollupUtils.BlobVerificationProof memory proof)
    {
        // Decode batchId and blobIndex
        proof.batchId = toUint32(data, offset);
        offset += 32;
        proof.blobIndex = toUint32(data, offset);
        offset += 32;

        // Decode batchHeader.blobHeadersRoot
        proof.batchMetadata.batchHeader.blobHeadersRoot = toBytes32(data, offset);
        offset += 32;

        // Decode batchHeader.quorumNumbers
        proof.batchMetadata.batchHeader.quorumNumbers = toBytes(data, offset);
        offset += getBytesLength(data, offset) + 32;

        // Decode batchHeader.signedStakeForQuorums
        proof.batchMetadata.batchHeader.signedStakeForQuorums = toBytes(data, offset);
        offset += getBytesLength(data, offset) + 32;

        // Decode batchHeader.referenceBlockNumber
        proof.batchMetadata.batchHeader.referenceBlockNumber = toUint32(data, offset);
        offset += 32;

        // Decode signatoryRecordHash
        proof.batchMetadata.signatoryRecordHash = toBytes32(data, offset);
        offset += 32;

        // Decode confirmationBlockNumber
        proof.batchMetadata.confirmationBlockNumber = toUint32(data, offset);
        offset += 32;

        // Decode inclusionProof
        proof.inclusionProof = toBytes(data, offset);
        offset += getBytesLength(data, offset) + 32;

        // Decode quorumIndices
        proof.quorumIndices = toBytes(data, offset);
    }

    function getBytesLength(bytes memory data, uint256 offset) internal pure returns (uint256 length) {
        assembly {
            length := mload(add(data, add(offset, 0x20)))
        }
    }

    function toG1Point(bytes memory data, uint256 offset) internal pure returns (BN254.G1Point memory point) {
        point.X = toUint256(data, offset);
        offset += 32;
        point.Y = toUint256(data, offset);
    }

    function toUint256(bytes memory data, uint256 offset) internal pure returns (uint256) {
        uint256 result;
        assembly {
            result := mload(add(data, add(0x20, offset)))
        }
        return result;
    }

    function toQuorumBlobParam(bytes memory data, uint256 offset)
        internal
        pure
        returns (IEigenDAServiceManager.QuorumBlobParam memory param)
    {
        param.quorumNumber = toUint8(data, offset);
        offset += 1;
        param.adversaryThresholdPercentage = toUint8(data, offset);
        offset += 1;
        param.confirmationThresholdPercentage = toUint8(data, offset);
        offset += 1;
        param.chunkLength = toUint32(data, offset);
    }

    function toUint32(bytes memory data, uint256 offset) internal pure returns (uint32) {
        uint32 result;
        assembly {
            result := mload(add(data, add(0x20, offset)))
        }
        return result;
    }

    function toUint8(bytes memory data, uint256 offset) internal pure returns (uint8) {
        uint8 result;
        assembly {
            result := mload(add(data, add(0x1, offset)))
        }
        return result;
    }

    function toUint64(bytes memory data, uint256 offset) internal pure returns (uint64) {
        uint64 result;
        assembly {
            result := mload(add(data, add(0x20, offset)))
        }
        return result;
    }

    function toBytes32(bytes memory data, uint256 offset) internal pure returns (bytes32) {
        bytes32 result;
        assembly {
            result := mload(add(data, add(0x20, offset)))
        }
        return result;
    }

    function toBytes(bytes memory data, uint256 offset) internal pure returns (bytes memory) {
        uint256 length = getBytesLength(data, offset);
        bytes memory result = new bytes(length);
        assembly {
            let dataPtr := add(data, add(0x20, add(offset, 0x20)))
            let resultPtr := add(result, 0x20)
            for { let i := 0 } lt(i, length) { i := add(i, 0x20) } { mstore(add(resultPtr, i), mload(add(dataPtr, i))) }
        }
        return result;
    }

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

    /**
     * @notice Return the protocol name
     */
    function getProcotolName() external pure override returns (string memory) {
        return _PROTOCOL_NAME;
    }
}
