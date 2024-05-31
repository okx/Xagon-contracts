// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/EigenDAVerifier.sol";
import {IEigenDAServiceManager} from "eigenda/interfaces/IEigenDAServiceManager.sol";
import {BN254} from "eigenlayer-middleware/libraries/BN254.sol";

contract TestDecodeDAMessage is Test {
    address constant adminAddress = 0x0000000000000000000000000000000000000001;
    address constant serviceManager = 0x0000000000000000000000000000000000000002;
    bytes testMessage = hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000003039000000000000000000000000000000000000000000000000000000000001093200000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000032000000000000000000000000000000000000000000000000000000000000004b00000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d4310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000003039000000000000000000000000000000000000000000000000000000000000000301020300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003323c460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000301020300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003040506000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030102030000000000000000000000000000000000000000000000000000000000";
    EigenDAVerifier verifierContract;

    function setUp() public {
        verifierContract = new EigenDAVerifier(adminAddress, IEigenDAServiceManager(serviceManager));        
    }

    function testDecodeTestMessage() public view {
        // Get correct blob data
        IEigenDAServiceManager.QuorumBlobParam[] memory params = new IEigenDAServiceManager.QuorumBlobParam[](1);
        params[0] = IEigenDAServiceManager.QuorumBlobParam(uint8(1), uint8(50), uint8(75), uint32(1024));
        EigenDAVerifier.BlobData memory data = EigenDAVerifier.BlobData(
            IEigenDAServiceManager.BlobHeader(
                BN254.G1Point(uint256(12345), uint256(67890)),
                uint32(100),
                params
            ),
            EigenDARollupUtils.BlobVerificationProof(
                uint32(1),
                uint32(2),
                IEigenDAServiceManager.BatchMetadata(
                    IEigenDAServiceManager.BatchHeader(
                        bytes32(0),
                        hex"010203",
                        hex"323c46",
                        uint32(12345)
                    ),
                    bytes32(0),
                    uint32(54321)
                ),
                hex"010203",
                hex"040506"
            ),
            hex"010203"
        );
        EigenDAVerifier.BlobData memory decodedData = verifierContract.decodeBlobData(testMessage);
        assertEq(data.blobHeader.commitment.X, decodedData.blobHeader.commitment.X);
        assertEq(data.blobHeader.commitment.Y, decodedData.blobHeader.commitment.Y);
        assertEq(data.blobHeader.dataLength, decodedData.blobHeader.dataLength);
        assertEq(data.blobHeader.quorumBlobParams.length, decodedData.blobHeader.quorumBlobParams.length);
        for (uint i=0; i < data.blobHeader.quorumBlobParams.length; i++) {
            assertEq(data.blobHeader.quorumBlobParams[i].quorumNumber, decodedData.blobHeader.quorumBlobParams[i].quorumNumber);
            assertEq(data.blobHeader.quorumBlobParams[i].adversaryThresholdPercentage, decodedData.blobHeader.quorumBlobParams[i].adversaryThresholdPercentage);
            assertEq(data.blobHeader.quorumBlobParams[i].confirmationThresholdPercentage, decodedData.blobHeader.quorumBlobParams[i].confirmationThresholdPercentage);
            assertEq(data.blobHeader.quorumBlobParams[i].chunkLength, decodedData.blobHeader.quorumBlobParams[i].chunkLength);
        }
        assertEq(data.blobVerificationProof.batchId, decodedData.blobVerificationProof.batchId);
        assertEq(data.blobVerificationProof.blobIndex, decodedData.blobVerificationProof.blobIndex);
        assertEq(data.blobVerificationProof.batchMetadata.batchHeader.blobHeadersRoot, decodedData.blobVerificationProof.batchMetadata.batchHeader.blobHeadersRoot);
        assertEq(data.blobVerificationProof.batchMetadata.batchHeader.quorumNumbers, decodedData.blobVerificationProof.batchMetadata.batchHeader.quorumNumbers);
        assertEq(data.blobVerificationProof.batchMetadata.batchHeader.signedStakeForQuorums, decodedData.blobVerificationProof.batchMetadata.batchHeader.signedStakeForQuorums);
        assertEq(data.blobVerificationProof.batchMetadata.batchHeader.referenceBlockNumber, decodedData.blobVerificationProof.batchMetadata.batchHeader.referenceBlockNumber);
        assertEq(data.blobVerificationProof.batchMetadata.signatoryRecordHash, decodedData.blobVerificationProof.batchMetadata.signatoryRecordHash);
        assertEq(data.blobVerificationProof.batchMetadata.confirmationBlockNumber, decodedData.blobVerificationProof.batchMetadata.confirmationBlockNumber);
        assertEq(data.blobVerificationProof.inclusionProof, decodedData.blobVerificationProof.inclusionProof);
        assertEq(data.blobVerificationProof.quorumIndices, decodedData.blobVerificationProof.quorumIndices);
    }
}
