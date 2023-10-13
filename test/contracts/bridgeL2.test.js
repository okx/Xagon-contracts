const { expect } = require('chai');
const { ethers, upgrades } = require('hardhat');

describe('PolygonZkEVMBridgeL2 Contract', () => {
    let deployer;
    let rollup;
    let zkevmAddress;

    let polygonZkEVMGlobalExitRoot;
    let polygonZkEVMBridgeContract;
    let tokenContract;
    let gasTokenContract;
    let wethContract;

    const tokenName = 'Matic Token';
    const tokenSymbol = 'MATIC';
    const decimals = 18;
    const tokenInitialBalance = ethers.utils.parseEther('20000000');
    const metadataToken = ethers.utils.defaultAbiCoder.encode(
        ['string', 'string', 'uint8'],
        [tokenName, tokenSymbol, decimals],
    );

    const gasTokenName = 'Gas Token';
    const gasTokenSymbol = 'GAS';

    const networkIDMainnet = 0;
    const networkIDRollup = 1;

    const LEAF_TYPE_ASSET = 0;

    let polygonZkEVMAddress;

    beforeEach('Deploy contracts', async () => {
        // load signers
        [deployer, rollup, zkevmAddress] = await ethers.getSigners();

        polygonZkEVMAddress = zkevmAddress.address;

        // deploy PolygonZkEVMBridge
        const polygonZkEVMBridgeFactory = await ethers.getContractFactory('PolygonZkEVMBridgeL2');
        polygonZkEVMBridgeContract = await upgrades.deployProxy(polygonZkEVMBridgeFactory, [], { initializer: false });

        // deploy weth contract
        const WETHzkEVMFactory = await ethers.getContractFactory('WETHzkEVM', deployer);
        wethContract = await WETHzkEVMFactory.deploy(polygonZkEVMBridgeContract.address);
        await wethContract.deployed();

        // deploy gas token
        const gasTokenFactory = await ethers.getContractFactory('ERC20PermitMock');
        gasTokenContract = await gasTokenFactory.deploy(
            gasTokenName,
            gasTokenSymbol,
            deployer.address,
            tokenInitialBalance,
        );

        await gasTokenContract.deployed();

        // deploy global exit root manager
        const PolygonZkEVMGlobalExitRootFactory = await ethers.getContractFactory('PolygonZkEVMGlobalExitRoot');
        polygonZkEVMGlobalExitRoot = await PolygonZkEVMGlobalExitRootFactory.deploy(rollup.address, polygonZkEVMBridgeContract.address);

        await polygonZkEVMBridgeContract.initialize(
            networkIDRollup,
            polygonZkEVMGlobalExitRoot.address,
            polygonZkEVMAddress,
            gasTokenContract.address,
            networkIDMainnet,
            wethContract.address,
        );

        // deploy token
        const maticTokenFactory = await ethers.getContractFactory('ERC20PermitMock');
        tokenContract = await maticTokenFactory.deploy(
            tokenName,
            tokenSymbol,
            deployer.address,
            tokenInitialBalance,
        );
        await tokenContract.deployed();
    });

    it('should check the constructor parameters', async () => {
        expect(await polygonZkEVMBridgeContract.globalExitRootManager()).to.be.equal(polygonZkEVMGlobalExitRoot.address);
        expect(await polygonZkEVMBridgeContract.networkID()).to.be.equal(networkIDRollup);
        expect(await polygonZkEVMBridgeContract.polygonZkEVMaddress()).to.be.equal(polygonZkEVMAddress);
    });

    it('should check the l2 token is not Permitted for the bridge at default state', async () => {
        const isPermitted = await polygonZkEVMBridgeContract.isTokenAllowed(tokenContract.address);
        expect(isPermitted).to.be.equal(false);
    });

    it('should update the l2 token to Permitted for the bridge', async () => {
        await expect(await polygonZkEVMBridgeContract.connect(zkevmAddress).setL2TokenBridgePermission(tokenContract.address, true))
            .to.emit(polygonZkEVMBridgeContract, 'L2TokenPermissionSet')
            .withArgs(tokenContract.address, true);

        const isPermitted = await polygonZkEVMBridgeContract.isTokenAllowed(tokenContract.address);
        expect(isPermitted).to.be.equal(true);
    });

    it('should revert when updating the l2 token to Permitted for the bridge from non zkevm address', async () => {
        await expect(polygonZkEVMBridgeContract.setL2TokenBridgePermission(tokenContract.address, true))
            .to.be.revertedWith('OnlyPolygonZkEVM');
    });

    it('should revert when updating the l2 token to Permitted for the bridge with invalid token address', async () => {
        await expect(polygonZkEVMBridgeContract.connect(zkevmAddress).setL2TokenBridgePermission(ethers.constants.AddressZero, true))
            .to.be.revertedWith('Invalid token address');
    });

    it('should revert when bridge asset with non permitted token', async () => {
        const amount = ethers.utils.parseEther('10');

        await expect(tokenContract.approve(polygonZkEVMBridgeContract.address, amount))
            .to.emit(tokenContract, 'Approval')
            .withArgs(deployer.address, polygonZkEVMBridgeContract.address, amount);

        const tokenInfo = await polygonZkEVMBridgeContract.wrappedTokenToTokenInfo(tokenContract.address);
        expect(tokenInfo.originTokenAddress).to.be.equal(ethers.constants.AddressZero);

        await expect(polygonZkEVMBridgeContract.bridgeAsset(
            networkIDMainnet,
            deployer.address,
            amount,
            tokenContract.address,
            false,
            '0x',

        ))
            .to.be.revertedWith('TokenNotPermitted');
    });

    it('should bridge asset with permitted token', async () => {
        const amount = ethers.utils.parseEther('10');

        await expect(tokenContract.approve(polygonZkEVMBridgeContract.address, amount))
            .to.emit(tokenContract, 'Approval')
            .withArgs(deployer.address, polygonZkEVMBridgeContract.address, amount);

        const tokenInfo = await polygonZkEVMBridgeContract.wrappedTokenToTokenInfo(tokenContract.address);
        expect(tokenInfo.originTokenAddress).to.be.equal(ethers.constants.AddressZero);

        await expect(await polygonZkEVMBridgeContract.connect(zkevmAddress).setL2TokenBridgePermission(tokenContract.address, true))
            .to.emit(polygonZkEVMBridgeContract, 'L2TokenPermissionSet')
            .withArgs(tokenContract.address, true);

        await expect(polygonZkEVMBridgeContract.bridgeAsset(
            networkIDMainnet,
            deployer.address,
            amount,
            tokenContract.address,
            false,
            '0x',
        )).to.emit(polygonZkEVMBridgeContract, 'BridgeEvent')
            .withArgs(
                0,
                networkIDRollup,
                tokenContract.address,
                networkIDMainnet,
                deployer.address,
                amount,
                metadataToken,
                0,
            ).to.emit(tokenContract, 'Transfer')
            .withArgs(deployer.address, polygonZkEVMBridgeContract.address, amount);
    });

    it('should bridge asset when isAllL2TokensAllowed is true', async () => {
        const amount = ethers.utils.parseEther('10');

        await expect(tokenContract.approve(polygonZkEVMBridgeContract.address, amount))
            .to.emit(tokenContract, 'Approval')
            .withArgs(deployer.address, polygonZkEVMBridgeContract.address, amount);

        const tokenInfo = await polygonZkEVMBridgeContract.wrappedTokenToTokenInfo(tokenContract.address);
        expect(tokenInfo.originTokenAddress).to.be.equal(ethers.constants.AddressZero);

        await expect(await polygonZkEVMBridgeContract.connect(zkevmAddress).setAllL2TokensAllowed(true))
            .to.emit(polygonZkEVMBridgeContract, 'AllL2TokensPermissionSet')
            .withArgs(true);

        await expect(polygonZkEVMBridgeContract.bridgeAsset(
            networkIDMainnet,
            deployer.address,
            amount,
            tokenContract.address,
            false,
            '0x',
        )).to.emit(polygonZkEVMBridgeContract, 'BridgeEvent')
            .withArgs(
                LEAF_TYPE_ASSET,
                networkIDRollup,
                tokenContract.address,
                networkIDMainnet,
                deployer.address,
                amount,
                metadataToken,
                0,
            ).to.emit(tokenContract, 'Transfer')
            .withArgs(deployer.address, polygonZkEVMBridgeContract.address, amount);
    });
});
