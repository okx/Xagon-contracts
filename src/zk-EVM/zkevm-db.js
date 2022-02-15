const { Scalar } = require('ffjavascript');

const Constants = require('./constants');
const Processor = require('./processor');
const SMT = require('./zkproverjs/smt');
const { getState } = require('./helpers/state-utils');
const { getValue, setValue } = require('./helpers/db-key-value-utils');

class ZkEVMDB {
    constructor(db, lastBatch, stateRoot, localExitRoot, globalExitRoot, arity, seqChainID, poseidon, sequencerAddress) {
        this.db = db;
        this.lastBatch = lastBatch || Scalar.e(0);
        this.poseidon = poseidon;
        this.F = poseidon.F;

        this.stateRoot = stateRoot || this.F.e(0);
        this.localExitRoot = localExitRoot || this.F.e(0);
        this.globalExitRoot = globalExitRoot || this.F.e(0);

        this.arity = arity;
        this.seqChainID = seqChainID;
        this.sequencerAddress = sequencerAddress;

        this.smt = new SMT(this.db, this.arity, this.poseidon, this.F);
    }

    /**
     * Return a new Processor with the current RollupDb state
     * @param {Number} timestamp - Timestamp of the batch
     * @param {Scalar} maxNTx - Maximum number of transactions
     */
    async buildBatch(timestamp, maxNTx = Constants.defaultMaxTx) {
        return new Processor(
            this.db,
            Scalar.add(this.lastBatch, 1),
            this.arity,
            this.poseidon,
            maxNTx,
            this.seqChainID,
            this.stateRoot,
            this.sequencerAddress,
            this.localExitRoot,
            this.globalExitRoot,
            timestamp,
        );
    }

    /**
     * Consolidate a batch by writing it in the DB
     * @param {Object} processor - Processor object
     */
    async consolidate(processor) {
        if (processor.batchNumber !== Scalar.add(this.lastBatch, 1)) {
            throw new Error('Updating the wrong batch');
        }

        if (!processor.builded) {
            await processor.executeTxs();
        }

        // Populate actual DB with the keys and values inserted in the batch
        await processor.tmpDB.populateSrcDb();

        // Set state root
        await setValue(
            Scalar.add(Constants.DB_StateRoot, processor.batchNumber),
            this.F.toString(processor.currentRoot),
            this.db,
            this.F,
        );

        // Set local exit root
        await setValue(
            Scalar.add(
                Constants.DB_LocalExitRoot,
                processor.batchNumber,
            ),
            this.F.toString(processor.localExitRoot),
            this.db,
            this.F,
        );

        // Set global exit root
        await setValue(
            Scalar.add(
                Constants.DB_GlobalExitRoot,
                processor.batchNumber,
            ),
            this.F.toString(processor.globalExitRoot),
            this.db,
            this.F,
        );

        // Set last batch number
        await setValue(Constants.DB_LastBatch, processor.batchNumber, this.db, this.F);

        // Update ZKEVMDB variables
        this.lastBatch = processor.batchNumber;
        this.stateRoot = processor.currentRoot;
        this.localExitRoot = processor.localExitRoot;
        this.globalExitRoot = processor.globalExitRoot;
    }

    /**
     * Get current address state
     * @param {String} ethAddr ethereum address
     * @returns {Object} ethereum address state
     */
    async getCurrentAccountState(ethAddr) {
        return getState(ethAddr, this.smt, this.stateRoot);
    }

    /**
     * Get the current Batch number
     * @returns {Scalar} batch Number
     */
    getCurrentNumBatch() {
        return this.lastBatch;
    }

    /**
     * Get the current state root
     * @returns {Uint8Array} state root
     */
    getCurrentStateRoot() {
        return this.stateRoot;
    }

    /**
     * Get the current local exit root
     * @returns {String} local exit root
     */
    getCurrentLocalExitRoot() {
        return this.localExitRoot;
    }

    /**
     * Get the current global exit root
     * @returns {String} global exit root
     */
    getCurrentGlobalExitRoot() {
        return this.globalExitRoot;
    }

    /**
     * Create a new instance of the ZkEVMDB
     * @param {Object} db - Mem db object
     * @param {Object} seqChainID - Sequencer chian id
     * @param {Object} poseidon - Poseidon object
     * @param {String} sequencerAddress - Sequencer address
     * @param {Uint8Array} root - Merkle root
     * @returns {Object} ZkEVMDB object
     */
    static async newZkEVM(db, seqChainID, arity, poseidon, sequencerAddress, stateRoot, localExitRoot, globalExitRoot) {
        const { F } = poseidon;
        try {
            const lastBatch = await getValue(Constants.DB_LastBatch, db, F);
            const DBStateRoot = await getValue(Scalar.add(Constants.DB_StateRoot, lastBatch), db, F);
            const DBLocalExitRoot = await getValue(Scalar.add(Constants.DB_LocalExitRoot, lastBatch), db, F);
            const DBGlobalExitRoot = await getValue(Scalar.add(Constants.DB_GlobalExitRoot, lastBatch), db, F);
            const dBSeqChainID = Scalar.toNumber(await getValue(Constants.DB_SeqChainID, db, F));
            const dBArity = Scalar.toNumber(await getValue(Constants.DB_Arity, db, F));

            return new ZkEVMDB(
                db,
                lastBatch,
                DBStateRoot,
                DBLocalExitRoot,
                DBGlobalExitRoot,
                dBArity,
                dBSeqChainID,
                poseidon,
                sequencerAddress,
            );
        } catch (error) {
            const setseqChainID = seqChainID || Constants.defaultSeqChainID;
            const setArity = arity || Constants.defaultArity;

            await setValue(Constants.DB_SeqChainID, setseqChainID, db, F);
            await setValue(Constants.DB_Arity, setArity, db, F);

            return new ZkEVMDB(
                db,
                Scalar.e(0),
                stateRoot,
                localExitRoot,
                globalExitRoot,
                setArity,
                setseqChainID,
                poseidon,
                sequencerAddress,
            );
        }
    }
}

module.exports = ZkEVMDB;