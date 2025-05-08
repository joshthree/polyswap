package polyswap;

import java.io.Serializable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.DumpedPrivateKey;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.SegwitAddress;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.SignatureDecodeException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.core.ECKey.ECDSASignature;
import org.bitcoinj.core.Transaction.SigHash;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.Script.ScriptType;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.wallet.KeyChain.KeyPurpose;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.Wallet.SendResult;

import sssig.SSSECDSA;
import wf.bitcoin.javabitcoindrpcclient.BitcoinJSONRPCClient;

public class Bitcoin implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private NetworkParameters params;

	BitcoinJSONRPCClient client;

	Transaction dTx,rTx,cTx;

	public Bitcoin(int a) {
		switch(a) {
		case 1:
			client = new BitcoinJSONRPCClient(); // Testnet mode: port: 18332
			params = TestNet3Params.get();
			break;
		case 2:
			client = new BitcoinJSONRPCClient(1); // RegTest mode: port: 18443
			params = RegTestParams.get();
			break;
		default:
			client = new BitcoinJSONRPCClient(1); // defaults to regtest
			params = RegTestParams.get();
		}

	}

	/**
	 * @return BitcoinJSONRPCClient
	 * This method returns the BitcoinJSONRPCClient. Useful for running method calls to network which are not abstracted.
	 */
	public BitcoinJSONRPCClient getClient() {
		return this.client;
	}

	/**
	 * This method imports some keys where we received some coins for testnet3. 
	 * only applicable to testnet3
	 */
	public void loadCoins() {
		BigInteger skLoadAddress = new BigInteger("20522560051119128457761780618774714854138929442215369825639298139992165507263");
		String pkLoadAddressP2PKH = "mn27UHsBaKjzfKipHSxXT49zDmtkqhFhCv";
		String pkLoadAddressP2WPKH = "tb1qga285nnwwe2288aprzdw9vlt77sdmsftmh95xy";
		String account1 = "mxd2R11rmxTvvNTFRdu7S3jzxnrtPW2cA8";
		String key1 = "cVbCQjYrTiyyrRwsR4edxgsk5t75iY1AsZ545t93GuZgoMWWMf8h"; // dumped from Bitcoind

		DumpedPrivateKey dumpedPrivateKey = DumpedPrivateKey.fromBase58(params, key1);
		ECKey key = dumpedPrivateKey.getKey();

		client.importPrivKey(key1);

		System.out.println("Balance: " + client.getBalance());
	}

	public Address getBaseAddress() {
		return Address.fromString(params, "tb1qga285nnwwe2288aprzdw9vlt77sdmsftmh95xy");
	}

	public static String getAddressReg(NetworkParameters param, ECKey pubKey) {
		return Address.fromKey(param, pubKey, ScriptType.P2WPKH).toString();
	}

	public Address utilConvertToAddress(String address) {
		return Address.fromString(params, address);
	}

	public BigInteger utilConvertToBigInteger(String val) {
		return new BigInteger(val);
	}

	//the value sent is the big integer as string
	public ECKey utilConvertToECKey(String val) {
		return ECKey.fromPrivate(new BigInteger(val));
	}

	public String getUTXO() {
		this.loadCoins();
		return client.sendToAddress(this.getBaseAddress().toString(), new BigDecimal("0.0001") );
	}

	public Address getAddress(ECKey pubKey) {
		return Address.fromKey(params, pubKey, ScriptType.P2WPKH);
	}

	public BigInteger getPrivateKeyforBaseAddress() {
		return new BigInteger("20522560051119128457761780618774714854138929442215369825639298139992165507263");
	}

	public ECKey getBaseECKey() {
		BigInteger skLoadAddress = new BigInteger("20522560051119128457761780618774714854138929442215369825639298139992165507263");
		return ECKey.fromPrivate(skLoadAddress) ;
	}

	public Address getNewAddress() {
		ECKey keyPair = new ECKey();
		System.out.println("sk: " + keyPair.getPrivKey() +  " for " + Address.fromKey(params, keyPair, ScriptType.P2WPKH));
		return Address.fromKey(params, keyPair, ScriptType.P2WPKH);
	}

	@Deprecated
	public Address generateAddress() {
		String sk = "cUpn2DpVKCr17Wpdn5hJUnFf29Kx3utD2m2QMEPTcpjWk3JfmPdG";
		String pk = "bcrt1qattsuun3gxrfkhpyfg73hzlkyer5xzhne9yzkh";
		DumpedPrivateKey dumpedPrivateKey = DumpedPrivateKey.fromBase58(params, sk);
		ECKey key = dumpedPrivateKey.getKey();
		//wallet.importKey(key);
		return SegwitAddress.fromBech32(params, pk);
	}



	@Deprecated
	public void testPublicKeyFormat(BigInteger privKey) {
		ECKey key = ECKey.fromPrivate(privKey);
		System.out.println("Segwit address from private key "+ SegwitAddress.fromKey(params, key));
	}


	/**
	 * @param address address to send coins from coinbase to
	 * @param val value in BTC
	 * @throws InsufficientMoneyException
	 * @throws BlockStoreException
	 * @throws UnknownHostException
	 * @throws InterruptedException
	 * Only for Bitcoin regtest mode: bitcoin-cli -regtest generatetoaddress 1 bcrt1q3gsj7fegug4hyfu8lxch6njvt0ah4yu68z8zgm
	 */
	public Transaction loadCoins(Address address, int val) throws InsufficientMoneyException, BlockStoreException, UnknownHostException, InterruptedException {
		String skToCoinbase = "cTRr2DBKoDaG53cpJoymibtWSiKomCUiy46CGJX86eVePbHE7Raj"; //pk = "bcrt1q3gsj7fegug4hyfu8lxch6njvt0ah4yu68z8zgm"
		DumpedPrivateKey dumpedPrivateKey = DumpedPrivateKey.fromBase58(params, skToCoinbase);
		ECKey key = dumpedPrivateKey.getKey();
		Wallet tempWallet = Wallet.createDeterministic(params, Script.ScriptType.P2PKH);
		tempWallet.importKey(key);

		final MemoryBlockStore blockStore = new MemoryBlockStore(params);
		BlockChain chain = new BlockChain(params, tempWallet, blockStore);

		final PeerGroup peerGroup = new PeerGroup(params, chain);
		peerGroup.addAddress(new PeerAddress(params, InetAddress.getLocalHost()));
		peerGroup.startAsync();
		peerGroup.downloadBlockChain();

		System.out.println("Current balance of coinbase is: " + tempWallet.getBalance().toFriendlyString());


		SendResult sr = tempWallet.sendCoins(peerGroup, address, (Coin.valueOf(val, 0)));
		Transaction hash = sr.tx;
		System.out.println("Transaction hash" + hash.getTxId());

		Thread.sleep(5000);
		peerGroup.stopAsync();

		return hash;
	}	


	/**
	 * @return
	 * 
	 * creates a new address and sends coins to it equals to value from base account, 
	 * returns the transaction hash, new address and private key to the address as string
	 */
	public String[] loadNewAddress() {

		ECKey keyPair = new ECKey();
		String sk = keyPair.getPrivKey().toString();
		String address = Address.fromKey(params, keyPair, ScriptType.P2WPKH).toString();
		this.loadCoins();
		String txHash = client.sendToAddress(this.getBaseAddress().toString(), new BigDecimal("0.0001") );
		return new String[] {sk, address, txHash};

	}


	public BigInteger createDepositTransaction(String fromTxId, int fromTxOutputIndex, ECKey sigKeyPublic, Address to) throws Exception {

		String fromTxHex = client.getRawTransactionHex(fromTxId);
		Transaction fromTx = new Transaction(params, Utils.HEX.decode(fromTxHex));
		// index of the output to be spent
		//int fromTxOutputIndex;

		List<TransactionOutput> txOutList = fromTx.getOutputs();
		TransactionOutput fromTxOut =  txOutList.get(fromTxOutputIndex);
		Script sc = fromTxOut.getScriptPubKey();
		byte[] scriptCodes = fromTxOut.getScriptBytes();
		Script scriptPubKey = new Script(scriptCodes);
		if (!ScriptPattern.isP2WPKH(scriptPubKey)) throw new Exception("scriptPubKey is not P2WPKH.");
		Coin prevValue = fromTxOut.getValue();

		TransactionOutPoint prevOut = new TransactionOutPoint(params, fromTxOut);


		dTx = new Transaction(params);
		TransactionOutput dTout = new TransactionOutput(params, dTx, prevValue.minus(Coin.parseCoin("0.00001")), ScriptBuilder.createOutputScript(to).getProgram());
		dTx.addOutput(dTout);

		TransactionInput input = new TransactionInput(params, dTx, new byte[] {}, prevOut);
		dTx.addInput(input);
		int inputIndex = 0;
		Script scriptCode = new ScriptBuilder()
				.data(ScriptBuilder.createOutputScript(LegacyAddress.fromKey(params, sigKeyPublic)).getProgram()).build();

		Sha256Hash hash = dTx.hashForWitnessSignature(inputIndex, scriptCode, prevValue, SigHash.ALL, false);          

		// signing with our SSSig
		return SSSECDSA.calculateBigIntegerforMessage(hash.getBytes());
	}





	public Transaction getDepositTransaction() {
		return dTx;
	}
	
	// should be called only after dTx is created and signed. This is because refund transaction spends output of dTx.
	// and to reference dTx, we need its Transaction Id which can be obtained after we have all the inputs signed.
	public BigInteger createRefundTransaction(Coin prevValue, ECKey sigKeyPublic, Address to, int timePeriodInHours) throws ScriptMismatchException {
		
		//
		Sha256Hash fromTxId = dTx.getWTxId();
		
		
		// index of the output to be spent
		long fromTxOutputindex = 0;


		TransactionOutPoint prevOut = new TransactionOutPoint(params, fromTxOutputindex, fromTxId);


		rTx = new Transaction(params);
		TransactionOutput rTout = new TransactionOutput(params, rTx, prevValue.minus(Coin.parseCoin("0.00001")), ScriptBuilder.createOutputScript(to).getProgram());
		rTx.addOutput(rTout);

		TransactionInput input = new TransactionInput(params, rTx, new byte[] {}, prevOut);

		// set sequence number for input so that lock time can be used.
		// in compliance with BIP-125
		input.setSequenceNumber(Long.parseUnsignedLong("fffffffe", 16));
		rTx.addInput(input);

		//set lock time , this network adds the transaction 2 hours before its locktime so, this should be considered.
		//https://bitcoin.org/en/transactions-guide#locktime-and-sequence-number
		long unixTime = System.currentTimeMillis() / 1000L;
		long lockTime = unixTime + timePeriodInHours * 60 * 60 ;
		rTx.setLockTime(lockTime);


		int inputIndex = 0;
		Script scriptCode = new ScriptBuilder()
				.data(ScriptBuilder.createOutputScript(LegacyAddress.fromKey(params, sigKeyPublic)).getProgram()).build();

		Sha256Hash hash = rTx.hashForWitnessSignature(inputIndex, scriptCode, prevValue, SigHash.ALL, false);          

		// signing with our SSSig
		return SSSECDSA.calculateBigIntegerforMessage(hash.getBytes());
	}

	public Transaction getRefundTransaction() {
		return rTx;
	}

	public BigInteger createTransaction(String fromTxId, int fromTxOutputindex, Coin prevValue, ECKey sigKeyPublic, Address to) throws ScriptMismatchException {


		// index of the output to be spent
		//long fromTxOutputindex = 0;


		TransactionOutPoint prevOut = new TransactionOutPoint(params, fromTxOutputindex, Sha256Hash.wrap(fromTxId));


		dTx = new Transaction(params);


		TransactionOutput rTout = new TransactionOutput(params, dTx, prevValue.minus(Coin.parseCoin("0.00001")), ScriptBuilder.createOutputScript(to).getProgram());
		dTx.addOutput(rTout);

		TransactionInput input = new TransactionInput(params, dTx, new byte[] {}, prevOut);
		dTx.addInput(input);
		int inputIndex = 0;
		Script scriptCode = new ScriptBuilder()
				.data(ScriptBuilder.createOutputScript(LegacyAddress.fromKey(params, sigKeyPublic)).getProgram()).build();

		Sha256Hash hash = dTx.hashForWitnessSignature(inputIndex, scriptCode, prevValue, SigHash.ALL, false);          

		// signing with our SSSig
		return SSSECDSA.calculateBigIntegerforMessage(hash.getBytes());
	}
	/**
	 * @param signatureComponents signature components for the deposit transaction
	 * @param pubKey public key whose private key was used to 
	 * @return
	 */
	public Transaction signDepositTransaction(Transaction dTx, BigInteger[] signatureComponents, ECKey pubKey) {
		int inputIndex = 0;
		ECDSASignature s = new ECDSASignature(signatureComponents[0], signatureComponents[1]);
		s = s.toCanonicalised();
		//TransactionSignature signature = new TransactionSignature(sigKey.sign(hash), SigHash.ALL, false); // here signing with bitcoinj's facility
		TransactionSignature signature = new TransactionSignature(s, SigHash.ALL, false);
		TransactionInput input = dTx.getInput(inputIndex);
		input.setScriptSig(ScriptBuilder.createEmpty());
		input.setWitness(TransactionWitness.redeemP2WPKH(signature, pubKey));
		return dTx;
	}
	/**
	 * @param signatureComponents signature components for the refund transaction
	 * @param pubKey public key whose private key was used to 
	 * @return
	 */
	public Transaction signRefundTransaction(BigInteger[] signatureComponents, ECKey pubKey) {
		int inputIndex = 0;
		ECDSASignature s = new ECDSASignature(signatureComponents[0], signatureComponents[1]);
		s = s.toCanonicalised();
		//TransactionSignature signature = new TransactionSignature(sigKey.sign(hash), SigHash.ALL, false); // here signing with bitcoinj's facility
		TransactionSignature signature = new TransactionSignature(s, SigHash.ALL, false);
		TransactionInput input = rTx.getInput(inputIndex);
		input.setScriptSig(ScriptBuilder.createEmpty());
		input.setWitness(TransactionWitness.redeemP2WPKH(signature, pubKey));
		return rTx;
	}

	public BigInteger[] getSignatureFromTransaction(String txId, int inputIndex) throws VerificationException, SignatureDecodeException {
		String txHex = client.getRawTransactionHex(txId);
		Transaction t = new Transaction(RegTestParams.get(), Utils.HEX.decode(txHex));
		TransactionInput tIn = t.getInput(inputIndex);
		TransactionWitness twin = tIn.getWitness();
		TransactionSignature sig = TransactionSignature.decodeFromBitcoin(twin.getPush(0), true, false);
		return new BigInteger[] {sig.r, sig.s};
	}

	public class ScriptMismatchException extends Exception {
		public ScriptMismatchException() {
			super("Script of the transaction that we are spending is not of compatible type: \n Expected P2WPKH.");
		}
	}
}
