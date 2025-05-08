package polyswapTest;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;

import org.bitcoinj.core.ECKey;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.FastRawTransactionManager;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.tx.response.PollingTransactionReceiptProcessor;
import org.web3j.tx.response.TransactionReceiptProcessor;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;
import org.web3j.utils.Convert.Unit;

import polyswap.Ethereum;
import sssig.SSSECDSA;

public class DeployTimeLockTest {
	public static void main(String[] arg) throws Exception {
		//credentials0xd82ef6feafef489bb020da298f09d444093acec9
		BigInteger privateKey = new BigInteger("89179811265080136650681266953673138167329384320295414412418920727415236104720");
		//credentials0xf7a572b491401c826a53e095e1114fda8bdfec6b
		//BigInteger privateKey = new BigInteger("46494197514632179436434992847372710252748354833533938993668237810697764884558");
		Ethereum eth = new Ethereum(3);
		//Credentials cred = eth.loadNewCredentials();
		//System.out.println("credentials" + cred.getAddress()+ "\n"+cred.getEcKeyPair().getPrivateKey());
		//ECKey key = new ECKey(privateKey);
		Credentials cred = Credentials.create(ECKeyPair.create(privateKey));
	//	polyswap.contracts.TimeLock t = polyswap.contracts.TimeLock.deploy(eth.getClient(), cred, new DefaultGasProvider()).send();
		//String contractAddress = "0x38dab3659ebc590c409f85e51ca3f8ddea5777c6";
		//eth.loadCoins(contractAddress, "0.06");
		//TimeLock t = TimeLock.load(contractAddress, eth.getClient(), cred, new DefaultGasProvider());
	//	String contractAddress = t.getContractAddress();
	//	System.out.println(contractAddress);
		
		
	//	TransactionReceipt rec = t.time().send();
//		{
//	//	Function function = new Function("refund",
//		//		Arrays.asList(new org.web3j.abi.datatypes.Address(eth.getBaseAddress())), Collections.emptyList());
//		
//		Function function = new Function("time",
//				Collections.emptyList(), Collections.emptyList());
//
//		//Encode function values in transaction data format
//		String txData = FunctionEncoder.encode(function);
//		System.out.println(txData);
//		
//		EthGetTransactionCount ethGetTransactionCount = eth.getClient().ethGetTransactionCount(cred.getAddress(), DefaultBlockParameterName.LATEST).send();
//		BigInteger nonce = ethGetTransactionCount.getTransactionCount();
//
//		BigInteger gasLimit = BigInteger.valueOf(210000);
//		BigInteger gasPrice = Convert.toWei("1", Unit.GWEI).toBigInteger();
//
//		RawTransaction rawTx = RawTransaction.createTransaction(nonce, gasPrice, gasLimit, contractAddress, txData);
//		
//		SSSECDSA k = new SSSECDSA();
//		BigInteger m = k.calculateBigIntegerforMessage(Hash.sha3(TransactionEncoder.encode(rawTx)));
//		
//		BigInteger[] sigComp = k.sign(m, privateKey);
//		
//		byte[] tx = eth.signDepositTransaction(rawTx, sigComp, ECKeyPair.create(privateKey).getPublicKey());
//		EthSendTransaction dTxE2 = eth.getClient().ethSendRawTransaction(Numeric.toHexString(tx)).send();
//		System.out.println("Ethereum dTx: "+ Numeric.toHexString(tx));
//		System.out.println("Ethereum deposit transaction id: " + dTxE2.getTransactionHash());
//		
//		}
		
		//BigInteger timeNow = t.timeNow().send();
		//BigInteger unlockTime = t.unlockTime().send();
		//System.out.println("Unlock Time: " + unlockTime);
		
		//System.out.println("Time Now: " + timeNow);
		//TransactionManager txManager = new FastRawTransactionManager(eth.getClient(), cred);

		//String txHash = txManager.sendTransaction(DefaultGasProvider.GAS_PRICE, DefaultGasProvider.GAS_LIMIT,
		//		t.getContractAddress(), txData, new BigInteger("1000000000000000")).getTransactionHash();

	//	System.out.println("contract address" + contractAddress);

		//TransactionReceiptProcessor receiptProcessor =
		//		new PollingTransactionReceiptProcessor(eth.getClient(), TransactionManager.DEFAULT_POLLING_FREQUENCY,
		//				TransactionManager.DEFAULT_POLLING_ATTEMPTS_PER_TX_HASH);

		//TransactionReceipt txReceipt = receiptProcessor.waitForTransactionReceipt(txHash);
		//System.out.println(txHash);
		//TransactionReceipt tx = t.claim(eth.getBaseAddress()).send();
		//System.out.println("transaction " + tx.getTransactionHash());
	}


}
