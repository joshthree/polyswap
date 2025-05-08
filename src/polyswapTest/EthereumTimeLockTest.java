package polyswapTest;

import java.io.IOException;
import java.math.BigInteger;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.utils.Numeric;

import polyswap.Ethereum;
import sssig.SSSECDSA;

public class EthereumTimeLockTest {
	public static void main(String[] args) throws Exception {
		Ethereum eth = new Ethereum(3);
		BigInteger privateKey = new BigInteger("89179811265080136650681266953673138167329384320295414412418920727415236104720");
		Credentials cred = Credentials.create(ECKeyPair.create(privateKey));
		
		SSSECDSA signer = new SSSECDSA();
		System.out.println("Signer created");
		
		//BigInteger m = eth.createDepositTransaction(cred.getAddress(), cred.getAddress(), new BigInteger("6000000000000"), new BigInteger("10"));
		//System.out.println(m);
		//BigInteger m = eth.createClaimTransaction(cred.getAddress(), cred.getAddress());
		
		
		/*
		 * byte[] signedTx = eth.signTransaction(eth.getDepositTransaction(),
		 * signer.sign(m, privateKey), cred.getEcKeyPair().getPublicKey());
		 * EthSendTransaction tx =
		 * eth.getClient().ethSendRawTransaction(Numeric.toHexString(signedTx)).send();
		 * System.out.println(Numeric.toHexString(signedTx)); System.out.println("TID: "
		 * + tx.getTransactionHash());
		 */
		
//		Thread.sleep(10000);
		
		BigInteger m2 = eth.createClaimTransaction(cred.getAddress(), cred.getAddress(), "0xc82f869d68e8a5e3bcf8fc97b8d4f8ab68b8142c");
		byte[] signedTx2 = eth.signTransaction(eth.getClaimTransaction(), signer.sign(m2, privateKey), cred.getEcKeyPair().getPublicKey());
		EthSendTransaction tx2 = eth.getClient().ethSendRawTransaction(Numeric.toHexString(signedTx2)).send();
		System.out.println(Numeric.toHexString(signedTx2));
		System.out.println("TID: " + tx2.getTransactionHash());
		
	}
}
