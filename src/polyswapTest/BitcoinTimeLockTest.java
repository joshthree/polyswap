package polyswapTest;

import java.math.BigInteger;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Utils;

import polyswap.Bitcoin;
import sssig.SSSECDSA;

public class BitcoinTimeLockTest {
	public static void main(String[] args) throws Exception {
		Bitcoin btc = new Bitcoin(1);
		
		SSSECDSA signer = new SSSECDSA();
		BigInteger m = btc.createDepositTransaction(btc.getUTXO(), 0, btc.getBaseECKey(), btc.getBaseAddress());
		
		BigInteger[] signature = signer.sign(m, btc.getPrivateKeyforBaseAddress());
		
		btc.dTx = btc.signDepositTransaction(btc.getDepositTransaction(), signature, btc.getBaseECKey());
		
		BigInteger m2 = btc.createRefundTransaction(Coin.parseCoin("0.0001"), btc.getBaseECKey(), btc.getBaseAddress(), 3);
		
		BigInteger[] signature2 = signer.sign(m, btc.getPrivateKeyforBaseAddress());
		
		btc.rTx = btc.signRefundTransaction(signature2, btc.getBaseECKey());
		
		String dTxId = btc.getClient().sendRawTransaction(Utils.HEX.encode(btc.getDepositTransaction().bitcoinSerialize()));
		
		System.out.println("Deposit transactoin " + dTxId);
		System.out.println(Utils.HEX.encode(btc.getRefundTransaction().bitcoinSerialize()));
		String rTxId = btc.getClient().sendRawTransaction(Utils.HEX.encode(btc.getRefundTransaction().bitcoinSerialize()));
		
		System.out.println("Refund transactoin "+ rTxId);
	
	}
}
