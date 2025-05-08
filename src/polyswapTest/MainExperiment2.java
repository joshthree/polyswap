package polyswapTest;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.SecureRandom;

import org.bitcoinj.core.Utils;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.utils.Numeric;

import polyswap.Bitcoin;
import polyswap.Ethereum;
import sssig.SSSECDSA;
import wf.bitcoin.javabitcoindrpcclient.BitcoinRPCException;
import wf.bitcoin.javabitcoindrpcclient.BitcoindRpcClient.Address;
import wf.bitcoin.javabitcoindrpcclient.BitcoindRpcClient.RawTransaction;
import wf.bitcoin.javabitcoindrpcclient.BitcoindRpcClient.Transaction;

public class MainExperiment2 {

	/**
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		args = new String[2];
		args[0] = "127.0.0.1";
		args[1] = "9999";
		int id = 1;


		ServerSocket host = null;
		Socket s;
		ObjectInputStream in;
		ObjectOutputStream out;
		SecureRandom rnd = new SecureRandom();

		try {
			SocketAddress dest = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
			s = new Socket();
			s.connect(dest);
			id = 2;
			System.out.println("Connection to Server successful");
			in = new ObjectInputStream(s.getInputStream());
			out = new ObjectOutputStream(s.getOutputStream());
		}
		catch(Exception e){
			System.out.println("Connection not open, opening server");
			try {
				host = new ServerSocket(Integer.parseInt(args[1]));
				s = host.accept();
				if(args[0].equals(s.getInetAddress().getHostAddress())){
					System.out.println("");
				}
				System.out.println("Connection established");
				out = new ObjectOutputStream(s.getOutputStream());
				in = new ObjectInputStream(s.getInputStream());
			}
			catch( java.net.BindException ex)
			{
				SocketAddress dest = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
				s = new Socket();
				s.connect(dest);
				System.out.println("Connection to Server successful");
				in = new ObjectInputStream(s.getInputStream());
				out = new ObjectOutputStream(s.getOutputStream());
			}
		}

		BigInteger  cTxEm = null, cTxBm = null;

		Bitcoin clB; 
		Ethereum clE;  //blockchain 1 is ethereum


		SSSECDSA signer = new SSSECDSA();

		SSSECDSA ethja = null,btcja = null;



		String dTxId;
		//post deposit transactions

		ethja = new SSSECDSA(id);
		btcja = new SSSECDSA(id);
		ethja.keygen2p(rnd, in, out);
		btcja.keygen2p(rnd, in, out);
		clE = new Ethereum(3);
		clB = new Bitcoin(1);

		String jaEAddress = Keys.getAddress(ethja.getPublicKey());
		
		//Transaction cTxB;
		if (id == 1) {
			BigInteger skE = clE.getPrivateKeyforBaseAddress();
			BigInteger dtx1m = clE.createDepositTransaction(clE.getBaseAddress(), jaEAddress, new BigInteger("600000000000000"));
			BigInteger[] sigParts = signer.sign(dtx1m, skE);

			RawTransaction tx = clE.getRefundTransaction();
			byte[] dTx = clE.signTransaction(tx,sigParts, ECKeyPair.create(skE).getPublicKey());	

			EthSendTransaction dTxE = clE.getClient().ethSendRawTransaction(Numeric.toHexString(dTx)).send();
			System.out.println("Ethereum deposit transaction id: " + dTxE.getTransactionHash());
			// create claim transactions
			dTxId = (String) in.readObject();
			cTxBm = clB.createDepositTransaction(dTxId, 0, btcja.getPublicECKey(), clB.getBaseAddress());
			

			cTxEm = (BigInteger) in.readObject();


			out.writeObject(cTxBm);
			out.flush();
			

			

			
		}else {
			
			Address jaBAddress = clB.getAddress(btcja.getPublicECKey());
			//String fromTxId = "d104274b7efe5557dea027e568f09fa0996e04055cdc560f16b83d0c6cfc7a27";
			String fromTxId = clB.getUTXO();
			BigInteger skB = clB.getPrivateKeyforBaseAddress();
			//BigInteger dtx2m = clB.createTransaction(fromTxId, 0, Coin.parseCoin("0.001"), clB.getBaseECKey(), jaBAddress);
			try {
				BigInteger dtx2m = clB.createDepositTransaction(fromTxId, 0, clB.getBaseECKey(), jaBAddress);
				BigInteger[] sigParts = signer.sign(dtx2m, skB);
				Transaction tx = clB.getDepositTransaction();
				Transaction dTxB = clB.signDepositTransaction(tx,sigParts, clB.getBaseECKey());
				dTxId = clB.getClient().sendRawTransaction(Utils.HEX.encode(dTxB.bitcoinSerialize()));
			} catch (BitcoinRPCException e) {
				BigInteger dtx2m = clB.createDepositTransaction(fromTxId, 1, clB.getBaseECKey(), jaBAddress);
				BigInteger[] sigParts = signer.sign(dtx2m, skB);
				Transaction tx = clB.getDepositTransaction();
				Transaction dTxB = clB.signDepositTransaction(tx,sigParts, clB.getBaseECKey());
				dTxId = clB.getClient().sendRawTransaction(Utils.HEX.encode(dTxB.bitcoinSerialize()));
			}
			System.out.println("Bitcoin deposit transaction id: " + dTxId);
			
			out.writeObject(dTxId);
			out.flush();
			
			//Thread.sleep(30000);
			// create claim transaction
			cTxEm = clE.createTransaction(jaEAddress, clE.getBaseAddress(), new BigInteger("500000000000000"),"0");
			//cTxEm = clE.createDepositTransaction(jaEAddress, clE.getBaseAddress(), new BigInteger("500000000000000"));
			
			out.writeObject(cTxEm);
			out.flush();

			cTxBm = (BigInteger) in.readObject();

			
			

		}

		ethja.pSign(cTxEm, in, out);
		btcja.pSign(cTxBm, in, out);
		

		if(id ==1 ) {	
			// partial signature on claim transactions
			BigInteger b2  = (BigInteger) in.readObject();

			//complete Bitcoin claim transaction
			BigInteger[] sigParts2 = btcja.complete(btcja.getPhi(), b2);
			Transaction tx = clB.getDepositTransaction();
			Transaction cTxBT = clB.signDepositTransaction(tx,sigParts2, btcja.getPublicECKey());
			String cTxId = clB.getClient().sendRawTransaction(Utils.HEX.encode(cTxBT.bitcoinSerialize()));
			System.out.println("Bitcoin claim transaction id: " + cTxId);
			out.writeObject(cTxId);
			out.flush();

			//sending 
			out.writeObject(ethja.getPhi());
			out.flush();

		} else {

			out.writeObject(btcja.getPhi());
			out.flush();

			String txId = (String) in.readObject();
			BigInteger[] signature = clB.getSignatureFromTransaction(txId, 0);
			BigInteger a2 = btcja.reveal(signature, btcja.getPhi());

			BigInteger phi = (BigInteger) in.readObject();
			BigInteger[] sigParts2 = ethja.complete(ethja.getPhi(), phi);
			RawTransaction tx = clE.getRefundTransaction();
			byte[] cTxET = clE.signTransaction(tx, sigParts2, ethja.getPublicKey());	
			Thread.sleep(10000);
			EthSendTransaction cTxETT = clE.getClient().ethSendRawTransaction(Numeric.toHexString(cTxET)).send();
			System.out.println("Ethereum claim transaction hex: ");
			System.out.println(Numeric.toHexString(cTxET));
			System.out.println("Ethereum claim transaction id: " + cTxETT.getTransactionHash());
		}







		



	}

}
