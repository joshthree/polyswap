package polyswap;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.SecureRandom;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Utils;
import org.bitcoinj.params.RegTestParams;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.RawTransaction;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.utils.Numeric;

import poly.PolyLock;
import sssig.SSSECDSA;
import wf.bitcoin.javabitcoindrpcclient.BitcoinRPCException;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class MainExperiment6 {

	/**
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		args = new String[2];
		args[0] = "127.0.0.1";
		args[1] = "9999";
		int id = 1;
		Coin btcvalue = Coin.parseCoin("0.0001");
		//BigInteger ethvalue = new BigInteger("52000000000000000000");
		BigInteger ethvalue1 = new BigInteger("600000000000000");
		//sk: 87055167286540421655467566219235740982771954884883891532191149251083961537694 for tb1q7mvzhy2x482yxr5s7s2rec5r4gsry63rwkj0xh
		
		//sk: 110859251210045186133673380331545556379224297188181081463489822471102819727088 for 0x9a5466f6d0f2cbc7e248a73e94d455e7e2d67d87
		//sk: 88018130352734761659013713853913883604744695333358931647889854423148054345245 for tb1qjkpwmg5l37tc7505e3ua876wf4vh67vxueqesj
		
		//sk: 1198122800444743492112746500343068198925412395711857035989603109412162315953 for 0xdd74fe26ec8c228a9cfded17014a4bc69021079d
		//sk: 80372014389520458484762025004867182158860889797485386270730933807098692037013 for tb1q0e0kgtknxnwx5wgtzqd06eaa9eqrw32256hjmk
		
		//sk: 23851462371192778742354387945878347112452991814544439261871580087374862599652 for 0xf7753831247abc95cb98f04789532dec167703a4
		
	//	sk: 91278880669390405203315137102639422957318079182509348368034286992068259833651 for tb1qmp4qhet8c08uxe2he38smuxj8kxttcyqgeeagx
		
	//	sk: 54522271191319086153761414409610140921241397410431006215391209179175613582774 for 0x26e7da6f4ceb6628501cc7a783daae00acae8b90
		//sk: 102586111864107589571407165322823031491754383337307859411730462800945443303038 for tb1q39u0p9f0x2fujz44587v2has2tz7p7ujnzkv0c
		
		//sk: 67514715085494714638344086134620177448045049140577270207913465928719346494084 for 0x0c2ef0e22ab9a182c43ed458a8b5b0063b578d9c
		//sk: 56598491925509259538220078929624468589019848432122809233495148266501322030731 for tb1qf6n3gk77pa6rnpzhq7x5qw9xtj6pgla48qk9sh
		//sk: 112096121286616422538603030149649199310361375007874745221599784001804016639264 for 0xe98c5ab4b049df18d56ebc39f4e8e7549e3b6397
		String recAddressB = "tb1qf6n3gk77pa6rnpzhq7x5qw9xtj6pgla48qk9sh";
		//BigInteger skRecB = new BigInteger("91278880669390405203315137102639422957318079182509348368034286992068259833651");
		String recAddressE = "0xe98c5ab4b049df18d56ebc39f4e8e7549e3b6397";
		//BigInteger skRecE = new BigInteger("54522271191319086153761414409610140921241397410431006215391209179175613582774");

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
		long startTime = System.nanoTime();
		BigInteger  cTxEm = null, cTxBm = null;
		BigInteger  rTxEm = null, rTxBm = null;
		
		Bitcoin clB; 
		Ethereum clE;  //blockchain 1 is ethereum


		SSSECDSA signer = new SSSECDSA(id);




		String dTxBId;
		//post deposit transactions

		SSSECDSA ethja = new SSSECDSA(id);
		SSSECDSA btcja = new SSSECDSA(id);
		
		ethja.keygen2p(rnd, in, out);
		btcja.keygen2p(rnd, in, out);
		
		clE = new Ethereum(3);
		clB = new Bitcoin(1);

		

		String jaEAddress1 = Keys.getAddress(ethja.getPublicKey());

		//Transaction cTxB;
		if (id == 1) {
			
			BigInteger timePeriodInMinutes =  new BigInteger("60");
			
			// Address of sending account (Alice's ethereum account address)
			// Address of receiving account (Joint account address)
			// ethereum value to be sent from Alice's etherum account to joint account
			BigInteger skE = clE.getPrivateKeyforBaseAddress();
			
			rTxEm  = clE.createRefundTransaction(jaEAddress1, recAddressE, clE.CONTRACT_ADDRESS);
			//create and sign deposit transaction for Ethereum
			BigInteger dTxE1m = clE.createDepositTransaction(clE.getBaseAddress(), clE.CONTRACT_ADDRESS, ethvalue1);
			BigInteger[] dTxE1mSigParts = signer.sign(dTxE1m, skE);
			RawTransaction dTxE1Raw = clE.getDepositTransaction();
			byte[] dTxE1Bytes = clE.signTransaction(dTxE1Raw,dTxE1mSigParts, ECKeyPair.create(skE).getPublicKey());	
			EthSendTransaction dTxE1 = clE.getClient().ethSendRawTransaction(Numeric.toHexString(dTxE1Bytes)).send();
			System.out.println("Ethereum dTx: "+ Numeric.toHexString(dTxE1Bytes));
			System.out.println("Ethereum deposit transaction id: " + dTxE1.getTransactionHash());
			
			out.writeObject(rTxEm);
			out.flush();
			
			rTxBm = (BigInteger) in.readObject();
			// create claim transaction for Bitcoin
			dTxBId = (String) in.readObject();
			cTxBm = clB.createDepositTransaction(dTxBId, 0, btcja.getPublicECKey(), Address.fromString(null, recAddressB));

			cTxEm = (BigInteger) in.readObject();
			
			out.writeObject(cTxBm);
			out.flush();
			
			

			


		}else {
			
			int timePeriodInHours = 1;
			
			//Transaction id from which the UTXO is to be spent
			//ECkey of the sending address
			// Address of receiving account (joint account)
			Address jaBAddress = clB.getAddress(btcja.getPublicECKey());
			String fromTxId = clB.getUTXO();
			BigInteger skB = clB.getPrivateKeyforBaseAddress();
			// create and sign deposit transaction for Bitcoin
			try {
				BigInteger dtx2m = clB.createDepositTransaction(fromTxId, 0, clB.getBaseECKey(), jaBAddress);
				BigInteger[] sigParts = signer.sign(dtx2m, skB);
				Transaction tx = clB.getDepositTransaction();
				Transaction dTxB = clB.signDepositTransaction(tx,sigParts, clB.getBaseECKey());
				dTxBId = clB.getClient().sendRawTransaction(Utils.HEX.encode(dTxB.bitcoinSerialize()));
			} catch (BitcoinRPCException e) {
				BigInteger dtx2m = clB.createDepositTransaction(fromTxId, 1, clB.getBaseECKey(), jaBAddress);
				BigInteger[] sigParts = signer.sign(dtx2m, skB);
				Transaction tx = clB.getDepositTransaction();
				Transaction dTxB = clB.signDepositTransaction(tx,sigParts, clB.getBaseECKey());
				dTxBId = clB.getClient().sendRawTransaction(Utils.HEX.encode(dTxB.bitcoinSerialize()));
			}
			System.out.println("Bitcoin deposit transaction id: " + dTxBId);
			rTxBm = clB.createRefundTransaction(btcvalue, btcja.getPublicECKey(), Address.fromString(null, recAddressB), timePeriodInHours);
			
			rTxEm = (BigInteger) in.readObject();
			
			out.writeObject(rTxBm);
			out.flush();

			out.writeObject(dTxBId);
			out.flush();

			
			// create claim transaction for Ethereum
			cTxEm = clE.createClaimTransaction(jaEAddress1, recAddressE);
		//	cTxEm = clE.createTransaction(jaEAddress1, recAddressE, ethvalue1.subtract(new BigInteger("100000000000000")),"0");
			//cTxEm = clE.createDepositTransaction(jaEAddress, clE.getBaseAddress(), new BigInteger("500000000000000"));

			out.writeObject(cTxEm);
			out.flush();

			cTxBm = (BigInteger) in.readObject();




		}

		ethja.pSign(rTxEm, in, out);
		btcja.pSign(rTxBm, in, out);
		
		if(id == 1) {
			BigInteger b2  = (BigInteger) in.readObject();
			
			
			out.writeObject(btcja.getPhi());
			out.flush();
			
			//complete Ethereum refund transaction
			BigInteger[] sigParts2 = ethja.complete(ethja.getPhi(), b2);
			
			byte[] rTx = clE.signTransaction(clE.getRefundTransaction(), sigParts2, ethja.getPublicKey());
			
			System.out.println("Ethereum signed Refund Transaction hex: " + Numeric.toHexString(rTx));
		} else {
			out.writeObject(ethja.getPhi());
			out.flush();
			BigInteger b = (BigInteger) in.readObject();
			
			//complete Bitcoin refund transaction
			BigInteger[] sigParts = btcja.complete(btcja.getPhi(), b);
			
			Transaction tx = clB.getRefundTransaction();
			Transaction cTxBT1 = clB.signRefundTransaction(sigParts, btcja.getPublicECKey());
			System.out.println("Bitcoin signed Refund Transaction hex: " + (Utils.HEX.encode(cTxBT1.bitcoinSerialize())));
			
		}
		
		ethja.pSign(cTxEm, in, out);
		
		btcja.pSign(cTxBm, in, out);
		
		ECPoint h;
		h = signer.generateSecondGenerator(rnd, in, out);
		
		if(id ==1 ) {	
			
			//create polylock
			ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

			ECCurve c = spec.getCurve();
			
			ECPoint g = spec.getG();
			BigInteger order = c.getOrder();
			
			//send h
			out.writeObject(h.getEncoded(true));
			out.flush();
			ECPoint h2 =  new ECCurveData(c,g).getECCurveData().decodePoint((byte[]) in.readObject());
			
		
			int n = 2;

			ECCurve[] curves = new ECCurve[n];
			ECPoint[][] gens = new ECPoint[n][2];

			curves[0] = c;
			curves[1] = c;
			
			gens[0][0] = g;
			gens[0][1] = h;

			gens[1][0] = g;
			gens[1][1] = h2;
			
			
			BigInteger[] keys = new BigInteger[n];
			ECPoint[] pubKeys = new ECPoint[n];
			CryptoData[] environments = new CryptoData[n];
			keys[0] = ethja.getPhi();
			keys[1] = btcja.getPhi();
			
			pubKeys[0] = ethja.getPublicPhi()[0];
			pubKeys[1] = btcja.getPublicPhi()[0];
			
			for(int i = 0; i < keys.length; i++) {
				environments[i] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curves[i], gens[i][0]), new ECPointData(gens[i][1])});
			}
			PolyLock lock = new PolyLock(new CryptoDataArray(pubKeys).getCryptoDataArray(), keys, environments, rnd);
			ZKPProtocol prover = lock.getProver();  

			CryptoData proverData = lock.buildProverData(environments, rnd);
			CryptoData publicData = lock.buildPublicInputs(environments);
			CryptoData env = lock.buildEnvironment(environments);

			CryptoData[] outputs = prover.proveFiatShamir(publicData, proverData, env);
			out.writeObject(lock);
			out.writeObject(outputs);

			// partial signature on claim transactions
			BigInteger b2  = (BigInteger) in.readObject();
			
			
			//complete Bitcoin claim transaction
			BigInteger[] sigParts2 = btcja.complete(btcja.getPhi(), b2);
		
			Transaction tx = clB.getDepositTransaction();
			Transaction cTxBT1 = clB.signDepositTransaction(tx,sigParts2, btcja.getPublicECKey());
			String cTxId = clB.getClient().sendRawTransaction(Utils.HEX.encode(cTxBT1.bitcoinSerialize()));
			System.out.println("Bitcoin claim transaction id: " + cTxId);
			out.writeObject(cTxId);
			out.flush();

			

		} else {
			
			
			
			//Receive and verify polyLock
			ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

			ECCurve c = spec.getCurve();
			ECPoint g = spec.getG();
			
			//send h
			ECPoint h2 =  new ECCurveData(c,g).getECCurveData().decodePoint((byte[]) in.readObject());
			out.writeObject(h.getEncoded(true));
			out.flush();
			
			

			int n = 2;

			ECCurve[] curves = new ECCurve[n];
			ECPoint[][] gens = new ECPoint[n][2];

			curves[0] = c;
			curves[1] = c;
			curves[2] = c;
			curves[3] = c;

			gens[0][0] = g;
			gens[0][1] = h2;

			gens[1][0] = g;
			gens[1][1] = h;
			
			BigInteger[] keys = new BigInteger[n];
			ECPoint[] pubKeys = new ECPoint[n];
			CryptoData[] environments = new CryptoData[n];
		
			pubKeys[0] = ethja.getPublicPhi()[0];
			pubKeys[1] = btcja.getPublicPhi()[0];
			
			for(int i = 0; i < keys.length; i++) {
				environments[i] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curves[i], gens[i][0]), new ECPointData(gens[i][1])});
			}
			PolyLock lock = (PolyLock) in.readObject();
			CryptoData[] outputs = (CryptoData[]) in.readObject();

			CryptoData publicData = lock.buildPublicInputs(environments);
			CryptoData env = lock.buildEnvironment(environments);
			ZKPProtocol prover = lock.getProver();
			boolean verify = lock.verifyHiddenValues(new CryptoDataArray(pubKeys).getCryptoDataArray(), environments);
			if(!verify) {
				System.out.println("Not my polynomial!");

			}
			else{
				verify = prover.verifyFiatShamir(publicData, outputs[0], outputs[1], env);
				if(!verify) {
					System.out.println("Bad Proof");
				}
			}

			out.writeObject(btcja.getPhi());
			out.flush();
			
			String txId = (String) in.readObject();
			BigInteger[] signature = clB.getSignatureFromTransaction(txId, 0);
			BigInteger a2 = btcja.reveal(signature, btcja.getPhi());
		
			//index of the secret we know could also be 4
			BigInteger[] result = lock.release(1,  a2, environments);


			BigInteger phiE = result[0];
			BigInteger[] sigParts2 = ethja.complete(ethja.getPhi(), phiE);
			RawTransaction tx = clE.getRefundTransaction();
			byte[] cTxET = clE.signTransaction(tx, sigParts2, ethja.getPublicKey());	
		//	Thread.sleep(10000);
			EthSendTransaction cTxETT = clE.getClient().ethSendRawTransaction(Numeric.toHexString(cTxET)).send();
			System.out.println("Ethereum claim transaction hex: ");
			System.out.println(Numeric.toHexString(cTxET));
			System.out.println("Ethereum claim transaction id: " + cTxETT.getTransactionHash());
			
						
		}
		long endTime = System.nanoTime();
		
		

		System.out.println("Time :" + (endTime-startTime));








	}

}
