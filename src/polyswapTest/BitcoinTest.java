package polyswapTest;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Bech32;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.DumpedPrivateKey;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.ECKey.ECDSASignature;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.SegwitAddress;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.Bech32.Bech32Data;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.Script.ScriptType;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.wallet.KeyChain.KeyPurpose;
import org.bitcoinj.wallet.Wallet;

import polyswap.Bitcoin;
import sssig.SSSECDSA;

public class BitcoinTest {
	
	public static NetworkParameters params;
	
	public static void main(String[] args) throws Exception {
//		BigInteger privKey = new BigInteger("20522560051119128457761780618774714854138929442215369825639298139992165507263");
//		ECKey key = ECKey.fromPrivate(privKey);
//		Address a = Address.fromKey(TestNet3Params.get(), key, ScriptType.P2WPKH);
//		System.out.println(a.toString());
//		Bitcoin btc = new Bitcoin();
//		Address recv = btc.generateAddress();
//		System.out.println("Receiving address: " + recv.toString());
//		try {
//			btc.loadCoins(recv);
//			System.out.println("Receiving addresss balance: "+ btc.getBalance());
//		} catch (UnknownHostException | InsufficientMoneyException | BlockStoreException | InterruptedException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
////		}
//		Private key: 19647452161438319071449973590068966049751795165614116190994973351527364968119
//		Current balance of coinbase is: 14669.0111035 BTC
//		Transaction hashd7bf7ba843f2d71e07634693e0242ade156ed070fff9b69af1a8ebc5b883318d
//		New Private Key: 90576844384072251126630605656151579959630477130504901308039991124682568101549
//		Message: 61515478708754801131500691561334072058015682018588347308216477610505469469751
//		r value = 17222347417486051929674785013659995908570687047394388587096056254573951719462
//		s value = 83086683070171646564837516711993720216027492695981160577579306332332205361494
//		Transaction Id is: 9376787c21f6b10c715e0a621046cb657df75c3a260582998d3594187d7f37de
		String txId = testCreateDepositTransaction();
		Bitcoin cl = new Bitcoin(2);
		String txHex = cl.getClient().getRawTransactionHex(txId);
		Transaction t = new Transaction(RegTestParams.get(), Utils.HEX.decode(txHex));
		TransactionInput tIn = t.getInput(0);
		TransactionWitness twin = tIn.getWitness();
		System.out.println(Utils.HEX.encode(twin.getPush(0)));
		TransactionSignature sig = TransactionSignature.decodeFromBitcoin(twin.getPush(0), true, false);
		System.out.println(sig.r);
		System.out.println(sig.s);
		
	}
	
	public static String testCreateDepositTransaction() throws Exception{
		Bitcoin cl = new Bitcoin(2);
		SSSECDSA k = new SSSECDSA();
		Object [] keyPair  = k.keygen(new SecureRandom());
		BigInteger privKey  = (BigInteger) keyPair[0];
		System.out.println("Private key: " + privKey);
		
		ECKey ecKeyPair = ECKey.fromPrivate(privKey);
		
		Address a = Address.fromKey(RegTestParams.get(), ecKeyPair, ScriptType.P2WPKH);
		Transaction loadTransaction = cl.loadCoins(a, 100 );
		
		ECKey bKeyPair = new ECKey(new SecureRandom());
		System.out.println("New Private Key: " + bKeyPair.getPrivKey());
		
		Address b = Address.fromKey(RegTestParams.get(), bKeyPair, ScriptType.P2WPKH);
		
		BigInteger m = cl.createDepositTransaction(loadTransaction.getTxId().toString(), 1, ecKeyPair, b);
		System.out.println("Message: " + m);
		
		BigInteger[] sigParts = k.sign(m, privKey);
		ECDSASignature sig = new ECDSASignature(sigParts[0], sigParts[1]);
		sig = sig.toCanonicalised();
		System.out.println("r value = " +sig.r);
		System.out.println("s value = " + sig.s);
		
		Transaction loadTransactionSigned = cl.signDepositTransaction(cl.getDepositTransaction(),sigParts, ecKeyPair);
		
		String txId = cl.getClient().sendRawTransaction(Utils.HEX.encode(loadTransactionSigned.bitcoinSerialize()));
		System.out.println("Transaction Id is: " + txId);
		return txId;
	}
	
	public static void overallTest(String[] argss) throws BlockStoreException, UnknownHostException, InsufficientMoneyException, InterruptedException {
		
		params = RegTestParams.get();
		checkPublicKey();
		
		try {
			
			//First string is the private key to bitcoin mining address/ coinbase address. "bcrt1q3gsj7fegug4hyfu8lxch6njvt0ah4yu68z8zgm"
			String[] args = {"cTRr2DBKoDaG53cpJoymibtWSiKomCUiy46CGJX86eVePbHE7Raj",
					"bcrt1q75s4hrk6k8227tudm24vnq80h4psjcgt50nkvt"};
            // Decode the private key from Satoshis Base58 variant. If 51 characters long then it's from Bitcoins
            // dumpprivkey command and includes a version byte and checksum, or if 52 characters long then it has 
            // compressed pub key. Otherwise assume it's a raw key.
            ECKey key;
            if (args[0].length() == 51 || args[0].length() == 52) {
                DumpedPrivateKey dumpedPrivateKey = DumpedPrivateKey.fromBase58(params, args[0]);
                key = dumpedPrivateKey.getKey();
            } else {
                BigInteger privKey = Base58.decodeToBigInteger(args[0]);
                key = ECKey.fromPrivate(privKey);
            }
            //System.out.println("Address from private key is: " + LegacyAddress.fromKey(params, key).toString());
            // And the address ...
            
            Address destination = LegacyAddress.fromString(params, args[1]);
            //System.out.println("destination");
   

            // Import the private key to a fresh wallet.
            Wallet wallet = Wallet.createDeterministic(params, Script.ScriptType.P2PKH);
            wallet.importKey(key);

            // Find the transactions that involve those coins.
            final MemoryBlockStore blockStore = new MemoryBlockStore(params);
            BlockChain chain = new BlockChain(params, wallet, blockStore);
            
            final PeerGroup peerGroup = new PeerGroup(params, chain);
            peerGroup.addAddress(new PeerAddress(params, InetAddress.getLocalHost()));
            peerGroup.startAsync();
            peerGroup.downloadBlockChain();

            // And take them!
            System.out.println("Sending address " + "bcrt1q3gsj7fegug4hyfu8lxch6njvt0ah4yu68z8zgm");
            System.out.println("Balance in Sending address " + wallet.getBalance().toFriendlyString());
            
            
            wallet.sendCoins(peerGroup, destination, (Coin.valueOf(1, 0)));
            
            //Generate second wallet
            Thread.sleep(20000);
            Wallet wallet2 = Wallet.createBasic(params);
            
            
            //wallet2.freshAddress(KeyPurpose.RECEIVE_FUNDS);
            
            wallet2.addWatchedAddress(destination);
            System.out.println("Receiving address "+ args[1]);
            System.out.println("Balance in receiving address " + wallet2.getBalance().toFriendlyString());

            // Wait a few seconds to let the packets flush out to the network (ugly).
            Thread.sleep(5000);
            peerGroup.stopAsync();
            System.exit(0);
        } catch (ArrayIndexOutOfBoundsException e) {
            System.out.println("First arg should be private key in Base58 format. Second argument should be address " +
                    "to send to.");
        }
		
	}
	
	public static void checkPublicKey() {
        
        BigInteger privKey = new BigInteger("26552144654319586874152160033374991152228906068474034635292476513307235429233");
        ECKey key = ECKey.fromPrivate(privKey);
        System.out.println(SegwitAddress.fromKey(params, key));
    	
	}
	
//	public static void loadCoins(Address a) {
//		String skToCoinbase = "cTRr2DBKoDaG53cpJoymibtWSiKomCUiy46CGJX86eVePbHE7Raj"; //pk = "bcrt1q3gsj7fegug4hyfu8lxch6njvt0ah4yu68z8zgm"
//		BigInteger privKey = Base58.decodeToBigInteger(skToCoinbase);
//		ECKey key = ECKey.fromPrivate(privKey);
//		Wallet wallet = Wallet.createDeterministic(params, Script.ScriptType.P2PKH);
//		wallet.importKey(key);
//		wallet.sendCoins(peerGroup, destination, (Coin.valueOf(1, 0)));
//		
//	}
}
