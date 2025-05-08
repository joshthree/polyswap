package polyswapTest;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URL;
import java.security.SecureRandom;
import java.util.List;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Bech32;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.ECKey.ECDSASignature;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.SegwitAddress;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Transaction.SigHash;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.core.Utils;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptPattern;
import org.bouncycastle.math.ec.ECPoint;

import sssig.SSSECDSA;

import wf.bitcoin.javabitcoindrpcclient.BitcoinJSONRPCClient;
public class RPCTest {
	public static void main(String[] args) throws Throwable {
//			JsonRpcHttpClient client = new JsonRpcHttpClient(
//		    new URL("http://127.0.0.1:18443"));
//
//			GetBlockCountResponse bc = client.invoke("getblockcount", null, GetBlockCountResponse.class);
//			System.out.println(bc.result);
		BitcoinJSONRPCClient client = new BitcoinJSONRPCClient(1);
//	    System.out.println(client.getWalletInfo().walletVersion());
	    String bitcoinPrivKey = "cTRr2DBKoDaG53cpJoymibtWSiKomCUiy46CGJX86eVePbHE7Raj";
	    client.importPrivKey(bitcoinPrivKey);
	    String coinBase = "bcrt1q3gsj7fegug4hyfu8lxch6njvt0ah4yu68z8zgm";
//	    System.out.println(client.dumpPrivKey("bcrt1q3gsj7fegug4hyfu8lxch6njvt0ah4yu68z8zgm"));
//	    String newAccount = client.getNewAddress();
//	    System.out.println(newAccount);
//	    System.out.println("private key of new account: " + client.dumpPrivKey(newAccount));
	    System.out.println("Balance: " + client.getBalance());
	    client.setTxFee(new BigDecimal("0.001"));
//		//client.sendToAddress(, amount)
	    
	    SSSECDSA k = new SSSECDSA();
	    Object[] keyPair  = k.keygen(new SecureRandom());
	    BigInteger secKey = (BigInteger) keyPair[0];
	    
	    ECPoint pubKey = ECKey.compressPoint(k.getPublic());
	    
	    SegwitAddress addressFromSSS = SegwitAddress.fromKey(RegTestParams.get(), ECKey.fromPublicOnly(pubKey));
	   
	    
	    //addressFromSSS.toBech32();
	    
	    //Address addressFromSSS = Address.fromKey(RegTestParams.get(), , ScriptType.P2WPKH);
	    System.out.println("Address: " + addressFromSSS.toBech32());
	    String spendingTxId = client.sendToAddress(addressFromSSS.toString(), new BigDecimal(1)); 
	    System.out.println("Previous Transaction Id: " + spendingTxId);
	    
	    
	    String newAddress = "bcrt1q56y9cm0ny5zjzc0dy06k0uezncg79252l0wny3";
	    //String newAddressPrivKey = "cT8VbwAegeXNdcoT5jckJefimAjtSr7mAfBBcEan9jSX2Fp6LAwS";
	    //String txId = "2a5da66632f3e2e849c105c31a984f7e4fd8aa6bc9cfbeac1eb29a2c87441744";
	    //BitcoinJSONRPCClient.Transaction t = client.getTransaction("2a5da66632f3e2e849c105c31a984f7e4fd8aa6bc9cfbeac1eb29a2c87441744");
	    String txHex = client.getRawTransactionHex(spendingTxId);
	    System.out.println("Previous Transaction hex: " + txHex);
	    byte[] txBytes = Utils.HEX.decode(txHex);
	    Transaction tx = new Transaction(RegTestParams.get(), txBytes);
	    //List<TransactionOutput> txOutList = tx.getOutputs();
	    //TransactionOutput tout =  txOutList.get(0);
	    //byte[] scriptBytes = tout.getScriptBytes();
	    //System.out.println("Script bytes " + tout.getValue());
	    
	    //ECKey fromKey = ECKey.fromPublicOnly(Address.fromString(RegTestParams.get(), newAddress).getHash());
	    Thread.sleep(5000);
	    Transaction dTx = createDepositTransaction(k, secKey, tx, ECKey.fromPublicOnly(pubKey), SegwitAddress.fromString(RegTestParams.get(), newAddress));
	    //System.out.println(t.address());
//	    RawTransaction rt = t.raw();
//	    rt.vOut();
	    String dTxHex = Utils.HEX.encode(dTx.bitcoinSerialize()); 
	    System.out.println(client.sendRawTransaction(dTxHex));
	   
	}
	
	public static Transaction createDepositTransaction(SSSECDSA k, BigInteger sk, Transaction fromTx, ECKey sigKey, Address to) {
//		Sha256Hash txid = Sha256Hash.wrap(hexId);
//		TransactionOutPoint top = new TransactionOutPoint(RegTestParams.get(), new Long(vout), txid);
//		
		NetworkParameters params = RegTestParams.get();
		
		List<TransactionOutput> txOutList = fromTx.getOutputs();
	    TransactionOutput fromTxOut =  txOutList.get(0);
	    Script sc = fromTxOut.getScriptPubKey();
	    byte[] scriptCodes = fromTxOut.getScriptBytes();
	    Script scriptPubKey = new Script(scriptCodes);
	    Coin prevValue = fromTxOut.getValue();
	    System.out.println("Previous transaction value: " + prevValue.toFriendlyString());
	    
	    TransactionOutPoint prevOut = new TransactionOutPoint(RegTestParams.get(), fromTxOut);
	    
	    
	    sigKey = ECKey.fromPrivate(sk);
	    
	    Transaction dTx = new Transaction(RegTestParams.get());
	    
	    TransactionOutput dTout = new TransactionOutput(RegTestParams.get(), dTx, prevValue.minus(Coin.CENT), ScriptBuilder.createOutputScript(to).getProgram());
	    dTx.addOutput(dTout);
	    
	    //dTx.addSignedInput(fromTxOut, sigKey);
	    
	    TransactionInput input = new TransactionInput(params, dTx, new byte[] {}, prevOut);
        dTx.addInput(input);
        int inputIndex = 0;
        if (ScriptPattern.isP2WPKH(scriptPubKey)) {
            Script scriptCode = new ScriptBuilder()
                    .data(ScriptBuilder.createOutputScript(LegacyAddress.fromKey(params, sigKey)).getProgram()).build();

            Sha256Hash hash = dTx.hashForWitnessSignature(inputIndex, scriptCode, prevValue, SigHash.ALL, false);          
            
            // signing with our SSSig
            BigInteger m = k.calculateBigIntegerforMessage(hash.getBytes());
    		BigInteger[] sigParts = k.sign(m, sk);
    		ECDSASignature s = new ECDSASignature(sigParts[0], sigParts[1]);
    		s = s.toCanonicalised();
    		//TransactionSignature signature = new TransactionSignature(sigKey.sign(hash), SigHash.ALL, false); // here signing with bitcoinj's facility
    		TransactionSignature signature = new TransactionSignature(s, SigHash.ALL, false);
            
            input.setScriptSig(ScriptBuilder.createEmpty());
            input.setWitness(TransactionWitness.redeemP2WPKH(signature, sigKey));
        }
	    return dTx;
	    /*
	    TransactionInput input = new TransactionInput(params, null, new byte[] {}, prevOut);
	    
	    Script scriptCode = new ScriptBuilder()
                .data(ScriptBuilder.createOutputScript(LegacyAddress.fromKey(params, sigKey)).getProgram()).build();
	    
       // TransactionSignature signature = calculateWitnessSignature(0, sigKey, scriptCode, input.getValue(), SigHash.ALL, false);

		Sha256Hash sigHash = fromTx.hashForWitnessSignature(0, scriptCode, prevValue, SigHash.ALL, false);
		
		
        
		BigInteger m = k.calculateBigIntegerforMessage(sigHash.getBytes());
		BigInteger[] sigParts = k.sign(m, sk);
		
		ECKey privateKey = ECKey.fromPrivate(sk);
		ECDSASignature s = privateKey.sign(sigHash);
		
		//ECDSASignature s = new ECDSASignature(sigParts[0], sigParts[1]);
		s = s.toCanonicalised();
		TransactionSignature signature = new TransactionSignature(s, SigHash.ALL, false);
        
        input.setScriptSig(ScriptBuilder.createEmpty());
        input.setWitness(TransactionWitness.redeemP2WPKH(signature, sigKey));
	    
	    dTx.addInput(input);
		
		//TransactionInput dTxIn = dTx.getInput(new Long(1));
		System.out.println(sigHash);
		//dTx.addSignedInput(fromTxOut,privateKey);
		
		dTx.verify();
		
		
		return dTx;
		*/
	}
	
	
}
