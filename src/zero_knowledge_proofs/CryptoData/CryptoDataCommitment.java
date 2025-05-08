package zero_knowledge_proofs.CryptoData;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;

import org.bouncycastle.math.ec.ECCurve;

import zero_knowledge_proofs.ZKToolkit;

public class CryptoDataCommitment {
	private ArrayList<CryptoData> commitments;
	private ArrayList<BigInteger> messages;
	private ArrayList<BigInteger> keys;
	private ArrayList<BigInteger> commitments2;

	
	protected CryptoDataCommitment(CryptoData c, CryptoData environment, SecureRandom rand) {

/*
 *    This is implemented for pedersen commitment scheme
 *    
 * 		BigInteger b = new BigInteger(c.getBytes());
		CryptoData[] e = environment.getCryptoDataArray();

		ECCurve curve = e[0].getECCurveData();
		ECPoint g = e[0].getECPointData(curve);
		ECPoint h = e[1].getECPointData(curve);
		BigInteger order = curve.getOrder();
		commitments = new ArrayList<CryptoData>((b.bitLength()/order.bitLength()) + 1);
		messages = new ArrayList<BigInteger>((b.bitLength()/order.bitLength()) + 1);
		keys = new ArrayList<BigInteger>((b.bitLength()/order.bitLength()) + 1);
		
		BigInteger[] part = b.divideAndRemainder(order);
		do {
			BigInteger key = ZKToolkit.random(order, rand);
			commitments.add(new ECPointData(g.multiply(part[1]).add(h.multiply(key))));
			keys.add(key);
			messages.add(part[1]);
			part = part[0].divideAndRemainder(order);
		}while(!part[0].equals(BigInteger.ZERO));
		
		if(!part[1].equals(BigInteger.ZERO)) {
			BigInteger key = ZKToolkit.random(order, rand);
			commitments.add(new ECPointData(g.multiply(part[1]).add(h.multiply(key))));
			keys.add(key);
			messages.add(part[1]);
		}
		System.out.println("messages:  " + messages.size());*/
		
		//implementation using hashing Com(x) = H(x||r)
		
		CryptoData[] e = environment.getCryptoDataArray();
		BigInteger b = new BigInteger(c.getBytes());
		ECCurve curve = e[0].getECCurveData();
		BigInteger order = curve.getOrder();
		
		commitments2 = new ArrayList<BigInteger>((b.bitLength()/order.bitLength()) + 1);
		messages = new ArrayList<BigInteger>((b.bitLength()/order.bitLength()) + 1);
		keys = new ArrayList<BigInteger>((b.bitLength()/order.bitLength()) + 1);
		
		
		
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-256");
			ByteArrayOutputStream outByte = new ByteArrayOutputStream();
			outByte.write(b.toByteArray());
			messages.add(b);
			
			BigInteger key = ZKToolkit.random(order, rand);
			keys.add(key);
			outByte.write(key.toByteArray());
			
			commitments2.add(new BigInteger(1,md.digest(outByte.toByteArray())));
		} catch (NoSuchAlgorithmException | IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
	}
	
	/*public ArrayList<CryptoData> getCommitments(){
		return new ArrayList<CryptoData>(commitments);
	}*/
	
	public ArrayList<BigInteger> getCommitments(){
		return new ArrayList<BigInteger>(commitments2);
	}
	
	public ArrayList<BigInteger> getMessages(){
		return new ArrayList<BigInteger>(messages);
	}
	public ArrayList<BigInteger> getKeys(){
		return new ArrayList<BigInteger>(keys);
	}
	
	/*public static boolean verifyCommitment(CryptoData plaintext, ArrayList<BigInteger> keys, ArrayList<CryptoData> commitments, CryptoData environment) {
		if(keys.size() != commitments.size()) return false;
		
		BigInteger b = new BigInteger(plaintext.getBytes());
		CryptoData[] e = environment.getCryptoDataArray();

		ECCurve curve = e[0].getECCurveData();
		ECPoint g = e[0].getECPointData(curve);
		ECPoint h = e[1].getECPointData(curve);
		BigInteger order = curve.getOrder();
		
		BigInteger[] part = b.divideAndRemainder(order);
		for(int i = 0; i < keys.size(); i++) {
			if(!g.multiply(part[1]).add(h.multiply(keys.get(i))).equals(commitments.get(i).getECPointData(curve))) return false;
			part = part[0].divideAndRemainder(order);
		}
		if(!part[1].equals(BigInteger.ZERO)) return false;
		return true;
	}
*/	
	public static boolean verifyCommitment(CryptoData plaintext, ArrayList<BigInteger> keys, ArrayList<BigInteger> commitments, CryptoData environment) throws NoSuchAlgorithmException, IOException {
		if(keys.size() != commitments.size()) return false;
		
		BigInteger b = new BigInteger(plaintext.getBytes());
		CryptoData[] e = environment.getCryptoDataArray();

		MessageDigest md;
		BigInteger rehash;
		
		md = MessageDigest.getInstance("SHA-256");
		ByteArrayOutputStream outByte = new ByteArrayOutputStream();
		outByte.write(b.toByteArray());
		
		
		BigInteger key = keys.get(0);
		
		outByte.write(key.toByteArray());
		
		rehash = new BigInteger(1,md.digest(outByte.toByteArray()));
		
		return (commitments.get(0).equals(rehash));
	}
}
