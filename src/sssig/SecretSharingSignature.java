package sssig;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;


public interface SecretSharingSignature {
	
	//CryptoData[] keyGen(CryptoData param, ObjectInputStream in, ObjectOutputStream out, SecureRandom rand);  //This will be constructor.
	
	ECPoint getPublic();
	
	Object[] pSign(BigInteger m, ObjectInputStream in, ObjectOutputStream out) throws NoSuchAlgorithmException;
	
	Object[] complete(BigInteger phi1, BigInteger phi2);
	
	BigInteger reveal(Object[] signature, BigInteger phi);
	
	boolean verify(BigInteger m, ECPoint pk, BigInteger[] signature);
	
	 Object[] keygen2p(SecureRandom r, ObjectInputStream in, ObjectOutputStream out);
	
	
}
