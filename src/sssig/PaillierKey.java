package sssig;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.InputMismatchException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

public class PaillierKey implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 6434330043004881397L;

	private BigInteger n;
	private transient BigInteger n2,g;
	private BigInteger p,q;
	private transient BigInteger lambda,mu, pm1, qm1;
	
	public PaillierKey(int nBits, SecureRandom rand) {
		BigInteger publicExponent = BigInteger.valueOf(0x10001); //unused for Paillier
		SecureRandom rnd = new SecureRandom();
		RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(publicExponent, rnd, nBits, 100);
		
		RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
		
		rsaGen.init(params);
		
		AsymmetricCipherKeyPair kp = rsaGen.generateKeyPair();
		RSAPrivateCrtKeyParameters pri = (RSAPrivateCrtKeyParameters)kp.getPrivate();
//		RSAKeyParameters pub = (RSAKeyParameters)kp.getPublic();
		
		n = pri.getModulus();
		n2 = n.pow(2);
		
		p = pri.getP();
		
		q = pri.getQ();
		
		pm1 =  p.subtract(BigInteger.ONE);
		qm1 =  q.subtract(BigInteger.ONE);
		
		lambda = pm1.divide(pm1.gcd(qm1)).multiply(qm1);
		g = n.add(BigInteger.ONE);

		mu = g.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).modInverse(n);
	}
	private PaillierKey(boolean isPrivate, PaillierKey orig) {
		if(isPrivate) {
			if(!orig.isPrivate()) {
				throw new InputMismatchException("Original Key is not private.");
			}
			p = orig.p;
			q = orig.q;
			lambda = orig.lambda;
			mu = orig.mu;
		}
		else {
			p = null;
			q = null;
			lambda = null;
			mu = null;
		}
		n = orig.n;
		n2 = orig.n2;
		g = orig.g;
	}
	public boolean isPrivate() {
		return p != null && q != null;
	}
	
	public PaillierKey getPublicKey()
	{
		return new PaillierKey(false, this);
	}
	
	public BigInteger encrypt(BigInteger message, SecureRandom rand) {
		if(n2 == null) n2 = n.pow(2);
		if(g == null) g = n.add(BigInteger.ONE);
		BigInteger r1 = new BigInteger(n.bitLength(), rand);
		while(r1.compareTo(n) >= 0 && !r1.equals(BigInteger.ZERO) && !r1.gcd(n).equals(BigInteger.ONE))
		{
			r1 = new BigInteger(n.bitLength(), rand);
		}
		//System.out.println(g);
		BigInteger enc1 = r1.modPow(n, n2).multiply(g.modPow(message, n2)).mod(n2);
		return enc1;
	}

	public BigInteger encrypt(BigInteger message, BigInteger r) {
		if(n2 == null) n2 = n.pow(2);
		
		BigInteger enc1 = r.modPow(n, n2).multiply(g.modPow(message, n2)).mod(n2);
		return enc1;
	}

	public BigInteger decrypt(BigInteger cipher) {
		if(!isPrivate()) throw new InputMismatchException("Key is not private."); 
		getNSquared();
		getLambda();
		getMu();
		if(mu == null) mu = g.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).modInverse(n);
		
		BigInteger toReturn = cipher.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).multiply(mu).mod(n);
		
		return toReturn;
	}
	
	public BigInteger getN() {
		return n;
	}
	public BigInteger getP() {
		return p;
	}
	public BigInteger getQ() {
		return q;
	}
	public BigInteger getNSquared() {
		if(n2 == null) {
			n2 = n.pow(2);
		}
		return n2;
	}
	public BigInteger getLambda() {
		if(!isPrivate()) throw new InputMismatchException("Key is not private.");
		if(lambda == null) {
			pm1 =  p.subtract(BigInteger.ONE);
			qm1 =  q.subtract(BigInteger.ONE);
			lambda = pm1.divide(pm1.gcd(qm1)).multiply(qm1);
		}
		return lambda;
	}
	public BigInteger getMu() {
		if(!isPrivate()) throw new InputMismatchException("Key is not private.");
		getLambda();
		if(mu == null) {
			mu = g.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).modInverse(n);
		}
	
		return mu;
	}
}
