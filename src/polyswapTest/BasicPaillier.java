package polyswapTest;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

public class BasicPaillier{

	public static void main(String[] args)
	{
		System.out.println("1");
		BigInteger publicExponent = BigInteger.valueOf(0x10001); 
		SecureRandom rnd = new SecureRandom();
		RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(publicExponent, rnd, 2048, 100);

		System.out.println("2");
		RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();

		System.out.println("3");
		rsaGen.init(params);

		System.out.println("4");
		AsymmetricCipherKeyPair kp = rsaGen.generateKeyPair();
		System.out.println("5");
		RSAPrivateCrtKeyParameters pri = (RSAPrivateCrtKeyParameters)kp.getPrivate();
		System.out.println("6");
		RSAKeyParameters pub = (RSAKeyParameters)kp.getPublic();
		System.out.println("7");

		BigInteger n = pri.getModulus();
		BigInteger n2 = n.pow(2);

		BigInteger p = pri.getP();

		BigInteger q = pri.getQ();

		BigInteger pm1 =  p.subtract(BigInteger.ONE);
		BigInteger qm1 =  q.subtract(BigInteger.ONE);

		SecureRandom rand = new SecureRandom();
		BigInteger lambda = pm1.divide(pm1.gcd(qm1)).multiply(qm1);
		BigInteger g = new BigInteger(n2.bitLength(), rand);
		g = n.add(BigInteger.ONE);
		while(g.compareTo(n) >= 0 && !g.gcd(n2).equals(BigInteger.ONE))
		{
			g = new BigInteger(n2.bitLength(), rand);
		}

		BigInteger mu = g.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).modInverse(n);

		BigInteger r1 = new BigInteger(n.bitLength(), rand);
		while(r1.compareTo(n) >= 0 && !r1.equals(BigInteger.ZERO) && !r1.gcd(n).equals(BigInteger.ONE))
		{
			r1 = new BigInteger(n.bitLength(), rand);
		}

		BigInteger r2 = new BigInteger(n.bitLength(), rand);
		while(r2.compareTo(n) >= 0 && !r2.equals(BigInteger.ZERO) && !r2.gcd(n).equals(BigInteger.ONE))
		{
			r2 = new BigInteger(n.bitLength(), rand);
		}
		BigInteger m = new BigInteger("5");
		BigInteger m2 = new BigInteger("10");
		//encryption
		BigInteger enc1 = r1.modPow(n, n2).multiply(g.modPow(m, n2)).mod(n2);
		BigInteger enc2 = r2.modPow(n, n2).multiply(g.modPow(m2, n2)).mod(n2);
		BigInteger enc = enc1.multiply(enc2).mod(n2);
		//decryption
		BigInteger mDecrypt = enc.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).multiply(mu).mod(n);
		System.out.println(mDecrypt);
		//	return new AKeyPair(new APrivateKey(pri), new APublicKey(pub));
		System.out.println(n.bitLength());
	}

}

