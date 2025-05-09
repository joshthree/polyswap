xpackage concealed_timelocked_puzzle;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;

public class ConcealedPuzzle implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = -2628521880739148168L;
	private BigInteger c1;
	private BigInteger c2;
	private BigInteger c3;
	private BigInteger c4;
	private BigInteger c5;
	private BigInteger c6;
	
	private BigInteger[][] proof3C;
	private BigInteger[][] proof4C;
	
	private CryptoData[] transcript1;
	
	
	public ConcealedPuzzle(BigInteger difficulty, BigInteger message, BigInteger messageR, BigInteger lockingValue, BigInteger lockingValueR, BigInteger rsaE, BigInteger rsaN, BigInteger rsaOrder, SecureRandom rand) {
		c1 = message.modPow(rsaE, rsaN);
		c2 = lockingValue.modPow(rsaE, rsaN);
		BigInteger modifiedDifficulty = BigInteger.TWO.modPow(difficulty, rsaOrder);
		c3 = c2.modPow(c2, modifiedDifficulty);
		BigInteger nP1 = rsaN.add(BigInteger.ONE);
		BigInteger nSquared = rsaN.pow(2);
		c4 = nP1.modPow(message, nSquared).multiply(messageR.modPow(rsaN, nSquared)).mod(nSquared);
		c5 = nP1.modPow(lockingValue, nSquared).multiply(lockingValueR.modPow(rsaN, nSquared)).mod(nSquared);
		c6 = message.multiply(lockingValue.modPow(modifiedDifficulty, rsaN)).mod(rsaN);
		
		
		//Now, proof transcripts must be created.  We will use the Fiat Shamir heuristic to create the challenges.
		createRPEroof(c1, c4, rand);
		
		
	}
	public void createRPEProof(BigInteger rsa, BigInteger pailier, BigInteger n, BigInteger n2, BigInteger g, BigInteger e, SecureRandom rand){
		
		
		int eLength = e.bitLength();
		CryptoData[] cPrimeProof5aPublic = new CryptoData[eLength+1];
		CryptoData[] cPrimeProof5aSecret = new CryptoData[eLength+1];
		CryptoData[] intermediatePublic5b = new CryptoData[e.bitCount()];
		CryptoData[] intermediateSecret5b = new CryptoData[e.bitCount()];
		BigInteger cIMinus1 = g;
		BigInteger cPrimeIMinus1;
		BigInteger muIMinus1 = BigInteger.ONE;
		BigInteger rhoIMinus1 = BigInteger.ONE;
		
		
		for(int i = 0; i < e.bitLength(); i++) {
			//First, save C'_i in first location.

			BigInteger muI;
			BigInteger rhoI;
			BigInteger gamma = ZKToolkit.random(n, rand);
			BigInteger cPrimeI = cIMinus1.modPow(muIMinus1, n2).multiply(gamma.modPow(n, n2)).mod(n2);
			
			//Now, create CryptoData for PEP (5a in paper)
			CryptoData[] unpackedPublicInputs = new CryptoData[2];
			
			
			
			BigInteger cI;
			if(e.testBit((e.bitLength()-1)-i)) { //if the bit is equal to 1
				BigInteger betaI = ZKToolkit.random(n, rand);
				cI = cPrimeI.modPow(m, n2).multiply(betaI.modPow(n, n2)).mod((n2));
				muI = muIMinus1.modPow(BigInteger.TWO, n).multiply(m).mod(n);
				rhoI = rhoIMinus1.modPow(muIMinus1, n).multiply(gamma).mod(n).modPow(m, n);
				
				//Now, I need to prepare CryptoData for the Paillier 
			}
			else System.out.print(0);
		}
    }
}
