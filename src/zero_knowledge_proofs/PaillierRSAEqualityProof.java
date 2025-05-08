package zero_knowledge_proofs;

import java.math.BigInteger;
import java.security.SecureRandom;

import zero_knowledge_proofs.CryptoData.CryptoData;

public class PaillierRSAEqualityProof extends ZKPProtocol{

	
	public static void fillInputs(CryptoData publicInput, CryptoData secrets, CryptoData environment, SecureRandom rand){
		CryptoData[] pubInputsArray = publicInput.getCryptoDataArray();
		CryptoData[] secretsArray = secrets.getCryptoDataArray();
		CryptoData[] environmentArray = environment.getCryptoDataArray();
		
		BigInteger m = secretsArray[0].getBigInt();
		
		BigInteger e = environmentArray[0].getBigInt();
		BigInteger n = environmentArray[1].getBigInt();
		BigInteger g = environmentArray[2].getBigInt();
		
		BigInteger n2 = n.multiply(n);
		
		int eLength = e.bitLength();
		CryptoData[] intermediatePublic = new CryptoData[eLength+1];
		CryptoData[] intermediateSecret = new CryptoData[eLength+1];
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
 
	@Override
	public boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge,
			CryptoData environment) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public CryptoData initialComm(CryptoData input, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData initialComm(CryptoData publicInput, CryptoData secrets, CryptoData environment) 
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		
		//publicInput = [RSA ciphertext, Paillier Ciphertext, Array of intermediate ciphertexts].
		//secrets = [m, d, phi (order n), r, array of intermediate secrets]
		//environment = [e, n, g]
		return ;
	}

	@Override
	public CryptoData initialCommSim(CryptoData input, BigInteger challenge, CryptoData environment)
			throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData initialCommSim(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment)
			throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData calcResponse(CryptoData input, BigInteger challenge, CryptoData environment)
			throws NoTrueProofException, MultipleTrueProofException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData calcResponse(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment) throws NoTrueProofException, MultipleTrueProofException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData simulatorGetResponse(CryptoData input) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData simulatorGetResponse(CryptoData publicInput, CryptoData secrets) {
		// TODO Auto-generated method stub
		return null;
	}
	
}
