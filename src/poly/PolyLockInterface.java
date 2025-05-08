package poly;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.CryptoData.CryptoData;

public interface PolyLockInterface extends Serializable {
	ZKPProtocol getProver();
	CryptoData buildPublicInputs(CryptoData[] environments);
	CryptoData buildProverData(CryptoData[] environments, SecureRandom rand);
	CryptoData buildEnvironment(CryptoData[] environments);
	
	boolean verifyHiddenValues(CryptoData[] myPublicFormsCopy, CryptoData[] environments);
	
	BigInteger[] release(int pos, BigInteger secret, CryptoData[] environments);
	
}
 