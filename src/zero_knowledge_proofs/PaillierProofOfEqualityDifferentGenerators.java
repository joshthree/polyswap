package zero_knowledge_proofs;

import java.math.BigInteger;

import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class PaillierProofOfEqualityDifferentGenerators extends ZKPProtocol {


	@Override
	public CryptoData initialComm(CryptoData input, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {	//depricated
		return null;
	}
	@Override
	public CryptoData initialCommSim(CryptoData input, BigInteger challenge, CryptoData environment)
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
	public CryptoData simulatorGetResponse(CryptoData input) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData initialComm(CryptoData publicInput, CryptoData secrets, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {

		if (publicInput == null || secrets == null) return null;
		try {
			BigInteger[] data = new BigInteger[2];
			CryptoData[] e = environment.getCryptoDataArray();  // e = [n, n^2, g1, g2]
			CryptoData[] s = secrets.getCryptoDataArray();		// s = [r1p, r2p, mp, r1, r2, m]

			BigInteger g1 = e[2].getBigInt();
			BigInteger g2 = e[3].getBigInt();
			BigInteger n = e[0].getBigInt();
			BigInteger n2 = e[1].getBigInt();
			
			BigInteger r1p = s[0].getBigInt();
			BigInteger r2p = s[1].getBigInt();
			BigInteger mp = s[2].getBigInt();
			data[0] = g1.modPow(mp,n2).multiply(r1p.modPow(n, n2)).mod(n2);
			data[1] = g2.modPow(mp,n2).multiply(r2p.modPow(n, n2)).mod(n2);
			CryptoData toReturn = new CryptoDataArray(data);
			return toReturn;
		} catch (NullPointerException e) {
			e.printStackTrace();
			System.out.println(publicInput);
			System.out.println(secrets);
			System.out.println(environment);
			throw new NullPointerException(e.getMessage());
		
		}
		
	}

	
	@Override
	public CryptoData initialCommSim(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment)
					throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {
		if (publicInput == null || secrets == null) return null;
		try {
			BigInteger[] data = new BigInteger[2];
			CryptoData[] e = environment.getCryptoDataArray();  // e = [g1, g2, n, n^2]
			CryptoData[] i = publicInput.getCryptoDataArray();	// i = [cipher1, cipher2]
			CryptoData[] s = secrets.getCryptoDataArray();		// s = [z1, z2, z3]

			BigInteger g1 = e[2].getBigInt();
			BigInteger g2 = e[3].getBigInt();
			BigInteger n = e[0].getBigInt();
			BigInteger n2 = e[1].getBigInt();
			
			BigInteger cipher1 = i[0].getBigInt();
			BigInteger cipher2 = i[1].getBigInt();
			
			BigInteger z1 = s[0].getBigInt();
			BigInteger z2 = s[1].getBigInt();
			BigInteger z3 = s[2].getBigInt();
			
			data[0] = (g1.modPow(z1, n2).multiply(z2.modPow(n, n2)).mod(n).multiply(cipher1.modPow(challenge.negate(), n2))).mod(n2);
			data[1] = (g2.modPow(z1, n2).multiply(z3.modPow(n, n2)).mod(n).multiply(cipher2.modPow(challenge.negate(), n2))).mod(n2);
			CryptoData toReturn = new CryptoDataArray(data);
			return toReturn;
		} catch (NullPointerException e) {
			e.printStackTrace();
			System.out.println(publicInput);
			System.out.println(secrets);
			System.out.println(environment);
			throw new NullPointerException(e.getMessage());
		}
	}
	
	@Override
	public CryptoData calcResponse(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment) throws NoTrueProofException, MultipleTrueProofException {
		if(publicInput == null || secrets == null) return null;
		BigInteger[] array = new BigInteger[3];
		CryptoData[] s = secrets.getCryptoDataArray();
		CryptoData[] e = environment.getCryptoDataArray();

		BigInteger r1 = s[3].getBigInt();
		BigInteger r2 = s[4].getBigInt();
		BigInteger m = s[5].getBigInt();		
		BigInteger r1p = s[0].getBigInt();	
		BigInteger r2p = s[1].getBigInt();
		BigInteger mp = s[2].getBigInt(); 
		
		BigInteger n = e[0].getBigInt();
		BigInteger n2 = e[1].getBigInt();
		
		array[0] = mp.add(m.multiply(challenge).mod(n2)).mod(n2);
		array[1] = r1p.multiply(r1.modPow(challenge, n)).mod(n);  //r'*r^e
		array[2] = r2p.multiply(r2.modPow(challenge, n)).mod(n);  //r'*r^e
		return new CryptoDataArray(array);
	}


	@Override
	public CryptoData simulatorGetResponse(CryptoData publicInput, CryptoData secrets) {
		if(secrets == null) return null;
		CryptoData[] in = secrets.getCryptoDataArray();
		BigInteger[] out = new BigInteger[3];
		out[0] = in[0].getBigInt();
		out[1] = in[1].getBigInt();
		out[2] = in[2].getBigInt();
		return new CryptoDataArray(out); 
	}

	@Override
	public boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge,
			CryptoData environment) {
		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] resp = z.getCryptoDataArray();
		CryptoData[] i = input.getCryptoDataArray();
		CryptoData[] a_pack = a.getCryptoDataArray();

		BigInteger g1 = e[2].getBigInt();
		BigInteger g2 = e[3].getBigInt();
		BigInteger n = e[0].getBigInt();
		BigInteger n2 = e[1].getBigInt();

		BigInteger cipher1 = i[0].getBigInt();
		BigInteger cipher2 = i[1].getBigInt();
		
		BigInteger a1 = a_pack[0].getBigInt();
		BigInteger a2 = a_pack[1].getBigInt();
		BigInteger z1 = resp[0].getBigInt();
		BigInteger z2 = resp[1].getBigInt();
		BigInteger z3 = resp[2].getBigInt();

		BigInteger side1 = g1.modPow(z1, n2).multiply(z2.modPow(n, n2)).mod(n2);
		BigInteger side2 = cipher1.modPow(challenge,n2).multiply(a1).mod(n2);
		
		if(side1.compareTo(side2) != 0) {
			System.out.printf("Error 1:  %s != %s\n", side1, side2);
			System.out.printf("n = %s, n2 = %s\n", n, n2);
			return false;
		}
		side1 = g2.modPow(z1, n2).multiply(z3.modPow(n, n2)).mod(n2);
		side2 = cipher2.modPow(challenge,n2).multiply(a2).mod(n2);
		
		if(side1.compareTo(side2) != 0) {
			System.out.printf("Error 2:  %s != %s\n", side1, side2);
			return false;
		}
		return true;
	}

}
