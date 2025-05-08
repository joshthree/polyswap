package poly;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.InputMismatchException;
import java.util.Set;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.ECOwnedPedersenCommitment;
import zero_knowledge_proofs.ECPedersenCommitment;
import zero_knowledge_proofs.ECSchnorrProver;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.ZeroKnowledgeOrProver;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class PolyLock implements PolyLockInterface{

	/**
	 * 
	 */
	private static final long serialVersionUID = 7386826010633805834L;

	private transient ModPolynomialInterface poly;
	
	private BigInteger[] orders;
	
	private CryptoData[] publicForms;
	
	private transient ECOwnedPedersenCommitment[] ownedCoefficientCommitments;
	private transient BigInteger[] coefficients;
	private ECPedersenCommitment[] coefficientCommitments;
	private transient ECOwnedPedersenCommitment[] ownedValueCommitments;
	private ECPedersenCommitment[] valueCommitments;
	private transient ECCurve[] curves;
	private BigInteger[] negValues;
	private transient ZKPProtocol prover;
	private transient ECPoint[][] generators;
	private boolean[] needsConversion;
	
	private ECPedersenCommitment[][][] bitwiseCommitments;
	private transient BigInteger[][][] bitwiseCommitmentKeys; 
	private ECPedersenCommitment[][] bitwiseCommitmentsCombined;
	private transient BigInteger[][] bitwiseCommitmentKeysCombined; 
	private transient BigInteger[][] keys;

	private int maxPos = 0;
	
	public PolyLock(CryptoData[] publicForm, BigInteger[] secrets, CryptoData[] environments, SecureRandom rand) {
		publicForms = publicForm.clone();
		
		orders = new BigInteger[environments.length];
		curves = new ECCurve[environments.length];
		ECPoint[][] generators = new ECPoint[environments.length][2];
		needsConversion = new boolean[environments.length];
		
		boolean sameOrder = false;
		
				
		for(int i = 0; i < environments.length; i++) {
			CryptoData[] e = environments[i].getCryptoDataArray();
			ECCurve c = e[0].getECCurveData();
			if(c != null)
			{
				curves[i] = c;
				generators[i][0] = e[0].getECPointData(c);
				generators[i][1] = e[1].getECPointData(c);
				
				orders[i] = c.getOrder();
				
				
				if(orders[i].compareTo(orders[maxPos]) == 0 && curves[i].equals(curves[maxPos])) {

					
					sameOrder = true;
				}
				if(orders[i].compareTo(orders[maxPos]) > 0) {
					maxPos = i;
					sameOrder = false;
				}
			}
			else throw new InputMismatchException("Only works for ellipic curves");		
		}
		if(sameOrder) {
			//If we are here, there are multiple curves of equal order.  In this event, we want the most common curve to be the curve we execute.
			ArrayList<ECCurve> list = new ArrayList<ECCurve>();
			int[] numCurves = new int[orders.length];
			for(int i = 0; i < orders.length; i++) {
				if(orders[i].equals(orders[maxPos])) {
					int pos = list.indexOf(curves[i]);
					if(pos == -1) {
						pos = list.size();
						list.add(curves[i]);
					}
					numCurves[pos]++;
				}
			}
			int max = 0;
			for(int i = 1; numCurves[i] != 0; i++) {
				if(numCurves[max] < numCurves[i]) max = i;
			}
			
			ECCurve mostCommonCurve = list.get(max);
			for(int i = 0; i < curves.length; i++) {
				if(mostCommonCurve.equals(curves[i])) {
					maxPos = i;
				}
			}
		}
		
		ArrayList<BigInteger[]> points = new ArrayList<BigInteger[]>(environments.length);
		for(int i = 0; i < environments.length; i++) {
			needsConversion[i] = !curves[i].equals(curves[maxPos]);
			points.add(new BigInteger[]{BigInteger.valueOf(i), secrets[i]});
		}
		
		poly = new ModPolynomial(points, orders[maxPos]);
		
		coefficients = poly.getCoefficients();
		
		ownedCoefficientCommitments = new ECOwnedPedersenCommitment[coefficients.length];
		coefficientCommitments = new ECPedersenCommitment[coefficients.length];
		
		for(int i = 0; i < coefficients.length; i++) {
			BigInteger key = ZKToolkit.random(orders[maxPos], rand);
			
			coefficientCommitments[i] = new ECPedersenCommitment(coefficients[i], key, environments[maxPos]);
			ownedCoefficientCommitments[i] = new ECOwnedPedersenCommitment();
			ownedCoefficientCommitments[i].comm = coefficientCommitments[i];
			ownedCoefficientCommitments[i].key = key;
			ownedCoefficientCommitments[i].message = coefficients[i];
			
		}
		valueCommitments = new ECPedersenCommitment[secrets.length];
		ownedValueCommitments = new ECOwnedPedersenCommitment[secrets.length];
		
		for(int i = 0; i < secrets.length; i++) {
			
			BigInteger key;
			if(needsConversion[i]) key = ZKToolkit.random(orders[maxPos], rand);
			else key = BigInteger.ZERO;
			
			valueCommitments[i] = new ECPedersenCommitment(secrets[i], key, environments[maxPos]);
			ownedValueCommitments[i] = new ECOwnedPedersenCommitment();
			ownedValueCommitments[i].comm = valueCommitments[i];
			ownedValueCommitments[i].key = key;
			ownedValueCommitments[i].message = secrets[i];
		}
		
		negValues = new BigInteger[secrets.length - 1];
		for(int i = 0; i < negValues.length; i++) {
			negValues[i] = poly.valueAt(-1-i);
		}
		
		//Now we create the proofs
		
		//First, we build the bitwise commitments when needed
		
		bitwiseCommitments = new ECPedersenCommitment[valueCommitments.length][][];
		bitwiseCommitmentKeys = new BigInteger[valueCommitments.length][][];
		
		//0 is maxPos, 1 is i
		for(int i = 0; i < valueCommitments.length; i++) {
			if(needsConversion[i]) {
				bitwiseCommitments[i] = new ECPedersenCommitment[orders[i].bitLength()][2];
				bitwiseCommitmentKeys[i] = new BigInteger[orders[i].bitLength()][2];

				for(int j = 0; j < bitwiseCommitments[i].length; j++) {
					BigInteger bit;
					if(secrets[i].testBit(j))
					{
						bit = BigInteger.ONE;
					}
					else bit = BigInteger.ZERO;
					bitwiseCommitmentKeys[i][j][0] = ZKToolkit.random(orders[maxPos], rand);
					bitwiseCommitmentKeys[i][j][1] = ZKToolkit.random(orders[i], rand);
					bitwiseCommitments[i][j][0] = new ECPedersenCommitment(bit, bitwiseCommitmentKeys[i][j][0], environments[maxPos]);
					bitwiseCommitments[i][j][1] = new ECPedersenCommitment(bit, bitwiseCommitmentKeys[i][j][1], environments[i]);
					
				}
			}
		}
		calculateCombinedValues(environments);
	}
	
	private void calculateCombinedValues(CryptoData[] environments)
	{
		if(bitwiseCommitmentsCombined != null) return;
		//j = 0 is the least significant bit.
		ECPedersenCommitment empty1 = new ECPedersenCommitment(BigInteger.ZERO, BigInteger.ZERO, environments[maxPos]);
		if(ownedCoefficientCommitments == null) {
			bitwiseCommitmentsCombined = new ECPedersenCommitment[valueCommitments.length][];
			
			for(int i = 0; i < bitwiseCommitments.length; i++) {

				if(bitwiseCommitments[i] == null) continue;
				ECPedersenCommitment empty2 = new ECPedersenCommitment(BigInteger.ZERO, BigInteger.ZERO, environments[i]);
				bitwiseCommitmentsCombined[i] = new ECPedersenCommitment[] {empty1, empty2};
				for(int j = 0; j < bitwiseCommitments[i].length; j++) {
					bitwiseCommitmentsCombined[i][0] = bitwiseCommitmentsCombined[i][0].multiplyShiftedCommitment(bitwiseCommitments[i][j][0], j, environments[maxPos]);
					bitwiseCommitmentsCombined[i][1] = bitwiseCommitmentsCombined[i][1].multiplyShiftedCommitment(bitwiseCommitments[i][j][1], j, environments[i]);
				}
			}
		}
		else {
			bitwiseCommitmentsCombined = new ECPedersenCommitment[valueCommitments.length][];
			bitwiseCommitmentKeysCombined = new BigInteger[valueCommitments.length][];
			for(int i = 0; i < bitwiseCommitments.length; i++) {

				if(bitwiseCommitments[i] == null) continue;
				ECPedersenCommitment empty2 = new ECPedersenCommitment(BigInteger.ZERO, BigInteger.ZERO, environments[i]);
				bitwiseCommitmentsCombined[i] = new ECPedersenCommitment[] {empty1, empty2};
				bitwiseCommitmentKeysCombined[i] = new BigInteger[] {BigInteger.ZERO, BigInteger.ZERO};
				for(int j = 0; j < bitwiseCommitments[i].length; j++) {
					bitwiseCommitmentsCombined[i][0] = bitwiseCommitmentsCombined[i][0].multiplyShiftedCommitment(bitwiseCommitments[i][j][0], j, environments[maxPos]);
					bitwiseCommitmentsCombined[i][1] = bitwiseCommitmentsCombined[i][1].multiplyShiftedCommitment(bitwiseCommitments[i][j][1], j, environments[i]);
					bitwiseCommitmentKeysCombined[i][0] = bitwiseCommitmentKeysCombined[i][0].add(bitwiseCommitmentKeys[i][j][0].multiply(BigInteger.ONE.shiftLeft(j))).mod(orders[maxPos]);
					bitwiseCommitmentKeysCombined[i][1] = bitwiseCommitmentKeysCombined[i][1].add(bitwiseCommitmentKeys[i][j][1].multiply(BigInteger.ONE.shiftLeft(j))).mod(orders[i]);
				}
			}
		}
		
		
	}
	


	@Override
	public BigInteger[] release(int pos, BigInteger secret, CryptoData[] environments) {
		ArrayList<BigInteger[]> list = new ArrayList<BigInteger[]>();
		
		ECPoint g = environments[pos].getCryptoDataArray()[0].getECPointData(environments[pos].getCryptoDataArray()[0].getECCurveData());
		
		if(!publicForms[pos].getECPointData(environments[pos].getCryptoDataArray()[0].getECCurveData()).equals(g.multiply(secret)))
		{
			System.out.println("Wrong value.");
			return null;
		}
	
		
		for(int i = 0; i < negValues.length; i++)
		{
			list.add(new BigInteger[] {BigInteger.valueOf(-1-i), negValues[i]});
		}
		list.add(new BigInteger[] {BigInteger.valueOf(pos), secret});
		poly = new ModPolynomial(list, orders[maxPos]);
		BigInteger[] toReturn = new BigInteger[list.size()];
		
		for(int i = 0; i < toReturn.length; i++) {
			toReturn[i] = poly.valueAt(i);
		}
		
		return toReturn;
	}

	@Override
	public ZKPProtocol getProver() {
		if(prover != null) return prover;
		ZKPProtocol schnorr = new ECSchnorrProver();
		ZKPProtocol[] outer = new ZKPProtocol[2];
		ZKPProtocol[] middle = new ZKPProtocol[valueCommitments.length];
		ZKPProtocol sameBit = new ZeroKnowledgeAndProver(new ZKPProtocol[]{schnorr, schnorr});
		ZKPProtocol inner = new ZeroKnowledgeOrProver(new ZKPProtocol[]{sameBit, sameBit});
		for(int i = 0; i < middle.length; i++) {
			
			if(needsConversion[i]) {
				ZKPProtocol[] innerMiddle = new ZKPProtocol[4];
				innerMiddle[0] = schnorr;
				innerMiddle[1] = schnorr;
				innerMiddle[2] = schnorr;
				ZKPProtocol[] baseConversion = new ZKPProtocol[orders[i].bitLength()];
				for(int j = 0; j < baseConversion.length; j++) {
					baseConversion[j] = inner;
				}
				innerMiddle[3] = new ZeroKnowledgeAndProver(baseConversion);
				middle[i] = new ZeroKnowledgeAndProver(innerMiddle);
			}
			else{
				middle[i] = schnorr;
			}
		}
		outer[0] = new ZeroKnowledgeAndProver(middle);
		middle = new ZKPProtocol[negValues.length];
		for(int i = 0; i < middle.length; i++) {
			middle[i] = schnorr;
		}
		outer[1] = new ZeroKnowledgeAndProver(middle);
		return prover = new ZeroKnowledgeAndProver(outer);
	}
	
	@Override
	public CryptoData buildPublicInputs(CryptoData[] environments) {
		calculateCombinedValues(environments);
		
		CryptoData[] outer = new CryptoData[2];
		CryptoData[] middle = new CryptoData[valueCommitments.length];
		//Positive values and group conversion
		ECPoint maxInf = environments[maxPos].getCryptoDataArray()[0].getECCurveData().getInfinity();
		ECPoint g = environments[maxPos].getCryptoDataArray()[0].getECPointData(environments[maxPos].getCryptoDataArray()[0].getECCurveData());
		for(int i = 0; i < middle.length; i++) {
			
			ECPoint commitmentFromCoefficients = maxInf;
			for(int j = 0; j < coefficientCommitments.length; j++) {
				commitmentFromCoefficients = commitmentFromCoefficients.add(coefficientCommitments[j].getCommitment(environments[maxPos]).multiply(BigInteger.valueOf(i).modPow(BigInteger.valueOf(j), orders[maxPos])));
			}
			if(needsConversion[i]) {
				CryptoData[] innerMiddle = new CryptoData[4];
				innerMiddle[0] = new CryptoDataArray(new ECPoint[] {commitmentFromCoefficients.subtract(valueCommitments[i].getCommitment(environments[maxPos]))});
				innerMiddle[1] = new CryptoDataArray(new ECPoint[] {bitwiseCommitmentsCombined[i][0].getCommitment(environments[maxPos]).subtract(valueCommitments[i].getCommitment(environments[maxPos]))});
				innerMiddle[2] = new CryptoDataArray(new ECPoint[] {bitwiseCommitmentsCombined[i][1].getCommitment(environments[i]).subtract(publicForms[i].getECPointData(environments[i].getCryptoDataArray()[0].getECCurveData()))});
				
				CryptoData[] baseConversion = new CryptoData[orders[i].bitLength()];
				for(int j = 0; j < baseConversion.length; j++) {
					CryptoData[] innerMid = new CryptoData[2];
					
					
						
					CryptoData[] temp = new CryptoData[2];
					temp[0] = new CryptoDataArray(new ECPoint[] {bitwiseCommitments[i][j][0].getCommitment(environments[maxPos])});
					temp[1] = new CryptoDataArray(new ECPoint[] {bitwiseCommitments[i][j][1].getCommitment(environments[i])});
					innerMid[0] = new CryptoDataArray(temp);
					
					temp = new CryptoData[2];
					
					temp[0] = new CryptoDataArray(new ECPoint[] {bitwiseCommitments[i][j][0].getCommitment(environments[maxPos]).subtract(g)});
					temp[1] = new CryptoDataArray(new ECPoint[] {bitwiseCommitments[i][j][1].getCommitment(environments[i]).subtract(environments[i].getCryptoDataArray()[0].getECPointData(environments[i].getCryptoDataArray()[0].getECCurveData()))});
					
					innerMid[1] = new CryptoDataArray(temp);
					baseConversion[j] = new CryptoDataArray(innerMid);
				}
				innerMiddle[3] = new CryptoDataArray(baseConversion);
				middle[i] = new CryptoDataArray(innerMiddle);
			}
			else {
				//calculate the value from the coefficients
				middle[i] = new CryptoDataArray(new ECPoint[] {commitmentFromCoefficients.subtract(valueCommitments[i].getCommitment(environments[maxPos]))});
			}
		}	

		outer[0] = new CryptoDataArray(middle);
		
		middle = new CryptoData[negValues.length];
		for(int i = 0; i < negValues.length; i++)
		{
			ECPoint commitmentFromCoefficients = maxInf;
			for(int j = 0; j < coefficientCommitments.length; j++) {
				commitmentFromCoefficients = commitmentFromCoefficients.add(coefficientCommitments[j].getCommitment(environments[maxPos]).multiply(BigInteger.valueOf(-1-i).modPow(BigInteger.valueOf(j), orders[maxPos])));
			}
			middle[i] = new CryptoDataArray(new ECPoint[] {commitmentFromCoefficients.subtract(g.multiply(negValues[i]))});
		}
		outer[1] = new CryptoDataArray(middle);
		return new CryptoDataArray(outer);
	}

	
	@Override
	public CryptoData buildProverData(CryptoData[] environments, SecureRandom rand) {
		if(ownedCoefficientCommitments == null) throw new InputMismatchException("This is lock is not owned by this party.");
		
		calculateCombinedValues(environments);
		
		CryptoData[] outer = new CryptoData[2];
		CryptoData[] middle = new CryptoData[valueCommitments.length];
		
		//Positive values and group conversion
		for(int i = 0; i < middle.length; i++) {
			
			BigInteger key = BigInteger.ZERO;
			for(int j = 0; j < coefficients.length; j++) {
				key = key.add(ownedCoefficientCommitments[j].key.multiply(BigInteger.valueOf(i).modPow(BigInteger.valueOf(j), orders[maxPos]))).mod(orders[maxPos]);
			}
			
			if(needsConversion[i]) {
				CryptoData[] innerMiddle = new CryptoData[4];
				
				
				innerMiddle[0] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[maxPos], rand), key.subtract(ownedValueCommitments[i].key).mod(orders[maxPos])});
				innerMiddle[1] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[maxPos], rand), bitwiseCommitmentKeysCombined[i][0].subtract(ownedValueCommitments[i].key).mod(orders[maxPos])});
				innerMiddle[2] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[i], rand), bitwiseCommitmentKeysCombined[i][1]});
				CryptoData[] baseConversion = new CryptoData[orders[i].bitLength()];
				for(int j = 0; j < baseConversion.length; j++) {
					CryptoData[] innerMid = new CryptoData[3];
					CryptoData[] innerChallenges = new CryptoData[2];
					
					
					if(!ownedValueCommitments[i].message.testBit(j)){
						innerChallenges[0] = new BigIntData(BigInteger.ZERO);
						innerChallenges[1] = new BigIntData(new BigInteger(255, rand));
						
						CryptoData[] temp = new CryptoData[2];
						temp[0] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[maxPos], rand), bitwiseCommitmentKeys[i][j][0]});
						temp[1] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[i], rand), bitwiseCommitmentKeys[i][j][1]});
						innerMid[0] = new CryptoDataArray(temp);
						
						temp = new CryptoData[2];
						
						temp[0] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[maxPos], rand)});
						temp[1] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[i], rand)});
						
						innerMid[1] = new CryptoDataArray(temp);
					}
					else{
						innerChallenges[0] = new BigIntData(new BigInteger(255, rand));
						innerChallenges[1] = new BigIntData(BigInteger.ZERO);
						
						CryptoData[] temp = new CryptoData[2];
						
						
						temp[0] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[maxPos], rand)});
						temp[1] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[i], rand)});
						
						temp = new CryptoData[2];
						
						temp[0] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[maxPos], rand), bitwiseCommitmentKeys[i][j][0]});
						temp[1] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[i], rand), bitwiseCommitmentKeys[i][j][1]});
						
						innerMid[0] = new CryptoDataArray(temp);
						innerMid[1] = new CryptoDataArray(temp);						
					}
					innerMid[2] = new CryptoDataArray(innerChallenges);
					baseConversion[j] = new CryptoDataArray(innerMid);
				}
				innerMiddle[3] = new CryptoDataArray(baseConversion);
				middle[i] = new CryptoDataArray(innerMiddle);
			}
			else{
				//calculate the value from the coefficients
				middle[i] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[maxPos], rand), key});
			}
		}
		outer[0] = new CryptoDataArray(middle);
		
		middle = new CryptoData[negValues.length];
		for(int i = 0; i < negValues.length; i++)
		{
			BigInteger key = BigInteger.ZERO;
			for(int j = 0; j < coefficients.length; j++) {
				key = key.add(ownedCoefficientCommitments[j].key.multiply(BigInteger.valueOf(-1-i).modPow(BigInteger.valueOf(j), orders[maxPos]))).mod(orders[maxPos]);
			}
			middle[i] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(orders[maxPos], rand), key});
		}
		outer[1] = new CryptoDataArray(middle);
		return new CryptoDataArray(outer);
	}
	@Override
	public CryptoData buildEnvironment(CryptoData[] environments) {
		CryptoData[] revEnvironments = new CryptoData[environments.length];
		for(int i = 0; i < environments.length; i++) {
			CryptoData[] temp = environments[i].getCryptoDataArray();
			ECCurve c = temp[0].getECCurveData();
			ECPoint g = temp[0].getECPointData(c);
			ECPoint h = temp[1].getECPointData(c);
			revEnvironments[i] = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, h), new ECPointData(g)});
		}
		CryptoData[] outer = new CryptoData[2];
		CryptoData[] middle = new CryptoData[valueCommitments.length];
		for(int i = 0; i < middle.length; i++) {
			
			if(needsConversion[i]) {
				CryptoData[] innerMiddle = new CryptoData[4];
				innerMiddle[0] = revEnvironments[maxPos];
				innerMiddle[1] = revEnvironments[maxPos];
				innerMiddle[2] = revEnvironments[i];
				CryptoData[] baseConversion = new CryptoData[orders[i].bitLength()];
				for(int j = 0; j < baseConversion.length; j++) {
					CryptoData[] innerMid = new CryptoData[2];
					
					
						
					CryptoData[] temp = new CryptoData[2];
					temp[0] = revEnvironments[maxPos];
					temp[1] = revEnvironments[i];
					innerMid[0] = innerMid[1] = new CryptoDataArray(temp);
					baseConversion[j] = new CryptoDataArray(innerMid);
				}
				innerMiddle[3] = new CryptoDataArray(baseConversion);
				middle[i] = new CryptoDataArray(innerMiddle);
			}
			else{
				middle[i] = revEnvironments[maxPos];
			}
		}
		outer[0] = new CryptoDataArray(middle);
		middle = new CryptoData[negValues.length];
		for(int i = 0; i < middle.length; i++) {
			middle[i] = revEnvironments[maxPos];
		}
		outer[1] = new CryptoDataArray(middle);
		return new CryptoDataArray(outer);
	}  

	@Override
	public boolean verifyHiddenValues(CryptoData[] myPublicFormsCopy, CryptoData[] environments) {
		for(int i = 0; i < publicForms.length; i++) {
			ECCurve c = environments[i].getCryptoDataArray()[0].getECCurveData();
			try{
				if(!orders[i].equals(c.getOrder()) || !(publicForms[i].getECPointData(c).equals(myPublicFormsCopy[i].getECPointData(c)))){
					return false;
				}
			}
			catch(Exception e) {
				System.out.println("Exceptions");
				return false;
			}
		}
		return true;
	}
	

}
