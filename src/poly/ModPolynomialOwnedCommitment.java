package poly;

import java.math.BigInteger;

import zero_knowledge_proofs.ECOwnedPedersenCommitment;

public class ModPolynomialOwnedCommitment {
	
	public ECOwnedPedersenCommitment[] committedValues;
	public int[] committedValuesPositions;
	public BigInteger[] committedValuesPositionsBig;  //Probably always going to be null, but if committedValuesPositions is null, this may not be
	
	public BigInteger[] plaintextValues;
	
	public int[] plaintextValuesPositions;
	public BigInteger[] plaintextValuesPositionsBig;  //Probably always going to be null, but if plaintextValuesPositions is null, this may not be
	
	public ECOwnedPedersenCommitment[] coefficients;
}
