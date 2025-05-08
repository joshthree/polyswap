package poly;

import java.math.BigInteger;


public interface ModPolynomialInterface {
	
	//4 constructors:  Values, coefficients, random, and empty
	
//	/**
//	 * Adds a set of output values for the polynomial.  f(position[i]) = value[i]
//	 * 
//	 * @param values The values to be added
//	 * @param positions The position of the values to be added
//	 */
//	void addValues(BigInteger[] values, int[] positions);
//	
//	/**
//	 * Adds a set of output values for the polynomial.  f(position[i]) = value[i]
//	 * 
//	 * @param values The values to be added
//	 * @param positions The position of the values to be added
//	 */
//	void addValues(BigInteger[] values, BigInteger[] positions);
//	
//	/**
//	 * Sets the coefficients of the polynomial
//	 * 
//	 * @param coefficients
//	 */
//	void setCoefficients(BigInteger[] coefficients);
//

	/**
	 * 
	 * 
	 * @param x The argument x from f(x)
	 * @return f(x)
	 */
	BigInteger valueAt(int x);
	/**
	 * @param x The argument x from f(x)
	 * @return f(x)
	 */
	BigInteger valueAt(BigInteger x);  //Not sure if this is needed
	
//	/**
//	 * @param positions The arguments for f(positions[i])
//	 * @return An array of f(position[i]) values for all i
//	 */
//	BigInteger[] getValues(int[] positions);
//	/**
//	 * @param positions The arguments for f(positions[i])
//	 * @return An array of f(position[i]) values for all i
//	 */
//	BigInteger[] getValues(BigInteger[] positions);
	/**
	 * @return The array of coefficients
	 */
	BigInteger[] getCoefficients();
	
	
	/**
	 * @return The prime modulus of the polynomial
	 */
	BigInteger getModulus();
	/**
	 * 
	 * @return The order of the polynomial
	 */
	int getDegree();

	/**
	 *  Add points to the polynomial to make it solvable.
	 *  
	 * @param point = [position, value]
	 */
	void addPoint(BigInteger[] point);
}

//	void createValueCommitment(Random rand);
//	void createCoefficientCommitment(Random rand);
//	
//	
//	PolynomialInterface getCommitedVersion();

//	PolynomialInterface createCommitedVersion(int[] positions, boolean commitCoefficients, Random rand);
//	PolynomialInterface createCommitedVersion(BigInteger[] positions, boolean commitCoefficients, Random rand);
//	
//	ECOwnedPedersenCommitment getCommittedValue(int x, Random rand);
//	ECOwnedPedersenCommitment getCommittedValue(BigInteger x, Random rand);
//	ECOwnedPedersenCommitment getCommittedValue(int x);
//	ECOwnedPedersenCommitment getCommittedValue(BigInteger x);