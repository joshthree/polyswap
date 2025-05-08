package poly;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import utils.Matrix;
import utils.MatrixInterface;

public class ModPolynomial implements ModPolynomialInterface {
	
	private ArrayList<BigInteger[]> points; // points[0] = [position, value]
	private BigInteger[] coefficients = null; // coefficients of the highest degree term first
	private BigInteger modulus;
	private final int degree;
	private static HashMap<BigInteger, Boolean> primeList = new HashMap<BigInteger, Boolean>();
	
	public ModPolynomial(int degree, BigInteger prime) {
		this.degree = degree;
		this.points = new ArrayList<BigInteger[]>();
		this.coefficients = new BigInteger[degree+1];
		Boolean check = primeList.get(prime);
		if (check == null) {
			check = prime.isProbablePrime(50);
			primeList.put(prime, check);
		}
		if(!check) throw new UnsupportedOperationException("prime is not prime");
		this.modulus = prime;
	}
	
	
	public ModPolynomial(BigInteger[] coeff, BigInteger prime) {
		this.degree = coeff.length - 1;
		this.coefficients = coeff.clone();

		this.points = new ArrayList<BigInteger[]>();
		Boolean check = primeList.get(prime);
		if (check == null) {
			check = prime.isProbablePrime(50);
			primeList.put(prime, check);
		}
		if(!check) throw new UnsupportedOperationException("prime is not prime");
		this.modulus = prime;
		
		
	}
	
	public ModPolynomial(ArrayList<BigInteger[]> points, int degree, BigInteger prime) {
		this.degree = degree;

		this.points = new ArrayList<BigInteger[]>(points);
		if(points.size() > degree+1) throw new UnsupportedOperationException("Too many points.  " + points.size() + " points for a "+degree+"-degree polynomial, more than maximum " + (degree+1) + " points.");
		this.coefficients = new BigInteger[degree+1];
		Boolean check = primeList.get(prime);
		if (check == null) {
			check = prime.isProbablePrime(50);
			primeList.put(prime, check);
		}
		if(!check) throw new UnsupportedOperationException("prime is not prime");
		this.modulus = prime;
		if(isSolvable()) {
			solve();
		}
	}
	
	public ModPolynomial(ArrayList<BigInteger[]> points, BigInteger prime) {
		this.degree = points.size()-1;

		this.points = new ArrayList<BigInteger[]>(points);
		this.coefficients = new BigInteger[degree+1];
		
		Boolean check = primeList.get(prime);
		if (check == null) {
			check = prime.isProbablePrime(50);
			primeList.put(prime, check);
		}
		if(!check) throw new UnsupportedOperationException("prime is not prime");
		this.modulus = prime;
		solve();
	}
	
	
	

	@Override
	public void addPoint(BigInteger[] point) {

		if(point.length != 2) throw new UnsupportedOperationException("Error in point format.");
		if(isDuplicate(point)){
			System.out.println("Duplicate point");
		} else {
			if(isSolvable()) throw new UnsupportedOperationException("Too many points.  " + (points.size()  + 1) + " points for a "+degree+"-degree polynomial, more than maximum " + (degree+1) + " points.");
			points.add(point);
		}

		if(isSolvable()) {
			solve();
		}
	}
	
	private boolean isDuplicate(BigInteger[] testPoint) {
		for (BigInteger[] point: this.points) {
			if (point[0] == testPoint[0]) {
				return true;
			}
		}
		return false;
	}
	
	public boolean isSolvable() {
		if (points.size() - 1 == degree) return true;
		return false;
	}
	
	public BigInteger[] solve() {
		if(!isSolvable()) throw new UnsupportedOperationException("Cannot solve not enough information");
		//if(this.coefficients != null) return this.coefficients;
		BigInteger[] positions = new BigInteger[points.size()];
		BigInteger[][] valueMatrix = new BigInteger[points.size()][1];
		{
			int i = 0;
			for (BigInteger[] point: this.points) {
				valueMatrix[i][0] = point[1];
				positions[i] = point[0];
				i++;
			}
		}
		Matrix values_ = new Matrix(valueMatrix, modulus);
		
		BigInteger[][] multiplierMatrix = new BigInteger[positions.length][positions.length];
		for (int j = 0; j < positions.length; j++) {
			BigInteger[] temp = new BigInteger[positions.length];
			for (int k = 1; k < positions.length; k++) {
				temp[k] = positions[j].modPow(BigInteger.valueOf(k), modulus);
			}
			temp[0] = BigInteger.ONE;
			multiplierMatrix[j] = temp;
		}
		Matrix multiplier_ = new Matrix(multiplierMatrix, modulus);

		MatrixInterface coeff = values_.multiply(multiplier_.getInverse());

		BigInteger[][] res =  coeff.getMatrix();
		
		for (int l = 0; l < res.length; l++) {
			this.coefficients[l] = res[l][0];
		}
		
		return this.coefficients.clone();
	}

	
	@Override
	public BigInteger valueAt(int x) {
		return valueAt(BigInteger.valueOf(x));
	}

	@Override
	public BigInteger valueAt(BigInteger x) {
		BigInteger res = BigInteger.ZERO;
		int i = 0;
		for (BigInteger coeff : this.coefficients) {
			res = res.add(coeff.multiply(x.modPow(BigInteger.valueOf(i), modulus)).mod(modulus)).mod(modulus); 
			i++;
		}
		return res;
	}

	
	@Override
	public BigInteger[] getCoefficients() {
		// TODO Auto-generated method stub
		return this.coefficients;
	}

	@Override
	public BigInteger getModulus() {
		// TODO Auto-generated method stub
		return this.modulus;
	}

	@Override
	public int getDegree() {
		// TODO Auto-generated method stub
		return this.degree;
	}


	
}
