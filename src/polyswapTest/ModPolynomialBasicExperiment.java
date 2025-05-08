package polyswapTest;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.InputMismatchException;

import poly.ModPolynomial;
import zero_knowledge_proofs.ZKToolkit;

//This is made to recreate the experiment from the excel

public class ModPolynomialBasicExperiment {
	public static void main(String[] args) {
		BigInteger[] p = new BigInteger[3];

		BigInteger output;
		int outputPos;

		SecureRandom rand = new SecureRandom();
		ArrayList<BigInteger[]> negValues;

		{//Party 1 scope
			BigInteger[] values = new BigInteger[3];
//			p[0] = BigInteger.valueOf(5501);
//			System.out.println(BigInteger.ZERO.modPow(BigInteger.ZERO, p[0]));
			p[0] = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
			p[1] = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
//			p[2] = BigInteger.valueOf(3847);
			p[2] = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

			for(int i = 0; i < 3; i++) {
				//if(!p[i].isProbablePrime(50)) System.out.println(String.format("p[%d] = %s, which is not prime.", i, p[i]));
				values[i] = ZKToolkit.random(p[i], rand);
			}
			//		values[0] = BigInteger.valueOf(3047);
			//		values[1] = BigInteger.valueOf(31);
			//		values[2] = BigInteger.valueOf(782);
			int min = 0;
			for(int i = 1; i < p.length; i++) {
				if(p[min].compareTo(p[i]) == 1)
					min = i;
			}
			if(!p[min].isProbablePrime(50)) {
				throw new InputMismatchException("p min not prime");
			}
			int[] pStart = new int[p.length];

			//This loop has 3 purposes:  Determine degree of polynomial, determine where each number starts, and determine modulus of most significant digit
			int count = 0;
			BigInteger[] maxHighestOrderQuotient = new BigInteger[p.length];
			for(int i = 0; i < p.length; i++)
			{
				pStart[i] = count;

				if(i == min) {
					count++;
					maxHighestOrderQuotient[i] = p[i].subtract(BigInteger.ONE);
					continue;
				}
				BigInteger quotient = p[i].subtract(BigInteger.ONE);
				BigInteger[] temp;
				while(!BigInteger.ZERO.equals((temp = quotient.divideAndRemainder(p[min]))[0])) {
					count++;
					quotient = temp[0];
				}
				count++;
				maxHighestOrderQuotient[i] = quotient;
				// TODO: review this part
				if(!BigInteger.ZERO.equals(temp[1])) {
					maxHighestOrderQuotient[i] = maxHighestOrderQuotient[i].add(BigInteger.ONE);
				}
				
			}
			
			
			
			BigInteger[] polyValues = new BigInteger[count];
			System.out.println("p");
			System.out.println(p[0]);
			System.out.println(p[1]);
			System.out.println(p[2]);

//			System.out.println();


			System.out.println("values");
			System.out.println(values[0]);
			System.out.println(values[1]);
			System.out.println(values[2]);

			
			System.out.println();
			
			for(int i = 0; i < 3; i++) {
				System.out.printf("max highest quotient[%d] = %s\n", i, maxHighestOrderQuotient[i]);
			}
//			System.out.println();

			System.out.println("factor");
			for(int i = 0; i < p.length; i++) {
				int index = pStart[i];
				BigInteger[] quotientRemainder = values[i].divideAndRemainder(p[min]);
				while((i != p.length-1 && index < pStart[i+1]-1) || (i == p.length-1 && index < polyValues.length-1)){
					polyValues[index] = quotientRemainder[1];
					index++;
					quotientRemainder = quotientRemainder[0].divideAndRemainder(p[min]);
				}

				polyValues[index] = quotientRemainder[1];
//				System.out.println("Value at "+ index + ":  " + polyValues[index]);
				quotientRemainder = p[min].divideAndRemainder(maxHighestOrderQuotient[i]);
				BigInteger temp = quotientRemainder[0];
				
				if(!quotientRemainder[1].equals(BigInteger.ZERO)) {
					temp = temp.add(BigInteger.ONE);
				}
					
				BigInteger[] temp3 = p[min].divideAndRemainder(maxHighestOrderQuotient[i]);
				
//				temp3[0] = temp3[0].add(BigInteger.ONE);
				if(polyValues[index].compareTo(temp3[1]) == -1) {
					temp3[0] = temp3[0].add(BigInteger.ONE);
				}
				
				System.out.println(temp3[0]);
				polyValues[index] = polyValues[index].add(maxHighestOrderQuotient[i].multiply(ZKToolkit.random(temp3[0], rand)));
				
			}
			
			
			int degree = count - 1;
			System.out.println();

			System.out.println("polyValues");
			for(int i = 0; i < polyValues.length; i++) {
				System.out.print(polyValues[i] + ", ");
			}
			System.out.println();

			ArrayList<BigInteger[]> points = new ArrayList<BigInteger[]>();

			for(int i = 0; i < polyValues.length; i++) {
				points.add(new BigInteger[] {BigInteger.valueOf(i), polyValues[i]});
			}

			ModPolynomial poly = new ModPolynomial(points, p[min]);

			BigInteger[] coefficients = poly.getCoefficients();
			System.out.println();
			System.out.println("Coefficients");
			for(int i = 0; i < coefficients.length; i++) {
				System.out.print(coefficients[i] + ", ");
			}
			System.out.println();
			negValues = new ArrayList<BigInteger[]>();
			for(int i = 0; i < degree; i++) {
				negValues.add(new BigInteger[] {BigInteger.valueOf(-i-1),poly.valueAt(-i-1)});
				System.out.println((-i-1)+" or " + negValues.get(i)[0]+ ": " +negValues.get(i)[1]);
			}


			output = values[0];
			outputPos = 0;
			
			for(int i = 0; i < count; i++)
			{
				System.out.printf("f(%d) = %s OR %s\n", i, polyValues[i], poly.valueAt(i));
			}
		}
		{
//			for(BigInteger[] val : negValues) {
//				
//			}
			int min = 0;
			for(int i = 1; i < p.length; i++) {
				if(p[min].compareTo(p[i]) == 1)
					min = i;
			}
			int[] pStart = new int[p.length];

			int count = 0;

			BigInteger[] maxHighestOrderQuotient = new BigInteger[p.length];
			for(int i = 0; i < p.length; i++)
			{
				pStart[i] = count;

				if(i == min) {
					count++;
					maxHighestOrderQuotient[i] = p[i].subtract(BigInteger.ONE);
					continue;
				}
				BigInteger quotient = p[i].subtract(BigInteger.ONE);
				BigInteger[] temp;
				while(!BigInteger.ZERO.equals((temp = quotient.divideAndRemainder(p[min]))[0])) {
					count++;
					quotient = temp[0];
				}
				count++;
				maxHighestOrderQuotient[i] = quotient;

				if(!BigInteger.ZERO.equals(temp[1])) {
					maxHighestOrderQuotient[i] = maxHighestOrderQuotient[i].add(BigInteger.ONE);
				}
				
			}


			int degree = count - 1;
			ModPolynomial otherPoly = new ModPolynomial(negValues, degree, p[min]);
			BigInteger[] brokenNumber;
			{
				int i = outputPos;
				int index = pStart[i];
//				int counter = 0;
				brokenNumber = new BigInteger[2];
				System.out.println(brokenNumber.length);
				BigInteger[] quotientRemainder = output.divideAndRemainder(p[min]);
				//				do{
				brokenNumber[0] = BigInteger.valueOf(index);
				brokenNumber[1] = quotientRemainder[1];
				//					index++;
				//					counter++;
				//					quotientRemainder = quotientRemainder[0].divideAndRemainder(p[min]);
				//				}while(!quotientRemainder[0].equals(BigInteger.ZERO));
				//
				//				brokenNumber[counter][0] = quotientRemainder[1];
				//				brokenNumber[counter][1] = BigInteger.valueOf(index);
				//				quotientRemainder = p[min].divideAndRemainder(maxHighestOrderQuotient[i]);
				//				BigInteger temp = quotientRemainder[0];
				//
				//				if(!quotientRemainder[1].equals(BigInteger.ZERO)) {
				//					temp = temp.add(BigInteger.ONE);
				//				}
				//
				//				BigInteger[] temp2 = p[i].subtract(BigInteger.ONE).divideAndRemainder(p[min]);
				//
				//				if(!BigInteger.ZERO.equals(temp2[1])) {
				//					temp2[0] = temp2[0].add(BigInteger.ONE);
				//				}
				//
				//				System.out.println(temp2[0]);
				//
				//				BigInteger[] temp3 = p[min].divideAndRemainder(temp2[0]);
				//
				//				temp3[0] = temp3[0].add(BigInteger.ONE);
				//				if(polyValues[index].compareTo(temp3[1]) == -1) {
				//					temp3[0] = temp3[0].add(BigInteger.ONE);
				//				}
				//
				//				System.out.println(temp3[0]);
				//				polyValues[index] = polyValues[index].add(temp2[0].multiply(ZKToolkit.random(temp3[0], rand)));
				otherPoly.addPoint(brokenNumber);


			}
			System.out.println("negValues = " + negValues.size());
			System.out.println(degree);
			System.out.println(brokenNumber[1]);
			System.out.println();
			System.out.println(otherPoly.isSolvable());
			BigInteger[] values = new BigInteger[3];
			System.out.println(pStart[0]);
			System.out.println(pStart[1]);
			for(int i = 0; i < p.length; i++) {
				int index = pStart[i];
//				System.out.println("index = " + index);
				values[i] = otherPoly.valueAt(BigInteger.valueOf(index));
				
				int j;
				for(j = 1; (i == p.length-1 && j+index < degree) || (i != p.length-1 && j < (pStart[i+1] - pStart[i]) - 1); j++) {
//					System.out.println("j = " + j);
//					System.out.printf("%-5d:%s\n",j,values[i]);
					values[i] = values[i].add(
								otherPoly.valueAt(BigInteger.valueOf(index + j)).multiply(
										p[min].modPow(BigInteger.valueOf(j), p[i])
									)
							).mod(p[i]);
				}
				
				if((i != p.length-1 && pStart[i+1] - pStart[i] != 1) || (i == p.length-1 && index != degree)) {
//					System.out.println(maxHighestOrderQuotient[i]);
					values[i] = values[i].add(otherPoly.valueAt(BigInteger.valueOf(index + j)).mod(maxHighestOrderQuotient[i]).multiply(p[min].modPow(BigInteger.valueOf(j), p[i]))).mod(p[i]);
				}
				
				System.out.println("value[" + i + "] = " +  values[i]);
//				
//				System.out.println("\n-------------------------------------------------------------------------------");
//				System.out.println();
				
//				maxHighestOrderQuotient
				
			}
		}
	}
}
