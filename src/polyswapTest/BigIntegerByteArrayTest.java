package polyswapTest;

import java.math.BigInteger;

public class BigIntegerByteArrayTest{
	 
    public static void main(String[] args)
    {
    	BigInteger blah = BigInteger.valueOf(4532);
    	byte[] blahBytes = blah.toByteArray();
    	System.out.println(blahBytes.length);
    	for(int i = 0; i < blahBytes.length; i++) {
    		System.out.println(blahBytes[i]);
    	}

    	for(int i = 0; i < blahBytes.length; i++) {
    		for(int j = 0; j < 8; j++) {
    			System.out.println((blahBytes[i] | 1 << j) / Math.pow(2, j));	
    		}
    	}
    }
 
  
 
}