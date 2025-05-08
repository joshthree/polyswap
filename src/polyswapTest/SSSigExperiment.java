package polyswapTest;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import sssig.SSSCRYPTO;
import sssig.SSSECDSA;
import sssig.SSSSCHNORR;
import sssig.SecretSharingSignature;
import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.InvalidStringFormatException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;

public class SSSigExperiment {
	public static void main(String[] args) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, SecurityException, InvalidStringFormatException, IOException, ClassNotFoundException, MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException, NoSuchAlgorithmException{
		int id = 1;
		int iterations = 100;
		
		if(args.length == 3) {
			iterations = Integer.parseInt(args[2]);
		}else {
			args = new String[2];
			args[0] = "127.0.0.1";
			args[1] = "9999";
			
		}
		String message = "0100000001344630cbff61fbc362f7e1ff2f11a344c29326e4ee96e787dc0d4e5cc02fd069000000004a493046022100ef89701f460e8660c80808a162bbf2d676f40a331a243592c36d6bd1f81d6bdf022100d29c072f1b18e59caba6e1f0b8cadeb373fd33a25feded746832ec179880c23901ffffffff0100f2052a010000001976a914dd40dedd8f7e37466624c4dacc6362d8e7be23dd88ac00000000"; 
	
		ServerSocket host = null;
		Socket s;
		ObjectInputStream in;
		ObjectOutputStream out;

		try {
			SocketAddress dest = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
			s = new Socket();
			s.connect(dest);
			id = 2;
			System.out.println("Connection to Server successful");
			in = new ObjectInputStream(s.getInputStream());
			out = new ObjectOutputStream(s.getOutputStream());
		}
		catch(Exception e){
			System.out.println("Connection not open, opening server");
			try {
				host = new ServerSocket(Integer.parseInt(args[1]));
				s = host.accept();
				if(args[0].equals(s.getInetAddress().getHostAddress())){
					System.out.println("");
				}
				System.out.println("Connection established");
				out = new ObjectOutputStream(s.getOutputStream());
				in = new ObjectInputStream(s.getInputStream());
			}
			catch( java.net.BindException ex)
			{
				SocketAddress dest = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
				s = new Socket();
				s.connect(dest);
				System.out.println("Connection to Server successful");
				in = new ObjectInputStream(s.getInputStream());
				out = new ObjectOutputStream(s.getOutputStream());
			}
		}
		
//		System.out.println("ECDSA " + timeAlgos(id, in, out, 1, 1) + " ms");
//		System.out.println("Crytonote " + timeAlgos(id, in, out, 2, 1) + " ms");
//		System.out.println("Schnorr " + timeAlgos(id, in, out, 3, 1)+ " ms");
		
		ecdsa(id, in, out, iterations,message, false);
		ecdsa(id, in, out, iterations,message, true);
		
		cryptonote(id, in, out, iterations, message, false);
		cryptonote(id, in, out, iterations, message, true);
//		
		schnorr(id, in, out, iterations, message, false);
		schnorr(id, in, out, iterations, message, true);
//		
//		System.out.println("ECDSA Keygen (ms):" + timeAlgos(id, in, out, 1, iterations));
//		System.out.println("Schnoor Keygen (ms):" + timeAlgos(id, in, out, 2, iterations));
//		System.out.println("Crypto Keygen (ms):" + timeAlgos(id, in, out, 3, iterations));
		
	}
	
	private static void cryptonote(int id, ObjectInputStream in, ObjectOutputStream out, int iterations, String message, boolean zkp) {
		//String message = "0100000001344630cbff61fbc362f7e1ff2f11a344c29326e4ee96e787dc0d4e5cc02fd069000000004a493046022100ef89701f460e8660c80808a162bbf2d676f40a331a243592c36d6bd1f81d6bdf022100d29c072f1b18e59caba6e1f0b8cadeb373fd33a25feded746832ec179880c23901ffffffff0100f2052a010000001976a914dd40dedd8f7e37466624c4dacc6362d8e7be23dd88ac00000000"; 
		System.out.println("Running Cyrptonote-based SSSig for " + iterations + " iterations...with ZKP = " + zkp);
		final int ITERATIONS = iterations;
		long totalTime0 = 0, totalTime1= 0,totalTime2=0,totalTime3 = 0;
		int comSize = 0;
		try {
			SSSCRYPTO test3 = new SSSCRYPTO(id, zkp);
			final long startTime0 = System.currentTimeMillis();
			test3.keygen2p(new SecureRandom(), in, out);
			final long endTime0 = System.currentTimeMillis();
			totalTime0 = (endTime0 - startTime0);
			
			Object[][] a3 = new Object[ITERATIONS][];
			final long startTime1 = System.currentTimeMillis();
			for(int i = 0; i < ITERATIONS; i++) {
				a3[i] = test3.pSign(new BigInteger(message.getBytes()), in, out);
//				if (id == 2) {
//					System.out.println("bytes:" + a3[i][3]);
//				}
			}
			final long endTime1 = System.currentTimeMillis();
			
			totalTime1 = (endTime1 - startTime1);
			
			Object[][] sign3 = new Object[ITERATIONS][];
			final long startTime2 = System.currentTimeMillis();
			for(int i = 0; i < ITERATIONS; i++) {
				out.writeObject(a3[i][0]);
				out.flush();
				BigInteger hisphi = ((BigInteger)in.readObject());
				//System.out.println((BigInteger)a3[i][0]);
				
				sign3[i] = test3.complete((BigInteger)a3[i][0], hisphi);
				
			}
			final long endTime2 = System.currentTimeMillis();
			totalTime2 =(endTime2 - startTime2);
			
			final long startTime3 = System.currentTimeMillis();
			for(int i=0; i< ITERATIONS; i++) {
				test3.reveal(sign3[i], (BigInteger)a3[i][0]);
			}
			final long endTime3 = System.currentTimeMillis();
			totalTime3 =(endTime3 - startTime3);
			//System.out.println(test3.verify(new BigInteger(message.getBytes()), test3.getPublic(), sign3[0]));
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
			
		
		System.out.println(totalTime0 * 1.0 + " ms for keygen P:" + id + " with total time " + totalTime0 + " ms for "+ iterations +" iterations" );
		System.out.println(totalTime1 * 1.0/iterations + " ms for signing P:" + id + " with total time " + totalTime1 + " ms for "+ iterations +" iterations");
		System.out.println(totalTime2 * 1.0/iterations + " ms for complete P:" + id + " with total time " + totalTime2 + " ms for "+ iterations +" iterations");
		System.out.println(totalTime3 * 1.0/iterations + " ms for reveal P:" + id + " with total time " + totalTime3 + " ms for "+ iterations +" iterations");

	}
	
	private static void schnorr(int id, ObjectInputStream in, ObjectOutputStream out, int iterations, String message, boolean zkp) {
		//String message = "0100000001344630cbff61fbc362f7e1ff2f11a344c29326e4ee96e787dc0d4e5cc02fd069000000004a493046022100ef89701f460e8660c80808a162bbf2d676f40a331a243592c36d6bd1f81d6bdf022100d29c072f1b18e59caba6e1f0b8cadeb373fd33a25feded746832ec179880c23901ffffffff0100f2052a010000001976a914dd40dedd8f7e37466624c4dacc6362d8e7be23dd88ac00000000"; 
		System.out.println("Running Schnorr-based SSSig for " + iterations + " iterations...with ZKP =" + zkp);
		final int ITERATIONS = iterations;
		long totalTime0 = 0, totalTime1= 0,totalTime2=0,totalTime3 = 0;
		
		try {
			SSSSCHNORR test3 = new SSSSCHNORR(id,zkp);
			final long startTime0 = System.currentTimeMillis();
			test3.keygen2p(new SecureRandom(), in, out);
			final long endTime0 = System.currentTimeMillis();
			totalTime0 = (endTime0 - startTime0);
			
			Object[][] a3 = new Object[ITERATIONS][];
			final long startTime1 = System.currentTimeMillis();
			for(int i = 0; i < ITERATIONS; i++) {
				a3[i] = test3.pSign(new BigInteger(message.getBytes()), in, out);
//				if(id == 1) {
//				System.out.println("bytes:" + ((int)a3[i][3]+(int)a3[i][4]));
//				}
			}
			final long endTime1 = System.currentTimeMillis();
			
			totalTime1 = (endTime1 - startTime1);
			
			Object[][] sign3 = new Object[ITERATIONS][];
			final long startTime2 = System.currentTimeMillis();
			for(int i = 0; i < ITERATIONS; i++) {
				out.writeObject(a3[i][0]);
				out.flush();
				BigInteger hisphi = ((BigInteger)in.readObject());
				//System.out.println((BigInteger)a3[i][0]);
				
				sign3[i] = test3.complete((BigInteger)a3[i][0], hisphi);
			}
			final long endTime2 = System.currentTimeMillis();
			totalTime2 =(endTime2 - startTime2);
			
			final long startTime3 = System.currentTimeMillis();
			for(int i=0; i< ITERATIONS; i++) {
				test3.reveal(sign3[i], (BigInteger)a3[i][0]);
			}
			final long endTime3 = System.currentTimeMillis();
			totalTime3 =(endTime3 - startTime3);
			
			//System.out.println(test3.verify(new BigInteger(message.getBytes()), test3.getPublic(), sign3[0]));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		System.out.println(totalTime0 * 1.0 + " ms for keygen P:" + id + " with total time " + totalTime0 + " ms for "+ iterations +" iterations" );
		System.out.println(totalTime1 * 1.0/iterations + " ms for signing P:" + id + " with total time " + totalTime1 + " ms for "+ iterations +" iterations");
		System.out.println(totalTime2 * 1.0/iterations + " ms for complete P:" + id + " with total time " + totalTime2 + " ms for "+ iterations +" iterations");
		System.out.println(totalTime3 * 1.0/iterations + " ms for reveal P:" + id + " with total time " + totalTime3 + " ms for "+ iterations +" iterations");

	}

	private static void ecdsa(int id, ObjectInputStream in, ObjectOutputStream out, int iterations, String message, boolean zkp) {
		//String message = "0100000001344630cbff61fbc362f7e1ff2f11a344c29326e4ee96e787dc0d4e5cc02fd069000000004a493046022100ef89701f460e8660c80808a162bbf2d676f40a331a243592c36d6bd1f81d6bdf022100d29c072f1b18e59caba6e1f0b8cadeb373fd33a25feded746832ec179880c23901ffffffff0100f2052a010000001976a914dd40dedd8f7e37466624c4dacc6362d8e7be23dd88ac00000000"; 
		System.out.println("Running ECDSA-based SSSig for " + iterations + " iterations... with ZKP = " + zkp);
		final int ITERATIONS = iterations;
		long totalTime0 = 0, totalTime1= 0,totalTime2=0,totalTime3 = 0;
		
		try {
			SSSECDSA test3 = new SSSECDSA(id,zkp);
			final long startTime0 = System.currentTimeMillis();
			test3.keygen2p(new SecureRandom(), in, out);
			final long endTime0 = System.currentTimeMillis();
			totalTime0 = (endTime0 - startTime0);
			
			Object[][] a3 = new Object[ITERATIONS][];
			final long startTime1 = System.currentTimeMillis();
			for(int i = 0; i < ITERATIONS; i++) {
				a3[i] = test3.pSign(new BigInteger(message.getBytes()), in, out);
//				if(id == 2) {
//				System.out.println("bytes:" + a3[i][3]);
//				}
			}
			final long endTime1 = System.currentTimeMillis();
			
			totalTime1 = (endTime1 - startTime1);
			
			Object[][] sign3 = new Object[ITERATIONS][];
			final long startTime2 = System.currentTimeMillis();
			for(int i = 0; i < ITERATIONS; i++) {
				out.writeObject(a3[i][0]);
				out.flush();
				BigInteger hisphi = ((BigInteger)in.readObject());
				//System.out.println((BigInteger)a3[i][0]);
				
				sign3[i] = test3.complete((BigInteger)a3[i][0], hisphi);
				
			}
			final long endTime2 = System.currentTimeMillis();
			totalTime2 =(endTime2 - startTime2);
			
			final long startTime3 = System.currentTimeMillis();
			for(int i=0; i< ITERATIONS; i++) {
				test3.reveal(sign3[i], (BigInteger)a3[i][0]);
			}
			final long endTime3 = System.currentTimeMillis();
			totalTime3 =(endTime3 - startTime3);
		} catch (Exception e) {
			e.printStackTrace();
		}
			
		System.out.println(totalTime0 * 1.0 + " ms for keygen P:" + id + " with total time " + totalTime0 + " ms for "+ iterations +" iterations" );
		System.out.println(totalTime1 * 1.0/iterations + " ms for signing P:" + id + " with total time " + totalTime1 + " ms for "+ iterations +" iterations");
		System.out.println(totalTime2 * 1.0/iterations + " ms for complete P:" + id + " with total time " + totalTime2 + " ms for "+ iterations +" iterations");
		System.out.println(totalTime3 * 1.0/iterations + " ms for reveal P:" + id + " with total time " + totalTime3 + " ms for "+ iterations +" iterations");
		
	}
	public static String timeAlgos(int id, ObjectInputStream in, ObjectOutputStream out, int algId, int iterations) {
		SecretSharingSignature k = null;
		long sum = 0;
		long[] times = new long[iterations];
		try {
			switch(algId) {
				case 1:
					 k = new SSSECDSA(id);
					break;
				case 2:
					 k = new SSSSCHNORR(id);
					break;
				case 3:
					 k = new SSSCRYPTO(id);
			}
			SecureRandom rnd = new SecureRandom();
			
			for(int i = 0; i < iterations; i++){
				final long startTime = System.currentTimeMillis();
				k.keygen2p(rnd, in, out);
				final long endTime = System.currentTimeMillis();
				times[i] = (endTime - startTime);
			}
			
			for (int i = 0; i< iterations; i++) {
				sum += times[i];
			}
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return sum * 1.0 / iterations + "";
		
	}
}
