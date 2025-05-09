package polyswap;
import java.io.File;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.math.ec.ECPoint;

import sssig.*;

import java.util.Base64.Decoder;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.InvalidStringFormatException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.VarianceToolkit;
import zero_knowledge_proofs.ZKPProtocol;
import poly.ModPolynomial;

public class MainExperiment {

	public static void main(String[] args) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, SecurityException, InvalidStringFormatException, IOException, ClassNotFoundException, MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException, NoSuchAlgorithmException{
		int debug = 1;
		int id = 1;
		int selectProtocol = 3;
		int iterations = 1;
		String message = "0100000001344630cbff61fbc362f7e1ff2f11a344c29326e4ee96e787dc0d4e5cc02fd069000000004a493046022100ef89701f460e8660c80808a162bbf2d676f40a331a243592c36d6bd1f81d6bdf022100d29c072f1b18e59caba6e1f0b8cadeb373fd33a25feded746832ec179880c23901ffffffff0100f2052a010000001976a914dd40dedd8f7e37466624c4dacc6362d8e7be23dd88ac00000000"; 
		Decoder decoder = Base64.getDecoder();
		System.out.println(new Date());
		System.out.println(new File("").getAbsolutePath());
		
		if(args.length < 3) {
			System.out.println("Usage: SSSig.jar address port protocol_id [iterations]" );
			System.out.println("\t iterations is optional, default 1");
			System.out.println("Where arguments are:");
			System.out.println("\t address\t Network address to use for connecting with parties");
			System.out.println("\t port\t\t Network port to use for connecting with parties");
			System.out.println("\t protocol_id\t Available protocols:\n\t\t\t\t 1: ECDSA-based SSSig\n\t\t\t\t 2: Schnorr-based SSSig \n\t\t\t\t 3: Cryptonote-based SSSig");
			System.out.println("\t iterations \tNumber of iterations to run a protocol for");
			System.out.println("Example: SSSig.jar 127.0.0.1 8888 1 1000\n");
			System.exit(1);
		}
		
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
		
		if(args.length == 3) {
			selectProtocol = Integer.parseInt(args[2]);
		}
		if(args.length == 4) {
			iterations = Integer.parseInt(args[3]);
		}
		
		switch(selectProtocol) {
		case 1:
			ecdsa(id,in,out,iterations,message);
			break;
		case 2:
			schnorr(id,in,out,iterations,message);
			break;
		case 3:
			cryptonote(id,in,out,iterations,message);
			break;
		default:
			System.out.println("No such protocol available\nAvailable protocols:\n 1: ECDSA-based SSSig\n 2: Schnorr-based SSSig \n 3: Cryptonotr-based SSSig");
		
		
		}
		
		
		
		
	}
	
	private static void ecdsa(int id, ObjectInputStream in, ObjectOutputStream out, int iterations, String message) {
		//String message = "0100000001344630cbff61fbc362f7e1ff2f11a344c29326e4ee96e787dc0d4e5cc02fd069000000004a493046022100ef89701f460e8660c80808a162bbf2d676f40a331a243592c36d6bd1f81d6bdf022100d29c072f1b18e59caba6e1f0b8cadeb373fd33a25feded746832ec179880c23901ffffffff0100f2052a010000001976a914dd40dedd8f7e37466624c4dacc6362d8e7be23dd88ac00000000"; 
		System.out.println("Running ECDSA-based SSSig for " + iterations + " iterations...");
		final int ITERATIONS = iterations;
		long totalTime0 = 0, totalTime1= 0,totalTime2=0,totalTime3 = 0;
		
		try {
			SSSECDSA test3 = new SSSECDSA(id);
			final long startTime0 = System.currentTimeMillis();
			test3.keygen2p(new SecureRandom(), in, out);
			final long endTime0 = System.currentTimeMillis();
			totalTime0 = (endTime0 - startTime0);
			
			Object[][] a3 = new Object[ITERATIONS][];
			final long startTime1 = System.currentTimeMillis();
			for(int i = 0; i < ITERATIONS; i++) {
				a3[i] = test3.pSign(new BigInteger(message.getBytes()), in, out);
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
			
		System.out.println(totalTime0/iterations + " ms for keygen P:" + id + " with total time " + totalTime0 + " ms for "+ iterations +" iterations" );
		System.out.println(totalTime1/iterations + " ms for signing P:" + id + " with total time " + totalTime1 + " ms for "+ iterations +" iterations");
		System.out.println(totalTime2/iterations + " ms for complete P:" + id + " with total time " + totalTime2 + " ms for "+ iterations +" iterations");
		System.out.println(totalTime3/iterations + " ms for reveal P:" + id + " with total time " + totalTime3 + " ms for "+ iterations +" iterations");

	}
	
	private static void schnorr(int id, ObjectInputStream in, ObjectOutputStream out, int iterations, String message) {
		//String message = "0100000001344630cbff61fbc362f7e1ff2f11a344c29326e4ee96e787dc0d4e5cc02fd069000000004a493046022100ef89701f460e8660c80808a162bbf2d676f40a331a243592c36d6bd1f81d6bdf022100d29c072f1b18e59caba6e1f0b8cadeb373fd33a25feded746832ec179880c23901ffffffff0100f2052a010000001976a914dd40dedd8f7e37466624c4dacc6362d8e7be23dd88ac00000000"; 
		System.out.println("Running Schnorr-based SSSig for " + iterations + " iterations...");
		final int ITERATIONS = iterations;
		long totalTime0 = 0, totalTime1= 0,totalTime2=0,totalTime3 = 0;
		
		try {
			SSSSCHNORR test3 = new SSSSCHNORR(id);
			final long startTime0 = System.currentTimeMillis();
			test3.keygen2p(new SecureRandom(), in, out);
			final long endTime0 = System.currentTimeMillis();
			totalTime0 = (endTime0 - startTime0);
			
			Object[][] a3 = new Object[ITERATIONS][];
			final long startTime1 = System.currentTimeMillis();
			for(int i = 0; i < ITERATIONS; i++) {
				a3[i] = test3.pSign(new BigInteger(message.getBytes()), in, out);
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
		
		System.out.println(totalTime0/iterations + " ms for keygen P:" + id + " with total time " + totalTime0 + " ms for "+ iterations +" iterations" );
		System.out.println(totalTime1/iterations + " ms for signing P:" + id + " with total time " + totalTime1 + " ms for "+ iterations +" iterations");
		System.out.println(totalTime2/iterations + " ms for complete P:" + id + " with total time " + totalTime2 + " ms for "+ iterations +" iterations");
		System.out.println(totalTime3/iterations + " ms for reveal P:" + id + " with total time " + totalTime3 + " ms for "+ iterations +" iterations");

	}
	
	private static void cryptonote(int id, ObjectInputStream in, ObjectOutputStream out, int iterations, String message) {
		//String message = "0100000001344630cbff61fbc362f7e1ff2f11a344c29326e4ee96e787dc0d4e5cc02fd069000000004a493046022100ef89701f460e8660c80808a162bbf2d676f40a331a243592c36d6bd1f81d6bdf022100d29c072f1b18e59caba6e1f0b8cadeb373fd33a25feded746832ec179880c23901ffffffff0100f2052a010000001976a914dd40dedd8f7e37466624c4dacc6362d8e7be23dd88ac00000000"; 
		System.out.println("Running Cyrptonote-based SSSig for " + iterations + " iterations...");
		final int ITERATIONS = iterations;
		long totalTime0 = 0, totalTime1= 0,totalTime2=0,totalTime3 = 0;
		
		try {
			SSSCRYPTO test3 = new SSSCRYPTO(id);
			final long startTime0 = System.currentTimeMillis();
			test3.keygen2p(new SecureRandom(), in, out);
			final long endTime0 = System.currentTimeMillis();
			totalTime0 = (endTime0 - startTime0);
			
			Object[][] a3 = new Object[ITERATIONS][];
			final long startTime1 = System.currentTimeMillis();
			for(int i = 0; i < ITERATIONS; i++) {
				a3[i] = test3.pSign(new BigInteger(message.getBytes()), in, out);
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
			
		
		System.out.println(totalTime0/iterations + " ms for keygen P:" + id + " with total time " + totalTime0 + " ms for "+ iterations +" iterations" );
		System.out.println(totalTime1/iterations + " ms for signing P:" + id + " with total time " + totalTime1 + " ms for "+ iterations +" iterations");
		System.out.println(totalTime2/iterations + " ms for complete P:" + id + " with total time " + totalTime2 + " ms for "+ iterations +" iterations");
		System.out.println(totalTime3/iterations + " ms for reveal P:" + id + " with total time " + totalTime3 + " ms for "+ iterations +" iterations");

	}
}
