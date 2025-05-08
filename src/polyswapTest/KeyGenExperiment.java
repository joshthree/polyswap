package polyswapTest;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

import org.omg.CORBA.LongHolder;
import org.web3j.abi.datatypes.primitive.Double;

import sssig.SSSCRYPTO;
import sssig.SSSECDSA;
import sssig.SSSSCHNORR;
import sssig.SecretSharingSignature;

import java.util.Base64.Decoder;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.InvalidStringFormatException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;

public class KeyGenExperiment {
	public static void main(String[] args) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, SecurityException, InvalidStringFormatException, IOException, ClassNotFoundException, MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException, NoSuchAlgorithmException{
		args = new String[2];
		args[0] = "127.0.0.1";
		args[1] = "9999";
		int id = 1;
		int selectProtocol = 3;
		int iterations = 1;
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
		
		System.out.println("ECDSA " + timeKeyGen(id, in, out, 1, 1) + " ms");
		System.out.println("Crytonote " + timeKeyGen(id, in, out, 2, 1) + " ms");
		System.out.println("Schnorr " + timeKeyGen(id, in, out, 3, 1)+ " ms");
		
		
	}
	
	public static String timeKeyGen(int id, ObjectInputStream in, ObjectOutputStream out, int algId, int iterations) {
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
