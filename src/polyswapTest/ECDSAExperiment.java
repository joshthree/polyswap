package polyswapTest;

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
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Date;
import java.util.Scanner;

import org.bouncycastle.math.ec.ECPoint;

import sssig.SSSECDSA;
import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.InvalidStringFormatException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;

public class ECDSAExperiment {

	public static void main(String[] args)
			throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException,
			SecurityException, InvalidStringFormatException, IOException, ClassNotFoundException,
			MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException, NoSuchAlgorithmException {
		int debug = 1;
		int id = 1;
		int selectProtocol = 3;
		int iterations = 1;
		String message = "0100000001344630cbff61fbc362f7e1ff2f11a344c29326e4ee96e787dc0d4e5cc02fd069000000004a493046022100ef89701f460e8660c80808a162bbf2d676f40a331a243592c36d6bd1f81d6bdf022100d29c072f1b18e59caba6e1f0b8cadeb373fd33a25feded746832ec179880c23901ffffffff0100f2052a010000001976a914dd40dedd8f7e37466624c4dacc6362d8e7be23dd88ac00000000";
		Decoder decoder = Base64.getDecoder();
		System.out.println(new Date());
		System.out.println(new File("").getAbsolutePath());

		String args0 = "127.0.0.1";
		String args1 = "8000";

		ServerSocket host = null;
		Socket s;
		ObjectInputStream in;
		ObjectOutputStream out;

		try {
			SocketAddress dest = new InetSocketAddress(args0, Integer.parseInt(args1));
			s = new Socket();
			s.connect(dest);
			id = 2;
			System.out.println("Connection to Server successful");
			in = new ObjectInputStream(s.getInputStream());
			out = new ObjectOutputStream(s.getOutputStream());
		} catch (Exception e) {
			System.out.println("Connection not open, opening server");
			try {
				host = new ServerSocket(Integer.parseInt(args1));
				s = host.accept();
				if (args0.equals(s.getInetAddress().getHostAddress())) {
					System.out.println("");
				}
				System.out.println("Connection established");
				out = new ObjectOutputStream(s.getOutputStream());
				in = new ObjectInputStream(s.getInputStream());
			} catch (java.net.BindException ex) {
				SocketAddress dest = new InetSocketAddress(args0, Integer.parseInt(args1));
				s = new Socket();
				s.connect(dest);
				System.out.println("Connection to Server successful");
				in = new ObjectInputStream(s.getInputStream());
				out = new ObjectOutputStream(s.getOutputStream());
			}
		}

		ecdsa(id, in, out, iterations, message);
		testplainecdsa(id);

	}

	private static void ecdsa(int id, ObjectInputStream in, ObjectOutputStream out, int iterations, String message) {
		System.out.println("Running ECDSA-based SSSig for " + iterations + " iterations...");

		try {
			SSSECDSA test3 = new SSSECDSA(id);
			// generate key
			Object[] keys = test3.keygen2p(new SecureRandom(), in, out);
			System.out.println("Secret key 1 = " + (BigInteger) keys[0]);
			System.out.println("Secret key 2 = " + (BigInteger) keys[1]);
			ECPoint pk = (ECPoint) keys[2];
			System.out.println("Public key 12 = " + (pk.getEncoded(true)).length);

			// write the public key to a file
			test3.writeKeyToFile(pk, "../publickey");

			// halt program to read message hash
			Scanner scan = new Scanner(System.in);
			System.out.println("Enter message");
			String msg = scan.nextLine();
			System.out.println("This is the message:" + msg);
			scan.close();

			// read message hash file
			File hashfile = new File("../hashfile");
			byte[] msghash = Files.readAllBytes(hashfile.toPath());

			// sign the message hash
			Object a3[] = test3.pSign(new BigInteger(1, msghash), in, out);

			// send our unlocking secret to other party
			out.writeObject(a3[0]);
			out.flush();
			BigInteger hisphi = ((BigInteger) in.readObject());

			// run complete to generate full signature
			Object sign3[] = test3.complete((BigInteger) a3[0], hisphi);
			System.out.println("r value: " + (BigInteger) sign3[0]);
			System.out.println("s value: " + (BigInteger) sign3[1]);

			// write signature to a file
//			PrintWriter signaturefile = new PrintWriter("../signaturefile");
//			signaturefile.println((BigInteger)sign3[0]); //r
//			signaturefile.println((BigInteger)sign3[1]); //s
//			signaturefile.close();
			test3.writeSigToFileinDER(new BigInteger[] { (BigInteger) sign3[0], (BigInteger) sign3[1] },
					"../signaturefile");

			BigInteger[] signature = new BigInteger[2];
			signature[0] = (BigInteger) sign3[0];
			signature[1] = (BigInteger) sign3[1];

			System.out.println("Verification " + test3.verify(new BigInteger(1, msghash), pk, signature));

			// Test with simple signature

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private static void testplainecdsa(int id) throws IOException {
		SSSECDSA k = new SSSECDSA(id);
		Object[] k_keys = k.keygen(new SecureRandom());
		BigInteger private_key = (BigInteger) k_keys[0];
		ECPoint public_key = (ECPoint) k_keys[1];
		System.out.println("Private key: " + private_key);
		System.out.println("Public key:" + k.getPublicKey());
		k.writeKeyToFile(public_key, "../publickey");

		System.out.println();
		Scanner scan = new Scanner(System.in);
		System.out.println("Enter message");
		String msg1 = scan.nextLine();
		System.out.println("This is the message:" + msg1);
		scan.close();
		// read message hash file
		File hashfile = new File("../hashfile");
		byte[] msghash = Files.readAllBytes(hashfile.toPath());

		System.out.println("msg integer " + new BigInteger(1, msghash));

		BigInteger[] k_signature = k.sign(new BigInteger(1, msghash), private_key);
		// write signature to a file
//		PrintWriter signaturefile1 = new PrintWriter("../signaturefile");
//		signaturefile1.println(k_signature[0]); //r
//		signaturefile1.println(k_signature[1]); //s
//		signaturefile1.close();
//		
		k.writeSigToFileinDER(k_signature, "../signaturefile");

		System.out.println("r " + k_signature[0]);
		System.out.println("s " + k_signature[1]);

		System.out.println("Test Verification " + k.verify(new BigInteger(1, msghash), public_key, k_signature));
	}

}
