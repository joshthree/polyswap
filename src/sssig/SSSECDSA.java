package sssig;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;

import org.bitcoinj.core.ECKey;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.DLSchnorrProver;
import zero_knowledge_proofs.ECEqualDiscreteLogsProver;
import zero_knowledge_proofs.ECSchnorrProver;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.VarianceToolkit;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.CryptoDataCommitment;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class SSSECDSA implements SecretSharingSignature{


	private boolean zkFlag = true;

	public SSSECDSA() {
		this.initializeParameters("secp256k1");
	}
	
	public SSSECDSA(int id) {
		this.initializeParameters("secp256k1");
		this.id = id;
	}
	
	//constructor to control zero knowledge proofs
	public  SSSECDSA(int id, boolean zkFlag) {
		this.initializeParameters("secp256k1");
		this.id = id;
		this.zkFlag = zkFlag;
	}
	
	BigInteger HALF_CURVE_ORDER;
	int id;
	private ECCurveData curve;
	private ECCurve c;
	private static ECPoint g,R;
	private BigInteger sk1,sk2,sk;
	private ECPoint pk12,pk, Phi1, Phi2;

	private SecureRandom rnd;

	private static BigInteger order;
	private BigInteger  sp, k2, r,ckey,  phi1, phi2;
	private PaillierKey paillierKey,publicPaillerKey;


	public void initializeParameters(String curveName) {
		g = ECNamedCurveTable.getParameterSpec(curveName).getG();		
		c = g.getCurve();
		curve = new ECCurveData(c,g);
		order = c.getOrder();
		rnd = new SecureRandom();
		HALF_CURVE_ORDER = ECNamedCurveTable.getParameterSpec(curveName).getN().shiftRight(1);
	}




	public Object[] keygen(SecureRandom r) {
		sk = ZKToolkit.random(order, r);
		pk = g.multiply(sk);
		return new Object[] {sk, pk};
	}
	
	public ECPoint generateSecondGenerator(SecureRandom r, ObjectInputStream in, ObjectOutputStream out) {
		ECPoint hisPk, h = null;
		try {
		if(id == 1) {
				BigInteger a1 = ZKToolkit.random(order, r);
			
				out.writeObject(g.multiply(a1).getEncoded(true));
				out.flush();
				hisPk = curve.getECCurveData().decodePoint((byte[]) in.readObject());
				h = hisPk.multiply(a1);
				
		}else if(id == 2) {
			BigInteger a2 = ZKToolkit.random(order, r);
			hisPk = curve.getECCurveData().decodePoint((byte[]) in.readObject());
			out.writeObject(g.multiply(a2).getEncoded(true));
			out.flush();
			h = hisPk.multiply(a2);
			
		}
			} catch (IOException | ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		
		return h;
	}

	public Object[] keygen2p(SecureRandom r, ObjectInputStream in, ObjectOutputStream out) {

		ECPoint hisPk;
		try {
			if(id == 1) {
				sk1 = ZKToolkit.random(order, r);

				//send public key part
				out.writeObject(g.multiply(sk1).getEncoded(true));
				out.flush();

				paillierKey = new PaillierKey(2048, rnd);

				//send public paillier Key
				publicPaillerKey = paillierKey.getPublicKey();
				out.writeObject(publicPaillerKey);
				out.flush();

				//receive his public key part
				hisPk =  curve.getECCurveData().decodePoint((byte[]) in.readObject());


				pk12 = hisPk.multiply(sk1);

				ckey = paillierKey.encrypt(sk1, rnd);

				//send ckey
				out.writeObject(ckey);
				out.flush();

			}else if(id == 2) {
				sk2 = ZKToolkit.random(order, r);

				//receive public key
				hisPk = curve.getECCurveData().decodePoint((byte[]) in.readObject());

				pk12 = hisPk.multiply(sk2);

				//receive his public paillier key
				publicPaillerKey = (PaillierKey) in.readObject();

				//send my public key part
				out.writeObject(g.multiply(sk2).getEncoded(true));
				out.flush();

				//receive ckey
				ckey = (BigInteger) in.readObject();
				
				{
					int b = 0;
					b += hisPk.getEncoded(true).length;
					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					ObjectOutputStream out2 = new ObjectOutputStream(bos);   
					out2.writeObject(publicPaillerKey);
					out2.flush();
					byte[] yourBytes = bos.toByteArray();
					b += yourBytes.length;
					b += g.multiply(sk2).getEncoded(true).length;
					//System.out.println("ECDSA bytes:" + b);

				}
				
			}

		} catch (IOException | ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return new Object[] {sk1,sk2,pk12};
	}

	//calculates e = H(m) to be in order
	public static BigInteger calculateBigIntegerforMessage( byte[] message)
	{
		int log2n = order.bitLength();
		int messageBitLength = message.length * 8;

		BigInteger e = new BigInteger(1, message);
		if (log2n < messageBitLength)
		{
			e = e.shiftRight(messageBitLength - log2n);
		}
		return e;
	}

	public BigInteger[] sign(BigInteger m, BigInteger sk) {
		BigInteger k = new BigInteger(order.bitLength(), rnd);
		//BigInteger k = new BigInteger("96600670304393138668912907453211310458449348424690287990577511114240127609836");

		ECPoint R = g.multiply(k).normalize();

		BigInteger r = R.getXCoord().toBigInteger();
		BigInteger s = k.modInverse(order).multiply(m.add(r.multiply(sk).mod(order)).mod(order));
		
		if(s.compareTo(HALF_CURVE_ORDER) > 0) {
			s = order.subtract(s);
		}
		
		return new BigInteger[] {r,s.mod(order)};
	}

	public void writeKeyToFile(ECPoint pk, String path) throws IOException {

		// writing the compressed public key to a file as byte array. Following Bitcoin format, Reference: https://bitcoin.org/en/wallets-guide
		ByteArrayOutputStream arr = new ByteArrayOutputStream();
		if(pk.normalize().getAffineYCoord().toBigInteger().and(new BigInteger("1")).compareTo(new BigInteger("1")) == 0) {
			arr.write(new byte[] {(byte)0x03});
		}else {
			arr.write(new byte[] {(byte)0x02});
		}
		//arr.write(pk.normalize().getAffineYCoord().toBigInteger().and(new BigInteger("1")).toByteArray());
		arr.write(pk.normalize().getAffineXCoord().getEncoded());
		//write the public key to a file
		try (FileOutputStream stream = new FileOutputStream(path)){
			stream.write(arr.toByteArray());
			//stream.write(pk.getEncoded(true));
		}
		arr.close();

		//		for(byte b: arr.toByteArray()) {
		//			System.out.println(b);
		//		}
	}

	//Bitcoin format
	public static byte[] getCompressedPublicKey(ECPoint pk){

		ByteArrayOutputStream arr = new ByteArrayOutputStream();
		try {
			// writing the compressed public key to a file as byte array. Following Bitcoin format, Reference: https://bitcoin.org/en/wallets-guide
			if(pk.normalize().getAffineYCoord().toBigInteger().and(new BigInteger("1")).compareTo(new BigInteger("1")) == 0) {
				arr.write(new byte[] {(byte)0x03});
			}else {
				arr.write(new byte[] {(byte)0x02});
			}
			//arr.write(pk.normalize().getAffineYCoord().toBigInteger().and(new BigInteger("1")).toByteArray());
			arr.write(pk.normalize().getAffineXCoord().getEncoded());
			//write the public key to a file


		} catch(IOException e) {
			e.printStackTrace();
		}
		return	arr.toByteArray();
	}



	public void writeSigToFileinDER(BigInteger[] sig, String path) throws IOException {
		BigInteger r = sig[0];
		BigInteger s = sig[1];
		//canonical signature in Bitcoin where s is ensured to be less than half the order of the curve.
		if(s.compareTo(order.divide(new BigInteger("2"))) == 1) {
			s = order.subtract(s);
		}

		ByteArrayOutputStream bos = new ByteArrayOutputStream(72);
		DERSequenceGenerator seq = new DERSequenceGenerator(bos);
		seq.addObject(new org.bouncycastle.asn1.ASN1Integer(r));
		seq.addObject(new org.bouncycastle.asn1.ASN1Integer(s));
		seq.close();
		try (FileOutputStream stream = new FileOutputStream(path)){
			stream.write(bos.toByteArray());
		}


	}

	public Object[] pSign(BigInteger m, ObjectInputStream in, ObjectOutputStream out) throws NoSuchAlgorithmException {
		ECPoint R1,R2p,RP1, RP2, R, R2, hisR, Q1, Q2;
		BigInteger c = BigInteger.ONE,rho,c2,k0,e,k3,k2,cp,sp,spp ;
		BigInteger c1 = BigInteger.ONE;
		BigInteger k1 = BigInteger.ONE;
		Object[] ret = new Object[4];
		int b = 0;

		//removed message hashing for checking things. this also affects variable e

		//MessageDigest md = MessageDigest.getInstance("SHA-256");
		//P1

		try {
			if(id == 1) {
				ECSchnorrProver ecsp = null;
				ECEqualDiscreteLogsProver ecdlp = null;
				CryptoData environment = null;
				
				if(zkFlag) {
					ecsp = new ECSchnorrProver();
					ecdlp = new ECEqualDiscreteLogsProver();
					environment = new CryptoDataArray(new CryptoData[] {curve});
				}

				k1 = ZKToolkit.random(order, rnd);
				R1 = g.multiply(k1);
				//e = new BigInteger(1,md.digest(m.toByteArray())); 
				e = m;
				
				CryptoData[] proof2 = null;
				CryptoData[] proof1 = null;
				CryptoDataCommitment proof1commitment = null;
				if(zkFlag) {
					CryptoData secrets1 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), k1});
					CryptoData publicInput1 = new CryptoDataArray(new CryptoData[] {new ECPointData(R1)});		
					proof1 = ecsp.proveFiatShamir(publicInput1, secrets1, environment);
					
					proof1commitment = new CryptoDataArray(proof1).commit(environment, rnd);
					
					//send proof1commitment 
					out.writeObject(proof1commitment.getCommitments());
					out.flush();
	
					//receive proof2 and R2
					proof2 = (CryptoData[]) in.readObject();
					
				}
				R2 = curve.getECCurveData().decodePoint((byte[]) in.readObject());

				//Send R1, proof1 and proof1commitmentkeys
				out.writeObject(R1.getEncoded(true));
				//verify proof2
				if(zkFlag) {
					out.writeObject(proof1);
					//out.flush();
					out.writeObject(proof1commitment.getKeys());
				}
				out.flush();

				if(zkFlag) {
					CryptoData publicInput2 = new CryptoDataArray(new CryptoData[] {new ECPointData(R2)});		
					if(!ecsp.verifyFiatShamir(publicInput2, proof2[0], proof2[1], environment))
						System.out.println("proof2 failed");
				} 
				

				
				R = R2.multiply(k1);

				r = R.normalize().getXCoord().toBigInteger(); 

				//receive cp
				cp = (BigInteger) in.readObject();
				sp = paillierKey.decrypt(cp).mod(order);
				spp = k1.modInverse(order).multiply(sp).mod(order);
				phi1 = spp.modInverse(order);
				Q1 = pk12.multiply(phi1);
				Phi1 = g.multiply(phi1);

				CryptoData[] proof3 = null;
				CryptoDataCommitment proof3commitment = null;
				CryptoData environment2 = null;
				if(zkFlag) {
					CryptoData secrets3 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), phi1});
					CryptoData publicInput3 = new CryptoDataArray(new CryptoData[] {new ECPointData(Phi1), new ECPointData(Q1)});		
	
					environment2 = new CryptoDataArray(new CryptoData[] {curve, new ECPointData(pk12)});
	
					proof3 = ecdlp.proveFiatShamir(publicInput3, secrets3, environment2);
					proof3commitment = new CryptoDataArray(proof3).commit(environment, rnd);
					//send proof3commitment
					out.writeObject(proof3commitment.getCommitments());
					out.flush();
				}
				//receive Q2, Phi2, and proof4
				Q2 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
				Phi2 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
				CryptoData[] proof4 = null;
				if(zkFlag) {
					proof4  = (CryptoData[]) in.readObject();
				
	
					//send proof3, commitmentkeys, Phi1, Q1
					out.writeObject(proof3);
					//out.flush();
					out.writeObject(proof3commitment.getKeys());
				}
				out.writeObject(Phi1.getEncoded(true));
				//out.flush();
				out.writeObject(Q1.getEncoded(true));
				out.flush();

				if(zkFlag) {				
//					out.flush();
					//verify proof4
					CryptoData publicInput4 = new CryptoDataArray(new CryptoData[] {new ECPointData(Phi2), new ECPointData(Q2)});		
					if(!ecsp.verifyFiatShamir(publicInput4, proof4[0], proof4[1], environment2))
						System.out.println("proof4 failed");
				}

				ECPoint vf = Phi2.multiply(phi1).multiply(e).add(Q2.multiply(phi1).multiply(r));
				if(!vf.normalize().getXCoord().toBigInteger().equals(r))
					System.out.println("verification for 1 failed");

				ret[0] = phi1;
				ret[1] = Phi1.normalize();
				ret[2] = Phi2.normalize();

			} else if(id == 2) {
				
				ECSchnorrProver ecsp = null;
				ECEqualDiscreteLogsProver ecdlp = null;
				CryptoData environment = null;
				CryptoData environment2 = null;
				if(zkFlag) {
					ecsp = new ECSchnorrProver();
					ecdlp = new ECEqualDiscreteLogsProver();
					environment = new CryptoDataArray(new CryptoData[] {curve});
					environment2 = new CryptoDataArray(new CryptoData[] {curve, new ECPointData(pk12)});
				}

				k3 = ZKToolkit.random(order, rnd);
				//e = new BigInteger(1,md.digest(m.toByteArray()));
				e = m;

				k2 = ZKToolkit.random(order, rnd);
				R2 = g.multiply(k2).multiply(k3);

				ArrayList<BigInteger> proof1commitment = null;
				CryptoData[] proof2 = null;
				if(zkFlag) {
					
					CryptoData secrets2 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), k2.multiply(k3)});
					CryptoData publicInput2 = new CryptoDataArray(new CryptoData[] {new ECPointData(R2)});		
					proof2 = ecsp.proveFiatShamir(publicInput2, secrets2, environment);
	
					//receive proof1commitment
					proof1commitment = (ArrayList<BigInteger> ) in.readObject();
	
					//send proof2 and R2
					out.writeObject(proof2);
					out.flush();
				}

				out.writeObject(R2.getEncoded(true));
				out.flush();

				//receive R1, proof1 and proof1commmitement keys
				R1 =  curve.getECCurveData().decodePoint((byte[]) in.readObject());

				CryptoData[] proof1 = null;
				ArrayList<BigInteger> proof1commitmentkeys = null;
				if(zkFlag) {
					proof1 = (CryptoData[]) in.readObject();

					proof1commitmentkeys = (ArrayList<BigInteger>) in.readObject();
	
					//verify commitment1 and proof1
					if(!CryptoDataCommitment.verifyCommitment(new CryptoDataArray(proof1), proof1commitmentkeys, proof1commitment, environment))
						System.out.println("commitment of proof1 verification failed");
					CryptoData publicInput1 = new CryptoDataArray(new CryptoData[] {new ECPointData(R1)});		
					if(!ecsp.verifyFiatShamir(publicInput1, proof1[0], proof1[1], environment))
						System.out.println("proof1 failed");
				}

				R = R1.multiply(k2).multiply(k3);

				r = R.normalize().getXCoord().toBigInteger(); 


				rho = ZKToolkit.random(order.pow(2), rnd);
				c1 = rho.multiply(order).add(k2.modInverse(order).multiply(e).mod(order));


				c1 = publicPaillerKey.encrypt(c1, rnd);
				BigInteger v = k2.modInverse(order).multiply(r).mod(order).multiply(sk2).mod(order);

				BigInteger n2 = publicPaillerKey.getNSquared();

				c2 = ckey.modPow(v, n2);


				cp = c1.multiply(c2).mod(n2);

				//send cp
				out.writeObject(cp);
				out.flush();

				phi2 = k3;
				Phi2 = g.multiply(phi2);

				Q2 = pk12.multiply(k3);

				CryptoData[] proof4 = null;
				ArrayList<BigInteger> proof3commitment = null;
				if(zkFlag) {
					CryptoData secrets4 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), phi2});
					CryptoData publicInput4 = new CryptoDataArray(new CryptoData[] {new ECPointData(Phi2), new ECPointData(Q2)});		
					proof4 = ecdlp.proveFiatShamir(publicInput4, secrets4, environment2);
	
					//receive proof3commitment
					proof3commitment = (ArrayList<BigInteger> ) in.readObject();
				}

				//send Q2, Phi2, proof4
				out.writeObject(Q2.getEncoded(true));
				out.flush();
				out.writeObject(Phi2.getEncoded(true));
				out.flush();
				
				CryptoData[] proof3 = null;
				ArrayList<BigInteger> proof3commitmentkeys = null;
				if(zkFlag) {
					out.writeObject(proof4);
					out.flush();
	
					//receive proof3, commitmentkeys, Phi1, Q1
					proof3 = (CryptoData[]) in.readObject();
					proof3commitmentkeys = (ArrayList<BigInteger>) in.readObject();
				}
				Phi1 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
				Q1 = curve.getECCurveData().decodePoint((byte[]) in.readObject());

				if(zkFlag) {
					//verify commitment2 and proof3
					if(!CryptoDataCommitment.verifyCommitment(new CryptoDataArray(proof3), proof3commitmentkeys, proof3commitment, environment))
						System.out.println("commitment of proof3 verification failed");
					CryptoData publicInput3 = new CryptoDataArray(new CryptoData[] {new ECPointData(Phi1), new ECPointData(Q1)});	
					if(!ecdlp.verifyFiatShamir(publicInput3, proof3[0], proof3[1], environment2))
						System.out.println("proof3 failed");
				}
				ECPoint vf = Phi1.multiply(k3).multiply(e).add(Q1.multiply(k3).multiply(r));
				if(!vf.normalize().getXCoord().toBigInteger().equals(r))
					System.out.println("verification for 2 failed");

				ret[0] = phi2;
				ret[1] = Phi2.normalize();
				ret[2] = Phi1.normalize();


					/* if(proof1commitment != null) {
						for(BigInteger k: proof1commitment) {
	 						b += k.bitLength()/8;
	 						if(k.bitLength()%8 != 0) b++;
	 					}
					}
					if(proof2 != null) {
	 					for (CryptoData blah: proof2) {
							b += blah.getBytes().length;
						}
					}
 					b += R2.getEncoded(true).length;
 					b += R1.getEncoded(true).length;
 					if(proof1 != null) {
	 					for (CryptoData blah: proof1) {
							b += blah.getBytes().length;
						}
 					}
 					if(proof1commitmentkeys != null) {
	 					for(BigInteger k: proof1commitmentkeys) {
	 						b += k.bitLength()/8;
	 						if(k.bitLength()%8 != 0) b++;
	 					}
 					}
 					b += cp.bitLength()/8;
 					if(proof3commitment != null) {
	 					for(BigInteger k: proof3commitment) {
	 						b += k.bitLength()/8;
	 						if(k.bitLength()%8 != 0) b++;
	 					}
 					}
 					b += Q2.getEncoded(true).length;
 					b += Phi2.getEncoded(true).length;
 					if(proof4 !=  null) {
	 					for (CryptoData blah: proof4) {
							b += blah.getBytes().length;
						}
 					}
 					if(proof3 != null) {
	 					for (CryptoData blah: proof3) {
							b += blah.getBytes().length;
						}
 					}
 					if(proof3commitmentkeys != null) {
	 					for(BigInteger k: proof3commitmentkeys) {
	 						b += k.bitLength()/8;
	 						if(k.bitLength()%8 != 0) b++;
	 					}
 					}
 					b += Q1.getEncoded(true).length;
 					b += Phi1.getEncoded(true).length; */


			}
		} catch (IOException | ClassNotFoundException  | NoSuchAlgorithmException |MultipleTrueProofException |NoTrueProofException | ArraySizesDoNotMatchException  ex) {
			// TODO Auto-generated catch block

			ex.printStackTrace();

		} 

		ret[3] = b;
		return ret;



	}
	
	public BigInteger getPhi() {
		if(id == 1) {
			return phi1;
		}else {
			return phi2;
		}
	}
	
	public ECPoint[] getPublicPhi() {

		return new ECPoint[] {Phi1,Phi2};
	}
	
	




	public BigInteger[] complete(BigInteger phi1, BigInteger phi2) {
		
		BigInteger s = phi1.multiply(phi2).modInverse(order);
		if(s.compareTo(HALF_CURVE_ORDER) > 0) {
			s = order.subtract(s);
		}
		return new BigInteger[]{r, s};
	}

	public BigInteger reveal(Object[] signature, BigInteger phi) {

		BigInteger s = (BigInteger)signature[1];
		return s.multiply(phi).modInverse(order);
	}

	public boolean verify(BigInteger m, ECPoint pk, BigInteger[] signature) {
		BigInteger r = signature[0];
		BigInteger s = signature[1];
		ECPoint rhs = (g.multiply(m).add(pk.multiply(r))).multiply(s.modInverse(order)).normalize();
		return r.equals(rhs.getXCoord().toBigInteger());
	}



	public BigInteger getOrder() {
		return this.order;
	}


	@Override
	public ECPoint getPublic() {
		return pk12;
	}


	//return public key as for Etherereum
	public BigInteger getPublicKey() {
		byte[] pubKeyBytes = pk12.getDetachedPoint().getEncoded(false);
		return new BigInteger(1, Arrays.copyOfRange(pubKeyBytes, 1, pubKeyBytes.length));
	}

	public ECKey getPublicECKey() {
		return ECKey.fromPublicOnly(ECKey.compressPoint(pk12));
	}






}
