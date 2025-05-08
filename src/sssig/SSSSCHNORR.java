package sssig;

import java.io.ByteArrayOutputStream;
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

import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.ECSchnorrProver;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.CryptoDataCommitment;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class SSSSCHNORR implements SecretSharingSignature{
	
		
	private boolean zkFlag = true;
	
	public SSSSCHNORR(int id) {
		this.initializeParameters("secp256k1");
		this.id = id;
	}
	
	public SSSSCHNORR(int id, boolean zkFlag) {
		this.initializeParameters("secp256k1");
		this.id = id;
		this.zkFlag = zkFlag;
	}
	
	int id;
	private ECCurveData curve;
	private ECCurve c;
	private static ECPoint g,R;
	private BigInteger sk1,sk2,sk;
	private ECPoint pk12;
	
	private SecureRandom rnd;

	private BigInteger order, sp, k2, r,e;
	
	
	public void initializeParameters(String curveName) {
		g = ECNamedCurveTable.getParameterSpec(curveName).getG();		
		c = g.getCurve();
		curve = new ECCurveData(c,g);
		order = c.getOrder();
		rnd = new SecureRandom();
	}
	
	
	public Object[] keygen2p(SecureRandom r, ObjectInputStream in, ObjectOutputStream out) {
		sk1 = ZKToolkit.random(order, r);
		ECPoint hisPk;
		try {
			out.writeObject(g.multiply(sk1).getEncoded(true));
			out.flush();
			hisPk = curve.getECCurveData().decodePoint((byte[]) in.readObject());
			pk12 = hisPk.add(g.multiply(sk1));
			
			{
				int b = 0;
				b += hisPk.getEncoded(true).length;
				//System.out.println("Schnorr bytes:" + b);
			}
		} catch (IOException | ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		//System.out.println("My Private key: "+ sk1);
		//System.out.println("Public Key: " + pk12.normalize());
		/*if(id == 1) {
			System.out.println("I am party 1");
		}else if(id == 2) {
			System.out.println("I am party 2");
		}*/
		return new Object[] {sk1,pk12};
	}
	
//	public BigInteger[] sign(BigInteger m, BigInteger sk) {
//		BigInteger k = new BigInteger(order.bitLength(), rnd);
//		ECPoint R = g.multiply(k).normalize();
//		
//		BigInteger r = R.getXCoord().toBigInteger();
//		BigInteger s = k.modInverse(order).multiply(m.add(r.multiply(sk).mod(order)).mod(order));
//		return new BigInteger[] {r,s};
//		
//	}
	
	public Object[] pSign(BigInteger m, ObjectInputStream in, ObjectOutputStream out) throws NoSuchAlgorithmException{
		ECPoint R0,R2p,RP1, RP2, R2, hisR, R1, Phi1, Phi2;
		BigInteger c = BigInteger.ONE,rho,c2,k2;
		BigInteger c1 = BigInteger.ONE;
		BigInteger k1 = BigInteger.ONE;
		BigInteger phi1 = BigInteger.ONE;
		BigInteger phi2 = BigInteger.ONE;
		Object[] ret = new Object[5];
		int bytesSent = 0;
		int bytesReceived = 0;
		
		
		
		//P1
		
			try {		
				if(id == 1) {
					ECSchnorrProver ecp = null;
					if(zkFlag) {
						ecp = new ECSchnorrProver();
					}
					k1 = ZKToolkit.random(order, rnd);
					R1 = g.multiply(k1);
					
					CryptoData pInput1 = null;
					CryptoData pSecret1 = null;
					CryptoData pEnv1 = null;
					CryptoData[] proof2 = null;
					CryptoDataCommitment comR1 = null;
					if(zkFlag) {
						pInput1 = new CryptoDataArray(new CryptoData[] {new ECPointData(R1)});
						
						
						pSecret1 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), k1});
						pEnv1 = new CryptoDataArray(new CryptoData[] {curve});
					
						//send the commitment of R1 to P2
						comR1 = pInput1.commit(pEnv1, rnd);	
						
						out.writeObject(comR1.getCommitments());
						out.flush();
						
						
					
						//receive proof2 and R1 from P2
						proof2 = (CryptoData[]) in.readObject();
					
					}
					R2 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					CryptoData pInput2 = new CryptoDataArray(new CryptoData[] {new ECPointData(R2)});
					
					CryptoData[] proof1 = null;
					if(zkFlag) {
						// verify proof2 from P2
						if (!ecp.verifyFiatShamir(pInput2, proof2[0], proof2[1], pEnv1)) 
							System.out.println("P2's proof2 failed ");
						
						//send proof1 and R1 and keys to P2
						proof1 = ecp.proveFiatShamir(pInput1, pSecret1, pEnv1);
						out.writeObject(proof1);
						out.flush();					
					}
					
					out.writeObject(R1.getEncoded(true));
					out.flush();
					
					if(zkFlag) {
						out.writeObject(comR1.getKeys());
						out.flush();
					}
					
					
					R = R2.add(R1);
					
					//Concatenating the public key, randomness and message
					MessageDigest md = MessageDigest.getInstance("SHA-256");
					ByteArrayOutputStream outByte = new ByteArrayOutputStream();
					outByte.write(pk12.getEncoded(true));
					outByte.write(R.getEncoded(true));
					outByte.write(m.toByteArray());
					e = new BigInteger(1,md.digest(outByte.toByteArray()));
					
					phi1 = k1.subtract(sk1.multiply(e));
					//System.out.println(phi1);

					Phi1 = g.multiply(phi1);
					
					CryptoData[] proof4 = null;
					CryptoDataCommitment comPhi1 = null;
					if(zkFlag) {
						CryptoData CPhi1 = new CryptoDataArray(new CryptoData[] {new ECPointData(Phi1)});
						comPhi1 = CPhi1.commit(pEnv1, rnd);
						//send the commitment of Phi1 to P2
						out.writeObject(comPhi1.getCommitments());
						out.flush();
					
					
						//receive proof4 and Phi2 from P2
						proof4 = (CryptoData[]) in.readObject();
					}
					Phi2 =  curve.getECCurveData().decodePoint((byte[]) in.readObject());
					
					CryptoData[] proof3 = null;
					if(zkFlag) {
						CryptoData pInput4 = new CryptoDataArray(new CryptoData[] {new ECPointData(Phi2)});
						// verify proof4 from P2
						if (!ecp.verifyFiatShamir(pInput4, proof4[0], proof4[1], pEnv1)) 
							System.out.println("P2's proof4 failed ");
						
						//send proof3 and Phi1 to P2
						CryptoData pInput3 = new CryptoDataArray(new CryptoData[] {new ECPointData(Phi1)});
						CryptoData pSecret3 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), phi1});
						proof3 = ecp.proveFiatShamir(pInput3, pSecret3, pEnv1);
						out.writeObject(proof3);
						out.flush();					
					}
					out.writeObject(Phi1.getEncoded(true));
					out.flush();
					
					if(zkFlag) {
						out.writeObject(comPhi1.getKeys());
						out.flush();
					}
					
					ret[0] = phi1;
					ret[1] = Phi1.normalize();
					ret[2] = Phi2.normalize();

//					System.out.println(phi1);
//					System.out.println(phi2);
//					System.out.println(Phi1);
//					System.out.println(Phi2);
					
					//counting bytes
					
					//SENT
					if(comR1 != null) {
						for(BigInteger blah : comR1.getCommitments()) {
							bytesSent += blah.bitLength()/8;
							if(blah.bitLength() % 8 != 0) bytesSent++;
						}
					}
					if(proof1 != null) {
						for(CryptoData blah : proof1) {
							bytesSent += blah.getBytes().length;
						}
					}
						bytesSent += R1.getEncoded(true).length;
					if(comR1 != null) {
						for(BigInteger b :comR1.getKeys()) {
							bytesSent += b.bitLength()/8;
							if(b.bitLength()%8 != 0) bytesSent++;
						}
					}
					if(comPhi1 != null) {
						for(BigInteger b :comPhi1.getCommitments()) {
							bytesSent += b.bitLength()/8;
							if(b.bitLength()%8 != 0) bytesSent++;
						}
					}
					if(proof3 != null) {
						for(CryptoData blah : proof3) {
							bytesSent += blah.getBytes().length;
						}
					}
						bytesSent += Phi1.getEncoded(true).length;
					if(comPhi1 != null) {
						for(BigInteger b :comPhi1.getKeys()) {
							bytesSent += b.bitLength()/8;
							if(b.bitLength()%8 != 0) bytesSent++;
						}
					}
						
					//RECEIVED
					if(proof2 != null) {
						for(CryptoData blah : proof2) {
							bytesReceived += blah.getBytes().length;
						}
					}
						bytesReceived += R2.getEncoded(true).length;
						
					if(proof4 != null) {
						for (CryptoData blah: proof4) {
							bytesReceived += blah.getBytes().length;
						}
					}
						bytesReceived += Phi2.getEncoded(true).length;
					
					
					
					
					
					
				}
				else if (id == 2) {
					ECSchnorrProver ecp = null;
					if(zkFlag) {
						ecp = new ECSchnorrProver();
					}
					k2 = ZKToolkit.random(order, rnd);
					R2 = g.multiply(k2);
					
					
					
					CryptoData pInput2 = null;
					CryptoData pSecret2 = null;
					CryptoData pEnv2  = null;
					ArrayList<BigInteger> com1 = null;
					if(zkFlag) {
						//receive commitment1 from P1
						 com1 = (ArrayList<BigInteger> ) in.readObject();
						 pInput2 = new CryptoDataArray(new CryptoData[] {new ECPointData(R2)});
						 pSecret2 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), k2});
						 pEnv2 = new CryptoDataArray(new CryptoData[] {curve});
					
						//send proof2 and R2 to P1
						CryptoData[] proof2 = ecp.proveFiatShamir(pInput2, pSecret2, pEnv2);
						out.writeObject(proof2);
						out.flush();
					}
					out.writeObject(R2.getEncoded(true));
					out.flush();
					
					CryptoData[] proof1 = null;
					if(zkFlag) {
						//receive proof1 and R1 and commitment1 keys from P1
						proof1 = (CryptoData[]) in.readObject();
					}
					R1 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					if(zkFlag) {
						CryptoData pInput1 = new CryptoDataArray(new CryptoData[] {new ECPointData(R1)});
						ArrayList<BigInteger> keyCom1 = (ArrayList<BigInteger>) in.readObject();
						if(!CryptoDataCommitment.verifyCommitment(pInput1, keyCom1, com1, pEnv2))
							System.out.println("P2's commitment failed");
						// verify proof2 from P2
						if (!ecp.verifyFiatShamir(pInput1, proof1[0], proof1[1], pEnv2)) 
							System.out.println("P2's proof2 failed ");
						
					}
			
					R = R2.add(R1);
					
					//Concatenating the public key, randomness and message
					MessageDigest md = MessageDigest.getInstance("SHA-256");
					ByteArrayOutputStream outByte = new ByteArrayOutputStream();
					outByte.write(pk12.getEncoded(true));
					outByte.write(R.getEncoded(true));
					outByte.write(m.toByteArray());
					e = new BigInteger(1,md.digest(outByte.toByteArray()));
					
					phi2 = k2.subtract(sk1.multiply(e));
					Phi2 = g.multiply(phi2);
					
					ArrayList<BigInteger> com3 = null;
					if(zkFlag) {
						//receive commitment3 of proof3 from P1
						com3 = (ArrayList<BigInteger>) in.readObject();
						//send proof4 and Phi2
						CryptoData pInput4 = new CryptoDataArray(new CryptoData[] {new ECPointData(Phi2)});
						CryptoData pSecret4 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), phi2});
						CryptoData[] proof4 = ecp.proveFiatShamir(pInput4, pSecret4, pEnv2);
						out.writeObject(proof4);
						out.flush();
					}
					
					out.writeObject(Phi2.getEncoded(true));
					out.flush();
					CryptoData[] proof3 = null;
					if(zkFlag) {
						// receive proof3 and Phi1 and keys 
						proof3 = (CryptoData[]) in.readObject();
					}
					Phi1 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					if(zkFlag) {
						CryptoData pInput3 = new CryptoDataArray(new CryptoData[] {new ECPointData(Phi1)});
						ArrayList<BigInteger> keyCom3 = (ArrayList<BigInteger>) in.readObject();
						if(!CryptoDataCommitment.verifyCommitment(pInput3, keyCom3, com3, pEnv2))
							System.out.println("P2's commitment failed");
						// verify proof3 from P2
						if (!ecp.verifyFiatShamir(pInput3, proof3[0], proof3[1], pEnv2)) 
							System.out.println("P2's proof2 failed ");
					}
					ret[0] = phi2;
					ret[1] = Phi2.normalize();
					ret[2] = Phi1.normalize();
					
//					System.out.println(phi1);
//					System.out.println(phi2);
//					System.out.println(Phi1);
//					System.out.println(Phi2);
					
					//counting bytes
					
//					//SENT
//						
//						for(CryptoData blah : proof2) {
//							bytesSent += blah.getBytes().length;
//						}
//						bytesSent += R2.getEncoded(true).length;
//						
//						for(CryptoData blah : proof4) {
//							bytesSent += blah.getBytes().length;
//						}
//						bytesSent += Phi2.getEncoded(true).length;
//						
//					//RECEIVED
//						for(BigInteger b :com1) {
//							bytesReceived += b.bitLength()/8;
//							if(b.bitLength()%8 != 0) bytesReceived++;
//						}
//						for(BigInteger b :keyCom1) {
//							bytesReceived += b.bitLength()/8;
//							if(b.bitLength()%8 != 0) bytesReceived++;
//						}
//						for(CryptoData blah : proof1) {
//							bytesReceived += blah.getBytes().length;
//						}
//						bytesReceived += R1.getEncoded(true).length;
//						
//						
//						
//						for (BigInteger b: com3) {
//							bytesReceived += b.bitLength()/8;
//							if(b.bitLength()%8 != 0) bytesReceived++;
//						}
//						for (CryptoData blah: proof3) {
//							bytesReceived += blah.getBytes().length;
//						}
//
//						bytesReceived += Phi1.getEncoded(true).length;
//						for (BigInteger b: keyCom3) {
//							bytesReceived += b.bitLength()/8;
//							if(b.bitLength()%8 != 0) bytesReceived++;
//						}
						
					
					
				}
				

				ret[3] = bytesSent;
				ret[4] = bytesReceived;
				
				

				
			} catch (IOException | ClassNotFoundException e) {
				// TODO Auto-generated catch block
				
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (MultipleTrueProofException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoTrueProofException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (ArraySizesDoNotMatchException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			
			
			return ret;
			
	
		
		
	}
	

	
	public boolean verify(BigInteger m, ECPoint pk, Object[] signature) {
		ECPoint R = (ECPoint)signature[0];
		BigInteger s = (BigInteger)signature[1];
		ByteArrayOutputStream outByte = new ByteArrayOutputStream();
		BigInteger e = BigInteger.ONE;
		
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			outByte.write(pk12.getEncoded(true));
			outByte.write(R.getEncoded(true));
			outByte.write(m.toByteArray());
			e = new BigInteger(1,md.digest(outByte.toByteArray()));
		} catch (IOException | NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
		ECPoint rhs = g.multiply(s).normalize();
		
		return rhs.equals(R.subtract(pk12.multiply(e)));
	}
	
	public Object[] complete(BigInteger phi1, BigInteger phi2) {
		BigInteger s = phi1.add(phi2).mod(order);
		return new Object[] {R,s};
		
	}
	
	public BigInteger reveal(Object[] signature, BigInteger phi) {
		ECPoint R = (ECPoint)signature[0];
		BigInteger s = (BigInteger)signature[1];
		return s.subtract(phi);
	}


	
	public CryptoData sign(BigInteger m, SecureRandom r) {
		BigInteger k0 = new BigInteger(order.bitLength(), r);
		ECPoint R0 = g.multiply(k0);
		BigInteger k1 = new BigInteger(order.bitLength(), r);
		BigInteger k2 = new BigInteger(order.bitLength(), r);
		return null;
	}


	
	public BigInteger getOrder() {
		return this.order;
	}


	@Override
	public ECPoint getPublic() {
		// TODO Auto-generated method stub
		return pk12;
	}


	@Override
	public boolean verify(BigInteger m, ECPoint pk, BigInteger[] signature) {
		// TODO Auto-generated method stub
		return false;
	}

}
