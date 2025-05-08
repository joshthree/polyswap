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
import zero_knowledge_proofs.ECEqualDiscreteLogsProver;
import zero_knowledge_proofs.ECSchnorrProver;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.CryptoDataCommitment;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class SSSCRYPTO implements SecretSharingSignature{
	
	private boolean zkFlag = true;
		
	public SSSCRYPTO(int id) {
		this.initializeParameters("Curve25519");
		this.id = id;
	}
	
	public SSSCRYPTO(int id, boolean zkFlag) {
		this.initializeParameters("Curve25519");
		this.id = id;
		this.zkFlag = zkFlag;
	}
	
	int id;
	private ECCurveData curve;
	private ECCurve c;
	private static ECPoint g,R;
	private BigInteger b1,b2,a1,a2,a;
	private ECPoint  B, A;
	
	private SecureRandom rnd;

	private BigInteger order, sp, k2, r,e;
	
	
	public void initializeParameters(String curveName) {
		g = ECNamedCurveTable.getParameterSpec(curveName).getG();		
		c = g.getCurve();
		curve = new ECCurveData(c,g);
		order = c.getOrder();
		rnd = new SecureRandom();
	}
	
//	public BigInteger[] release(BigInteger a, ObjectInputStream in, ObjectOutputStream out) {
//		
//		
//				try {
//					out.writeObject(a);
//					out.flush();
//					BigInteger hisA = (BigInteger)in.readObject();
//					BigInteger s =  hisA.modInverse(order).multiply(a).mod(order);
//					if(id == 2) {
//						s = a.modInverse(order).multiply(hisA).mod(order);
//					}
//					return new BigInteger[] {this.r,s};
//				} catch (IOException | ClassNotFoundException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
//				
//				
//				return new BigInteger[] {};	
//	
//		
//
//
//	}
	
	public Object[] keygen2p(SecureRandom r, ObjectInputStream in, ObjectOutputStream out) {
		
		ECPoint B1,B2;
		BigInteger sk = BigInteger.ONE;
		try {
			if (id == 1) {
				b1 = ZKToolkit.random(order, r);
				B1 = g.multiply(b1);
				

				// send B1
				out.writeObject(B1.getEncoded(true));
				out.flush();
				
				//receive B2
				B2 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
				B = B2.add(B1);
				
				a1 = ZKToolkit.random(order, r);
				

				// send a1
				out.writeObject(a1);
				out.flush();
				
				//receive a2
				a2 = ((BigInteger) in.readObject());
				a = a1.add(a2);
				A = g.multiply(a);
				
				sk  = b1;
				
			} else if (id == 2) {
				b2 = ZKToolkit.random(order, r);
				B2 = g.multiply(b2);
				
				//receive B1
				B1 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
				B = B1.add(B2);
				
				//send B2
				out.writeObject(B2.getEncoded(true));
				out.flush();
				
				
				a2 = ZKToolkit.random(order, r);
				//receive a1
				a1 = ((BigInteger) in.readObject());
				
				//send a2
				out.writeObject(a2);
				out.flush();
				
				a = a1.add(a2);
				A = g.multiply(a);
				
				sk= b2;
				
				{
					int b = 0;
					b += B1.getEncoded(true).length;
					b += B2.getEncoded(true).length;
					b += (a1.bitLength()/8);
					b += (a1.bitLength()/8);
					//System.out.println("Cryptonote bytes:" + b);
				}
			}
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
//		System.out.println("Private key part for Spend key: "+ sk);
//
//		System.out.println("Private View key: "+ a);
//
//		System.out.println("Public View key: "+ A);
//		System.out.println("Public Spend Key: " + B.normalize());
		
		return new Object[] {sk,B};
	}
	
	
	private ECPoint HashPoint(ECPoint x) {
		return g.add(x);
	}
	
	private BigInteger HashScalar(ECPoint x) throws NoSuchAlgorithmException {
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return new BigInteger(1,md.digest(x.getEncoded(true)));
	}
	
	public Object[] pSign(BigInteger m, ObjectInputStream in, ObjectOutputStream out) throws NoSuchAlgorithmException {
		ECPoint I1, I2, L1, L2, R1, R2, P1, P2, I, L, R, Phi1, Phi2, L1p, R1p, L2p, R2p;
		BigInteger x1 = BigInteger.ONE,x2,q1,q2,r1,r2,cj;
		
		ECPoint Ps;
		
		ECPoint Rs = g.multiply(ZKToolkit.random(order, rnd));
		
		BigInteger phi1 = BigInteger.ONE;
		BigInteger phi2 = BigInteger.ONE;
		Object[] ret = new Object[4];
		int b = 0;
		
		//P1
		
			try {		
				if(id == 1) {
					
					
					ECEqualDiscreteLogsProver ecp = null;
					if(zkFlag) {
						ecp = new ECEqualDiscreteLogsProver();
					}
					
					x1 = b1;
					
					ECPoint X1 = g.multiply(x1);
					
					//send X1
					out.writeObject(X1.getEncoded(true));
					out.flush();
					
					//receive X2
					ECPoint X2 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					
					Ps = X1.add(X2);
					
					
					
					//send R
					out.writeObject(Rs.getEncoded(true));
					out.flush();
				
					
					
					q1 = ZKToolkit.random(order, rnd);
					I1 = HashPoint(Ps).multiply(x1);
					L1 = g.multiply(q1);
					R1 = HashPoint(Ps).multiply(q1);
					P1 = g.multiply(x1); 
					
					CryptoData environment = null;
					CryptoData[] proof1 = null;
					CryptoData[] proof2 = null;
					CryptoDataCommitment proof1Commitment = null;
					CryptoDataCommitment proof2Commitment = null;
					if(zkFlag) {
						environment = new CryptoDataArray(new CryptoData[] {curve, new ECPointData(HashPoint(Ps))});
						
						CryptoData secrets1 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), x1});
						CryptoData publicInput1 = new CryptoDataArray(new CryptoData[] {new ECPointData(P1), new ECPointData(I1)});
						CryptoData secrets2 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), q1});
						CryptoData publicInput2 = new CryptoDataArray(new CryptoData[] {new ECPointData(L1), new ECPointData(R1)});
						
						proof1 = ecp.proveFiatShamir(publicInput1, secrets1, environment);
						proof2 = ecp.proveFiatShamir(publicInput2, secrets2, environment);
					    proof1Commitment = new CryptoDataArray(proof1).commit(environment, rnd);
						proof2Commitment = new CryptoDataArray(proof2).commit(environment, rnd);
						
						//send proof1com and proof2com
						out.writeObject(proof1Commitment.getCommitments());
						out.flush();
						out.writeObject(proof2Commitment.getCommitments());
						out.flush();
					}
					//receive P2,I2,L2,R2
					P2 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					I2 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					L2 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					R2 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					
					if(zkFlag) {
						//receive proof3 and proof4
						CryptoData[] proof3 = (CryptoData[]) in.readObject();
						CryptoData[] proof4 = (CryptoData[]) in.readObject();
						CryptoData publicInput3 = new CryptoDataArray(new CryptoData[] {new ECPointData(P2), new ECPointData(I2)});
						CryptoData publicInput4 = new CryptoDataArray(new CryptoData[] {new ECPointData(L2), new ECPointData(R2)});
						
						//verify proof3 and proof4
						if (!ecp.verifyFiatShamir(publicInput3, proof3[0], proof3[1], environment)) 
							System.out.println("P2's proof3 failed ");
						if (!ecp.verifyFiatShamir(publicInput4, proof4[0], proof4[1], environment)) 
							System.out.println("P2's proof4 failed ");
						
					}
					
					
					
					
					//send P1,I1,L1,R1
					
					out.writeObject(P1.getEncoded(true));
					out.flush();
					out.writeObject(I1.getEncoded(true));
					out.flush();
					out.writeObject(L1.getEncoded(true));
					out.flush();
					out.writeObject(R1.getEncoded(true));
					out.flush();
					
					I = I1.add(I2);
					L = L1.add(L2);
					R = R1.add(R2);

					if(zkFlag) {
						//send proof1 and proof2
						out.writeObject(proof1);
						out.flush();
						out.writeObject(proof2);
						out.flush();
						
						//send proof1commitment keys and proof2commitment keys
						out.writeObject(proof1Commitment.getKeys());
						out.flush();
						out.writeObject(proof2Commitment.getKeys());
						out.flush();
					}
					//send cj
					cj = ZKToolkit.random(order, rnd);
					out.writeObject(cj);
					out.flush();
					
					r1 = q1.subtract(cj.multiply(x1));
					L1p = g.multiply(r1);
					R1p = HashPoint(Ps).multiply(r1);
					
					CryptoData[] proof5 = null;
					CryptoDataCommitment proof5Commitment = null;
					if(zkFlag) {
						CryptoData secrets5  = new CryptoDataArray(new BigInteger[]{ZKToolkit.random(order, rnd), r1});
						CryptoData publicInput5 = new CryptoDataArray(new CryptoData[] {new ECPointData(L1p), new ECPointData(R1p)});
						proof5 = ecp.proveFiatShamir(publicInput5, secrets5, environment);
						
						// send proof5 commitment
						proof5Commitment = new CryptoDataArray(proof5).commit(environment, rnd);
						out.writeObject(proof5Commitment.getCommitments());
						out.flush();
					}
					
					
					
					//receive L2p, R2p
					L2p = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					R2p =  curve.getECCurveData().decodePoint((byte[]) in.readObject());
					
					if(zkFlag) {
						//receive proof6 
						CryptoData[] proof6 = (CryptoData[]) in.readObject();
						CryptoData publicInput6 = new CryptoDataArray(new CryptoData[] {new ECPointData(L2p), new ECPointData(R2p)});
						
						//verify proof6 
					
						if (!ecp.verifyFiatShamir(publicInput6, proof6[0], proof6[1], environment)) 
							System.out.println("P2's proof6 failed ");
					}
					if(!L.equals(L1p.add(L2p).add(Ps.multiply(cj)))) {
						System.out.println("verification 1 failed for p2's data");
					}
					
					if(!R.equals(R1p.add(R2p).add(I.multiply(cj)))) {
						System.out.println("verification 2 failed for p2's data");
					}
					
					//send L1p, R1p
					out.writeObject(L1p.getEncoded(true));
					out.flush();
					out.writeObject(R1p.getEncoded(true));
					out.flush();
					
					if(zkFlag) {
						//send proof5				
						out.writeObject(proof5);
						out.flush();
						
						//send proof5commitment keys
						out.writeObject(proof5Commitment.getKeys());
						out.flush();
					}
					phi1 = r1;
					Phi1 = L1;
					Phi2 = L2;
					
					ret[0] = phi1;
					ret[1] = Phi1.normalize();
					ret[2] = Phi2.normalize();
					
					
					
					
					
					
					
				}
				else if (id == 2) {
					ECEqualDiscreteLogsProver ecp  = null;
					if(zkFlag) {
						ecp = new ECEqualDiscreteLogsProver();
					}
					x2 = b2.add(HashScalar(Rs.multiply(a)));
					
					//receive X1
					ECPoint X1 = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					
					//send X2
					ECPoint X2 = g.multiply(x2);
					out.writeObject(X2.getEncoded(true));
					out.flush();
					
					Ps = X1.add(X2);
					
					
					//Receive Rs
					Rs = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					
					CryptoData environment = null;
					if(zkFlag) {
						environment = new CryptoDataArray(new CryptoData[] {curve, new ECPointData(HashPoint(Ps))});
					}
					
					q2 = ZKToolkit.random(order, rnd);
					I2 = HashPoint(Ps).multiply(x2);
					L2 = g.multiply(q2);
					R2 = HashPoint(Ps).multiply(q2);
					P2 = g.multiply(x2); 
					
					ArrayList<BigInteger> proof1Commitment = null;
					ArrayList<BigInteger> proof2Commitment = null;
					if(zkFlag) {
						//receive proof1 commitment and proof2 commitment
						proof1Commitment = (ArrayList<BigInteger>) in.readObject();
						proof2Commitment = (ArrayList<BigInteger>) in.readObject();
					}
					//send P2,I2,L2,R2
					out.writeObject(P2.getEncoded(true));
					out.flush();
					out.writeObject(I2.getEncoded(true));
					out.flush();
					out.writeObject(L2.getEncoded(true));
					out.flush();
					out.writeObject(R2.getEncoded(true));
					out.flush();
					
					CryptoData[] proof3 = null;
					CryptoData[] proof4 = null;
					if(zkFlag) {
						// send proof3 and proof4
						CryptoData publicInput3 = new CryptoDataArray(new CryptoData[] {new ECPointData(P2), new ECPointData(I2)});
						CryptoData publicInput4 = new CryptoDataArray(new CryptoData[] {new ECPointData(L2), new ECPointData(R2)});
						CryptoData secret3 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), x2});
						CryptoData secret4 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), q2});
						
	
						proof3 = ecp.proveFiatShamir(publicInput3, secret3, environment);
						proof4 = ecp.proveFiatShamir(publicInput4, secret4, environment);
						
						out.writeObject(proof3);
						out.flush();
						
						out.writeObject(proof4);
						out.flush();
						
					}
					//receive P1,I1,L1,R1
					
					P1 =  curve.getECCurveData().decodePoint((byte[]) in.readObject());
					I1 =  curve.getECCurveData().decodePoint((byte[]) in.readObject());
					L1 =  curve.getECCurveData().decodePoint((byte[]) in.readObject());
					R1 =  curve.getECCurveData().decodePoint((byte[]) in.readObject());
					
					I = I1.add(I2);
					L = L1.add(L2);
					R = R1.add(R2);
					
					CryptoData[] proof1 = null;
					CryptoData[] proof2 = null;
					ArrayList<BigInteger> proof1commitmentkeys = null;
					ArrayList<BigInteger> proof2commitmentkeys =  null;
					if(zkFlag) {
						//receive proof1 and proof2
						proof1 = (CryptoData[]) in.readObject();
						proof2 = (CryptoData[]) in.readObject();
						CryptoData publicInput1 = new CryptoDataArray(new CryptoData[] {new ECPointData(P1), new ECPointData(I1)});
						CryptoData publicInput2 = new CryptoDataArray(new CryptoData[] {new ECPointData(L1), new ECPointData(R1)});
						
						//receive proof1commitment keys and proof2commitment keys
						proof1commitmentkeys = (ArrayList<BigInteger>) in.readObject();
						proof2commitmentkeys = (ArrayList<BigInteger>) in.readObject();
						
						//verify proof1commitment and proof2commitment
						if(!CryptoDataCommitment.verifyCommitment(new CryptoDataArray(proof1), proof1commitmentkeys, proof1Commitment, environment))
							System.out.println("P1's proof1commitment failed");
						if(!CryptoDataCommitment.verifyCommitment(new CryptoDataArray(proof2), proof2commitmentkeys, proof2Commitment, environment))
							System.out.println("P1's proof2commitment failed");
						
						// verify proof1 and proof2
						if (!ecp.verifyFiatShamir(publicInput1, proof1[0], proof1[1], environment)) 
							System.out.println("P1's proof1 failed ");
						if (!ecp.verifyFiatShamir(publicInput2, proof2[0], proof2[1], environment)) 
							System.out.println("P1's proof2 failed ");
					}
					//receive cj
					cj = (BigInteger)in.readObject();
					
					
					r2 = q2.subtract(cj.multiply(x2));
					L2p = g.multiply(r2);
					R2p = HashPoint(Ps).multiply(r2);
					
					ArrayList<BigInteger> poof5Commitments = null;
					if(zkFlag) {
						//receive proof5Commitments
						poof5Commitments = (ArrayList<BigInteger>) in.readObject();
						
					}
					
					//send L2p, R2p
					out.writeObject(L2p.getEncoded(true));
					out.flush();
					out.writeObject(R2p.getEncoded(true));
					out.flush();
					
					CryptoData[] proof6 = null;
					if(zkFlag) {
						//send proof6
						CryptoData publicInput6 = new CryptoDataArray(new CryptoData[] {new ECPointData(L2p), new ECPointData(R2p)});
						CryptoData secret6 = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rnd), r2});
						proof6 = ecp.proveFiatShamir(publicInput6, secret6, environment);
						out.writeObject(proof6);
						out.flush();
					}
					//receive L1p, R1p
					L1p = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					R1p = curve.getECCurveData().decodePoint((byte[]) in.readObject());
					
					CryptoData publicInput5 = null;
					if(zkFlag) {
						publicInput5 = new CryptoDataArray(new CryptoData[] {new ECPointData(L1p), new ECPointData(R1p)});
					}
					
					
					if(!R.equals(R1p.add(R2p).add(I.multiply(cj)))) {
						System.out.println("verification 2 failed for p1's data");
					}
					
					CryptoData[] proof5 = null;
					ArrayList<BigInteger> proof5Commitmentkeys = null;
					if(zkFlag) {
						//receive proof5
						proof5 = (CryptoData[]) in.readObject();
						
						//receive proof5Commitment keys
						proof5Commitmentkeys = (ArrayList<BigInteger>) in.readObject();
						
						//verify proof5commitment
						if(!CryptoDataCommitment.verifyCommitment(new CryptoDataArray(proof5), proof5Commitmentkeys, poof5Commitments, environment))
							System.out.println("P1's proof5commitment failed");
						if (!ecp.verifyFiatShamir(publicInput5, proof5[0], proof5[1], environment)) 
							System.out.println("P1's proof5 failed ");
						if(!L.equals(L1p.add(L2p).add(Ps.multiply(cj)))) {
							System.out.println("verification 1 failed for p1's data");
						}
					}
					
					phi2 = r2;
					Phi1 = L2.normalize();
					Phi2 = L1.normalize();
					
					ret[0] = phi2;
					ret[1] = Phi2;
					ret[2] = Phi1;
					
					//Byte count
					
					
					b+=X1.getEncoded(true).length;
					b+=X2.getEncoded(true).length;
					b+=Rs.getEncoded(true).length;
					if(proof1Commitment != null) {
						for(BigInteger k: proof1Commitment) {
							b += k.bitLength()/8;
							if(k.bitLength()%8 != 0) b++;
						}
					}
					if(proof2Commitment != null) {
						for(BigInteger k: proof2Commitment) {
							b += k.bitLength()/8;
							if(k.bitLength()%8 != 0) b++;
						}
					}
					b+=P2.getEncoded(true).length;
					b+=I2.getEncoded(true).length;
					b+=L2.getEncoded(true).length;
					b+=R2.getEncoded(true).length;
					if(proof3 != null) {
						for(CryptoData blah : proof3) {
							b += blah.getBytes().length;
						}
					}
					if(proof4 != null) {
						for(CryptoData blah : proof4) {
							b += blah.getBytes().length;
						}
					}
					b+=P1.getEncoded(true).length;
					b+=I1.getEncoded(true).length;
					b+=L1.getEncoded(true).length;
					b+=R1.getEncoded(true).length;
					if(proof1 != null) {
						for(CryptoData blah : proof1) {
							b += blah.getBytes().length;
						}
					}
					if(proof2 != null) {
						for(CryptoData blah : proof2) {
							b += blah.getBytes().length;
						}
					}
					if(proof1commitmentkeys != null) {
						for(BigInteger k: proof1commitmentkeys) {
							b += k.bitLength()/8;
							if(k.bitLength()%8 != 0) b++;
						}
					}
					if(proof2commitmentkeys != null) {
						for(BigInteger k: proof2commitmentkeys) {
							b += k.bitLength()/8;
							if(k.bitLength()%8 != 0) b++;
						}
					}
					b+=cj.bitLength()/8;
					if(poof5Commitments != null) {
						for(BigInteger k: poof5Commitments) {
							b += k.bitLength()/8;
							if(k.bitLength()%8 != 0) b++;
						}
					}
					b+=L2p.getEncoded(true).length;
					b+=R2p.getEncoded(true).length;
					if(proof6 != null) {
						for(CryptoData blah : proof6) {
							b += blah.getBytes().length;
						}
					}
					b+=L1p.getEncoded(true).length;
					b+=R1p.getEncoded(true).length;
					if(proof5 != null) {
						for(CryptoData blah : proof5) {
							b += blah.getBytes().length;
						}
					}
					if(proof5Commitmentkeys != null) {
					for(BigInteger k: proof5Commitmentkeys) {
						b += k.bitLength()/8;
						if(k.bitLength()%8 != 0) b++;
					}
					}
					
				
				
				}
				ret[3] =  b;

				
			} catch (IOException | ClassNotFoundException | MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException   e) {
				// TODO Auto-generated catch block
				
				e.printStackTrace();
			} 
			
//			System.out.println("My unlocking secret: " + ret[0]);
//			System.out.println("My unlocking secret public form: " + ret[1]);
//			System.out.println("Their unlocking secret public form: " + ret[2]);
			
			
			
			return ret;
			
			
		
		
		//BigInteger sp = k0.modInverse(order).multiply(c);
		//return new BigInteger[] {sp,k2, r};
	}
	

	
	public boolean verify(BigInteger m, ECPoint pk, Object[] signature) {
		ECPoint R = (ECPoint)signature[0];
		BigInteger s = (BigInteger)signature[1];
		ByteArrayOutputStream outByte = new ByteArrayOutputStream();
		BigInteger e = BigInteger.ONE;
		
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			outByte.write(B.getEncoded(true));
			outByte.write(R.getEncoded(true));
			outByte.write(m.toByteArray());
			e = new BigInteger(1,md.digest(outByte.toByteArray()));
		} catch (IOException | NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
		ECPoint rhs = g.multiply(s).normalize();
		
		return rhs.equals(R.subtract(pk.multiply(e)));
	}
	
	public Object[] complete(BigInteger phi1, BigInteger phi2) {
		BigInteger r = phi1.add(phi2).mod(order);
		return new Object[] {r};
		
	}
	
	public BigInteger reveal(Object[] signature, BigInteger phi) {
		
		BigInteger s = (BigInteger)signature[0];
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
		return null;
	}

	@Override
	public boolean verify(BigInteger m, ECPoint pk, BigInteger[] signature) {
		// TODO Auto-generated method stub
		return false;
	}

}
