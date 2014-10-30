/*
 *  Java OTR library
 *  Copyright (C) 2008-2009  Ian Goldberg, Muhaimeen Ashraf, Andrew Chung,
 *                           Can Tang
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 2.1 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package ca.uwaterloo.crysp.otr.crypt.jca;

import ca.uwaterloo.crysp.otr.crypt.*;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * The DSA digital signature algorithm, as implemented by the Java Cryptography
 * Architecture.
 * 
 * @author Can Tang <c24ang@gmail.com>
 */
public class JCARawDSA extends ca.uwaterloo.crysp.otr.crypt.RawDSA {
	//private java.security.Signature sig;

	public JCARawDSA() {
		super();
	}

	public byte[] sign(PrivateKey priv, byte[] data)
			throws OTRCryptException{
		Sig ss = new Sig();
		ss.initSign((JCADSAPrivateKey)priv);
		byte[] ret = ss.sign(data);
		return ret;
	}
	
	public boolean verify(PublicKey pub, byte[] signature, byte[] data)
			throws OTRCryptException{
		Sig ss = new Sig();
		ss.initVerify((JCADSAPublicKey)pub);
		return ss.verify(signature, data);
	}

	class Sig{
		JCADSAPrivateKey priv;
		JCADSAPublicKey pub;
		
		void initSign(JCADSAPrivateKey p){
			priv = p;
		}
		
		void initVerify(JCADSAPublicKey p){
			pub = p;
		}
		
		byte[] sign(byte[] data) throws OTRCryptException{
			BigInteger p = JCAMPI.fromBytes(priv.getP());
			BigInteger q = JCAMPI.fromBytes(priv.getQ());
			BigInteger g = JCAMPI.fromBytes(priv.getG());
			BigInteger x = JCAMPI.fromBytes(priv.getX());
			
			BigInteger m = new BigInteger(1,data);
			try {
				SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
				BigInteger k = new BigInteger(q.bitLength(), random);
				while(k.compareTo(q)==1){
					k = new BigInteger(q.bitLength(), random);
				}

				BigInteger r = g.modPow(k, p).mod(q);
				BigInteger s = k.modInverse(q).multiply(m.add(x.multiply(r))).mod(q);
				byte[] rr = r.toByteArray();
				byte[] ss = s.toByteArray();
				int rstart=0, sstart=0;
				while(rr[rstart]==0){ rstart++;}
				while(ss[sstart]==0){ sstart++;}
				byte[] ret = new byte[40];

				System.arraycopy(rr, rstart, ret, 20-(rr.length-rstart), (rr.length-rstart));
				System.arraycopy(ss, sstart, ret, 40-(ss.length-sstart), (ss.length-sstart));
			
				return ret;
				
			} catch (NoSuchAlgorithmException e) {
				throw new OTRCryptException(e);
			}
			
		}
		
		boolean verify(byte[] signature, byte[] data)
			    throws OTRCryptException{
			BigInteger p = JCAMPI.fromBytes(pub.getP());
			BigInteger q = JCAMPI.fromBytes(pub.getQ());
			BigInteger g = JCAMPI.fromBytes(pub.getG());
			BigInteger y = JCAMPI.fromBytes(pub.getY());

			BigInteger m = new BigInteger(1, data);
			byte[] rr = new byte[20];
			byte[] ss = new byte[20];
			System.arraycopy(signature, 0, rr, 0, 20);
			System.arraycopy(signature, 20, ss, 0, 20);
			BigInteger r = new BigInteger(1, rr);
			BigInteger s = new BigInteger(1, ss);
			
			if(r.compareTo(q)>=0 || s.compareTo(q)>=0 ||
					r.compareTo(BigInteger.ZERO)==0 ||
					s.compareTo(BigInteger.ZERO)==0 ){
				return false;
			}
			BigInteger w = s.modInverse(q);
			BigInteger u1 = m.multiply(w).mod(q);
			BigInteger u2 = r.multiply(w).mod(q);
			BigInteger v = g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q);
			

			
			return v.compareTo(r)==0;
		}
		
	}
}
