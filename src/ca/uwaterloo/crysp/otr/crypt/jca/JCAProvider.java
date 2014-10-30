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

import java.math.BigInteger;

import ca.uwaterloo.crysp.otr.OTRException;
import ca.uwaterloo.crysp.otr.crypt.*;

/**
 * The JCA crypto provider.
 * 
 * @author Ian Goldberg <iang@cs.uwaterloo.ca>
 */
public class JCAProvider extends ca.uwaterloo.crysp.otr.crypt.Provider {
	public RawDSA getRawDSA() {
		return new JCARawDSA();
	}

	public DSAKeyPairGenerator getDSAKeyPairGenerator() {
		return new JCADSAKeyPairGenerator();
	}

	public SHA1 getSHA1() {
		return new JCASHA1();
	}
	
	public SHA256 getSHA256() {
		return new JCASHA256();
	}

	public HMAC getHMAC() {
		return new JCAHMACSHA256();
	}

	public AESCTR getAESCounterMode(SecretKey key, byte[] ctrHigh) throws OTRCryptException {
		return new JCAAESCTR(key, ctrHigh);
	}

	public SecureRandom getSecureRandom() {
		return new JCASecureRandom();
	}

	public DHKeyPairGenerator getDHKeyPairGenerator() {
		return new JCADHKeyPairGenerator();
	}

	public AESKey getAESKey(byte[] r) {
		return new JCAAESKey(r);
	}

	public HMACKey getHMACKey(byte[] encoded) {
		return new JCAHMACKey(encoded);
	}
	
	public HMAC getHMACSHA1() {
		return new JCAHMACSHA1();
	}

	public HMAC getHMACSHA256() {
		return new JCAHMACSHA256();
	}

	public DSAPublicKey getDSAPublicKey
	(ca.uwaterloo.crysp.otr.crypt.MPI p, 
			ca.uwaterloo.crysp.otr.crypt.MPI q, 
			ca.uwaterloo.crysp.otr.crypt.MPI g, 
			ca.uwaterloo.crysp.otr.crypt.MPI y) throws Exception {
		return new JCADSAPublicKey(p, q, g, y);
	}

	public DHPublicKey getDHPublicKey(ca.uwaterloo.crysp.otr.crypt.MPI val) {
		return new JCADHPublicKey(val);
	}

	public DHKeyAgreement getDHKeyAgreement() {
		return new JCADHKeyAgreement();
	}

	public int compareMPI(ca.uwaterloo.crysp.otr.crypt.MPI ours,
			ca.uwaterloo.crysp.otr.crypt.MPI theirs) {
		BigInteger bi_ours = JCAMPI.getBigInteger(ours);
		BigInteger bi_theirs = JCAMPI.getBigInteger(theirs);
		return bi_ours.compareTo(bi_theirs);
	}

	public HMACKeyGenerator getHMACKeyGenerator() {
		return new JCAHMACKeyGenerator();
	}

	public MPI powm(MPI base, MPI exp, MPI mod) throws OTRException {
		BigInteger b = JCAMPI.getBigInteger(base);
		BigInteger e = JCAMPI.getBigInteger(exp);
		BigInteger m = JCAMPI.getBigInteger(mod);
		BigInteger res = b.modPow(e, m);
		return JCAMPI.toMPI(res);
	}

	public MPI mulm(MPI a, MPI b, MPI mod) throws OTRException {
		BigInteger ba = JCAMPI.getBigInteger(a);
		BigInteger bb = JCAMPI.getBigInteger(b);
		BigInteger m = JCAMPI.getBigInteger(mod);
		BigInteger res = ba.multiply(bb).mod(m);
		return JCAMPI.toMPI(res);
	}

	public MPI subm(MPI a, MPI b, MPI mod) throws OTRException {
		BigInteger ba = JCAMPI.getBigInteger(a);
		BigInteger bb = JCAMPI.getBigInteger(b);
		BigInteger m = JCAMPI.getBigInteger(mod);
		BigInteger res = ba.subtract(bb).mod(m);
		return JCAMPI.toMPI(res);
	}

	public MPI invm(MPI a, MPI mod) throws OTRException {
		BigInteger ba = JCAMPI.getBigInteger(a);
		BigInteger m = JCAMPI.getBigInteger(mod);
		BigInteger res = ba.modInverse(m);
		return JCAMPI.toMPI(res);
	}

}
