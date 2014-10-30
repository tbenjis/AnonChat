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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.spec.DSAPublicKeySpec;

import ca.uwaterloo.crysp.otr.crypt.*;

/**
 * Wrapper class for the DSA verification (public) key using the JCA provider.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public class JCADSAPublicKey extends JCADSAKey 
implements ca.uwaterloo.crysp.otr.crypt.DSAPublicKey {
	
	private java.security.interfaces.DSAPublicKey pk;

	// Serialize buffer
	private byte[] ser;
	
	public java.security.interfaces.DSAParams getDSAParams() {
		return pk.getParams();
	}

	/**
	 * Returns the JCA instance of the DSA public key.
	 * @return the JCA instance of the DSA public key.
	 */
	public java.security.interfaces.DSAPublicKey getDSAPublicKey() {
		return pk;
	}
	
	public byte[] getY() {
		BigInteger result = pk.getY();
		return JCAMPI.toBytes(result);
	}

	public String getValue() {
		return pk.toString();
	}


	public byte[] serialize() {
		return ser;
	}

	public JCADSAPublicKey(BigInteger p, BigInteger q, BigInteger g,
			BigInteger y) throws Exception{
		DSAPublicKeySpec pubspec = new DSAPublicKeySpec(y, p, q, g);
		java.security.KeyFactory kfac = java.security.KeyFactory.getInstance("DSA", "SUN");
		this.pk=(java.security.interfaces.DSAPublicKey) kfac
						.generatePublic(pubspec);
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    try {
			baos.write(JCAMPI.toBytes(pk.getParams().getP()));
			baos.write(JCAMPI.toBytes(pk.getParams().getQ()));
			baos.write(JCAMPI.toBytes(pk.getParams().getG()));
			baos.write(JCAMPI.toBytes(pk.getY()));
	    } catch (java.io.IOException e) {
	    	throw new OTRCryptException(e);
	    }
	    ser = baos.toByteArray();
		
	}
	
	public JCADSAPublicKey(MPI p, 
			MPI q, 
			MPI g,
			MPI y) throws Exception{
		DSAPublicKeySpec pubspec = new DSAPublicKeySpec(
				JCAMPI.fromTrimmedBytes(y.getValue()), 
				JCAMPI.fromTrimmedBytes(p.getValue()),
				JCAMPI.fromTrimmedBytes(q.getValue()),
				JCAMPI.fromTrimmedBytes(g.getValue()));
		java.security.KeyFactory kfac = java.security.KeyFactory.getInstance("DSA", "SUN");
		this.pk=(java.security.interfaces.DSAPublicKey) kfac
						.generatePublic(pubspec);
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    try {
			baos.write(JCAMPI.toBytes(pk.getParams().getP()));
			baos.write(JCAMPI.toBytes(pk.getParams().getQ()));
			baos.write(JCAMPI.toBytes(pk.getParams().getG()));
			baos.write(JCAMPI.toBytes(pk.getY()));
	    } catch (java.io.IOException e) {
	    	throw new OTRCryptException(e);
	    }
	    ser = baos.toByteArray();
		
	}
	
	public JCADSAPublicKey(java.security.interfaces.DSAPublicKey pk) throws OTRCryptException{
		this.pk=pk;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
		baos.write(JCAMPI.toBytes(pk.getParams().getP()));
		baos.write(JCAMPI.toBytes(pk.getParams().getQ()));
		baos.write(JCAMPI.toBytes(pk.getParams().getG()));
		baos.write(JCAMPI.toBytes(pk.getY()));
		} catch (java.io.IOException e) {
		throw new OTRCryptException(e);
		}
		ser = baos.toByteArray();
	}


}
