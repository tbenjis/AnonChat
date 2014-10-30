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

/**
 * Public key for the Diffie Hellman key exchange. Consists of a single BigInteger value.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public class JCADHPublicKey extends JCADHKey implements ca.uwaterloo.crysp.otr.crypt.DHPublicKey {
	private BigInteger pub;

	public JCADHPublicKey(ca.uwaterloo.crysp.otr.crypt.MPI val) {
		super(JCADHKeyPairGenerator.DH_G,
				JCADHKeyPairGenerator.DH_P);
		pub = JCAMPI.getBigInteger(val);
	}
	
	public byte[] getY() {
		return JCAMPI.toBytes(pub);
	}

	public byte[] serialize() {
		return getY();
	}
	
	public String toString() {
		return pub.toString();
	}
}
