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
 * Private key for the Diffie Hellman key exchange. Consists of a single BigInteger value.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public class JCADHPrivateKey extends JCADHKey implements ca.uwaterloo.crysp.otr.crypt.DHPrivateKey {
	private BigInteger priv;
	public JCADHPrivateKey(BigInteger val) {
		super(JCADHKeyPairGenerator.DH_G,
				JCADHKeyPairGenerator.DH_P);
		priv = val;
	}

	public byte[] getX() {
		return JCAMPI.toBytes(priv);
	}
	
	public String toString() {
		return priv.toString();
	}
}
