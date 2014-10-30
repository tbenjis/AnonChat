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
 * Wrapper class for the DSA signing (private) key using the JCA provider.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public class JCADSAPrivateKey extends JCADSAKey implements ca.uwaterloo.crysp.otr.crypt.DSAPrivateKey {
	
	private java.security.interfaces.DSAPrivateKey pk;
	
	/**
	 * Constructs the wrapping instance of the given DSA private key using the JCA provider.
	 * 
	 * @param pk the DSA private key.
	 */
	public JCADSAPrivateKey(java.security.interfaces.DSAPrivateKey pk) {
		this.pk = pk;
	}
	
	public java.security.interfaces.DSAParams getDSAParams() {
		return pk.getParams();
	}
	
	/**
	 * Returns the JCA instance of the DSA private key.
	 * @return the JCA instance of the DSA private key.
	 */
	public java.security.interfaces.DSAPrivateKey getDSAPrivateKey() {
		return pk;
	}

	public byte[] getX() {
		BigInteger result = pk.getX();
		return JCAMPI.toBytes(result);
	}

	public String getValue() {
		return pk.toString();
	}
}
