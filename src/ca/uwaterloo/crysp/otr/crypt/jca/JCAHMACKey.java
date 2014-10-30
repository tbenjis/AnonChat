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

import javax.crypto.spec.SecretKeySpec;

/**
 * Abstract class for a HMAC tagging or verification key.
 * 
 * @author Can Tang (c24tang@gmail.com)
 */
public class JCAHMACKey extends ca.uwaterloo.crysp.otr.crypt.HMACKey {
	
	private java.security.Key key;
	

	/**
	 * Constructs the wrapping instance of the given HMAC key using the JCA provider.
	 * 
	 * @param k the HMAC key.
	 */
	public JCAHMACKey(java.security.Key k) {
		this.key = k;
	}
	
	/**
	 * Constructs an HMAC key from a byte-array.
	 * @param encodedKey The encoded key.
	 */
	public JCAHMACKey(byte[] encodedKey) {
		SecretKeySpec sKeySpec = new SecretKeySpec(encodedKey, "ANYTHING");
		key = sKeySpec;
	}

	/**
	 * Returns the JCA instance of the HMAC key.
	 * @return the JCA instance of the HMAC key.
	 */
	public java.security.Key getHMACKey() {
		return key;
	}
	
	public String toString() {
	    return getValue();
	}

	/**
	 * Returns the value of the HMAC key.
	 * 
	 * @return the value of the HMAC key.
	 */
	public String getValue(){
		return key.toString();
	}
	
	public byte[] getEncoded() {
		return null;
	}
}
