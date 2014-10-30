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
 * Wrapper class for the AES key provided by the JCA framework.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public class JCAAESKey extends ca.uwaterloo.crysp.otr.crypt.AESKey {
	javax.crypto.SecretKey secretKey;
	
	/**
	 * Constructs the wrapping instance of the given AES key using the JCA provider.
	 * 
	 * @param secretKey the AES key.
	 */
	public JCAAESKey(javax.crypto.SecretKey secretKey) {
		this.secretKey = secretKey;
	}
	
	/**
	 * Constructs an AES key from a byte-array.
	 * @param encodedKey The encoded key.
	 */
	public JCAAESKey(byte[] encodedKey) {
		SecretKeySpec sKeySpec = new SecretKeySpec(encodedKey, "AES");
		secretKey = sKeySpec;
	}
	
	/**
	 * Returns the JCA instance of the secret key.
	 * 
	 * @return the JCA instance of the secret key.
	 */
	public javax.crypto.SecretKey getSecretKey() {
		return secretKey;
	}

	public String toString() {
		return secretKey.toString();
	}
	
	public byte[] getEncoded() {
		return secretKey.getEncoded();
	}
	
	/*public static void main(String[] args) {
		byte[] content = {(byte) 0x01, (byte) 0x02, (byte) 0xff, (byte) 0xde, (byte) 0xab};
		
		AESKey k = new AESKey(content);
		byte[] encodedKey = k.getEncoded();
		
		// Verify key encoding & decoding
		for (int i = 0; i < encodedKey.length; i++) {
			if (content[i] != encodedKey[i]) {
				System.out.println("Byte mismatch.");
			}
		}
		
		System.out.println("Key check done.");
	}*/
}
