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

import ca.uwaterloo.crysp.otr.crypt.OTRCryptException;


import java.security.*;
/**
 * The SHA-256 hash algorithm, as implemented by the Java Cryptography
 * Architecture.
 * 
 * @author Can Tang <c24tang@gmail.com>
 */
public class JCASHA256 extends ca.uwaterloo.crysp.otr.crypt.SHA256 {
	MessageDigest sha;

	public JCASHA256() {
		super();
		try {
			sha = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	public byte[] hash() throws OTRCryptException {
		return sha.digest();
	}

	public void update(byte[] data) throws OTRCryptException {
		sha.update(data);
		
	}

	public void update(byte[] data, int offset, int length)
			throws OTRCryptException {
		sha.update(data, offset, length);

		
	}
	
	public byte[] hash(byte[] data) throws OTRCryptException {
		sha.update(data);
		return sha.digest();
	}

	public byte[] hash(byte[] data, int offset, int length)
			throws OTRCryptException {
		sha.update(data, offset, length);
		return sha.digest();
	}
	
	public boolean verify(byte[] digest, byte[] data) throws OTRCryptException {
		sha.update(data);
		byte[] trueDigest = sha.digest();
		return MessageDigest.isEqual(digest, trueDigest);
	}
	
	public boolean verify(byte[] digest, byte[] data, int offset, int length)
			throws OTRCryptException {
		sha.update(data, offset, length);
		byte[] trueDigest = sha.digest();
		return MessageDigest.isEqual(digest, trueDigest);
	}

	public String toString() {
		return sha.toString();
	}
	
	/*public static void main(String args[]) throws OTRCryptException{
		SHA256 d = new SHA256();				
		byte[] message = "Hello ".getBytes();
		byte[] message2 = "world".getBytes();
		
		d.update(message);
		d.update(message2);
		byte[] s = d.hash();
		d.hash("Hello world".getBytes());
		boolean r = d.verify(s, "Hello world".getBytes());
		System.out.println(r);
	}*/


}
