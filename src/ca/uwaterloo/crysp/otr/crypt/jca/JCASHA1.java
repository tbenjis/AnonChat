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
 * The SHA-1 hash algorithm, as implemented by the Java Cryptography
 * Architecture.
 * 
 * @author Can Tang <c24tang@gmail.com>
 */
public class JCASHA1 extends ca.uwaterloo.crysp.otr.crypt.SHA1 {
	MessageDigest sha;

	public JCASHA1() {
		super();
		try {
			sha = MessageDigest.getInstance("SHA-1");
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
	
	/*public static void main(String args[]) throws Exception{
		SHA1 sha = new SHA1();
		byte[] msg1 = "Test message 1".getBytes();
		byte[] digest1;
		try {
			digest1 = sha.hash(msg1);

			byte[] msg2 = "Another test message".getBytes();
			AuthInfo.checkBytes("msg1", digest1);
			System.out.println(sha.verify(digest1, msg1));
			System.out.println(sha.verify(digest1, msg2));
		} catch (OTRCryptException e) {
			e.printStackTrace();
		}
		byte[] msg3 ="c7d54f4c520b7adfe3a85b3f2b7d66cf20afc9b54bcc934c395057de18148947".getBytes();
		msg3 = fromHex(msg3);
		sha = new SHA1();
		digest1 = sha.hash(msg3);
		AuthInfo.checkBytes("digest", digest1);
		

	}*/
	public static byte[] fromHex(byte[] msg){
		byte[] ret = new byte[msg.length/2];
		for(int i=0; i<msg.length; i++){
			if(msg[i]<=57) msg[i]-=48;
			else msg[i]-=87;
			if(i%2==0) ret[i/2]+=(msg[i]<<4);
			else ret[i/2]+=msg[i];
		}
		return ret;
	}



}
