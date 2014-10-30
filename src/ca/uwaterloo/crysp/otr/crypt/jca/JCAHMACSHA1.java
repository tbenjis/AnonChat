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

import java.security.InvalidKeyException;

import ca.uwaterloo.crysp.otr.crypt.Key;
import ca.uwaterloo.crysp.otr.crypt.OTRCryptException;

import javax.crypto.*;

/**
 * The HMAC algorithm, as implemented by the Java Cryptography
 * Extension.
 * 
 * @author Can Tang <c24tang@gmail.com>
 */
public class JCAHMACSHA1 extends ca.uwaterloo.crysp.otr.crypt.HMAC {
	Mac hmac;

	public JCAHMACSHA1() {
		super();
	}

	public void setKey(Key key) throws OTRCryptException {
		super.setKey(key);

		// Reset the JCA signature instance
		try {
			hmac = javax.crypto.Mac
					.getInstance("HmacSHA1");
			hmac.init(((JCAHMACKey)key).getHMACKey());
		} catch (Exception e) {
			throw new OTRCryptException(e);
		}
	}

	public byte[] tag(byte[] data, int offset, int length)
			throws OTRCryptException {
		try {
			hmac.init(((JCAHMACKey)key).getHMACKey());
		} catch (InvalidKeyException e) {
			throw new OTRCryptException(e);
		}
		hmac.update(data, offset, length);
		return hmac.doFinal();
	}

	public void update(byte[] input){
		hmac.update(input);
	}

	
	public void update(byte[] input, int inputOffset, int inputLen){
		hmac.update(input, inputOffset, inputLen);
	}

	public byte[] doFinal(){
		return hmac.doFinal();
	}

	public boolean verify(byte[] tag, byte[] data, int offset,
			int length) throws OTRCryptException {

			try {
				hmac.init(((JCAHMACKey)key).getHMACKey());
			} catch (InvalidKeyException e) {
				throw new OTRCryptException(e);
			}
			hmac.update(data, offset, length);

			byte[] realtag = hmac.doFinal();
			
			return java.security.MessageDigest.isEqual(tag, realtag);
		}

}
