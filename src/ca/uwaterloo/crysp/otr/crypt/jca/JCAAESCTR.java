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
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import ca.uwaterloo.crysp.otr.crypt.Key;
import ca.uwaterloo.crysp.otr.crypt.OTRCryptException;
import ca.uwaterloo.crysp.otr.crypt.SecretKey;

/**
 * JCA-specific implementations of AES in Counter Mode. In particular, JCA is used to encrypt
 * the control block that is XORd with the blocks of plaintext/ciphertext.
 * 
 * Also manages the symmetric key using JCA's SecretKey class.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public class JCAAESCTR extends ca.uwaterloo.crysp.otr.crypt.AESCTR {
	private javax.crypto.Cipher cipher;
	
	public JCAAESCTR(SecretKey key, byte[] inputHigh) throws OTRCryptException {
		super(key, inputHigh);
		
		try {
			cipher = Cipher.getInstance("AES");
			// Initialize cipher with key
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), "AES"));
		} catch (NoSuchAlgorithmException e) {
			throw new OTRCryptException(e);
		} catch (NoSuchPaddingException e) {
			throw new OTRCryptException(e);
		} catch (InvalidKeyException e) {
			throw new OTRCryptException(e);
		}
	}
	
	public void setKey(Key key) throws OTRCryptException {
		if (key instanceof SecretKey) {
			secretKey = (SecretKey)key;
			// Update cipher with the secret key
			try {
				cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey.getEncoded(), "AES"));
			} catch (InvalidKeyException e) {
				throw new OTRCryptException(e);
			}
		}
		else {
			throw new OTRCryptException("Wrong key type!");
		}
	}

	/**
	 * Runs the control block through AES with the secret key.
	 * @throws OTRCryptException 
	 * 
	 * @param controlBlock The control block to send through AES.
	 * 
	 * @returns AES_k(controlBlock)
	 */
	protected byte[] aesControlBlock(byte[] controlBlock) throws OTRCryptException {
		try {
			// Return AES_secretkey(controlBlock);
			return cipher.doFinal(controlBlock);
		} catch (IllegalBlockSizeException e) {
			throw new OTRCryptException(e);
		} catch (BadPaddingException e) {
			throw new OTRCryptException(e);
		}
	}
}
