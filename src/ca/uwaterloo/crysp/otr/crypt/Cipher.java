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

package ca.uwaterloo.crysp.otr.crypt;

/**
 * Interface for encrypting/decrypting messages.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public interface Cipher {
	/**
	 * Returns the algorithm used.
	 * @return the algorithm used.
	 */
	public String getAlgorithm();
	
	/**
	 * Sets the symmetric key used by the cipher.
	 * @param key The symmetric key.
	 * @throws OTRCryptException
	 */
	public void setKey(Key key) throws OTRCryptException;
	
	/**
	 * Returns the symmetric key used by the cipher.
	 * @return the symmetric key used by the cipher.
	 */
	public Key getKey();
	
	/**
	 * Encrypts/Decrypts the data.
	 * 
	 * @param data The data to process.
	 * @return the encrypted/decrypted data.
	 * @throws OTRCryptException
	 */
	public byte[] doFinal(byte[] data) throws OTRCryptException;
	
	/**
	 * Encrypts/Decrypts the data at the given offset for length bytes.
	 * @param data The data to process.
	 * @param offset The index for which encryption/decryption begins.
	 * @param length The number of bytes to be encrypted/decrypted.
	 * @return the encrypted/decrypted data.
	 * @throws OTRCryptException
	 */
	public byte[] doFinal(byte[] data, int offset, int length) throws OTRCryptException;
}
