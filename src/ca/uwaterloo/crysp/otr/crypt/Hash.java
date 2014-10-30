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
 * Interface for generating and verifying the hash digest of a message.
 * 
 * @author Can Tang (c24tang@gmail.com)
 */
public interface Hash {
	/**
	 * Returns the name of the algorithm used for hash function.
	 * 
	 * @return the name of the algorithm used for hash function.
	 */
	public String getAlgorithm();

	/**
	 * Returns the string representation of the Hash's current state.
	 * 
	 * @return the string representation of the Hash's current state.
	 */
	public String toString();

	/**
	 * Updates the digest using the specified array of bytes. 
	 * 
	 * @param data the data to be processed.
	 * @return void.
	 * @throws OTRCryptException
	 */
	public void update(byte[] data) throws OTRCryptException;
	
	/**
	 * Updates the digest using the specified array of bytes, starting at the specified offset. 
	 * 
	 * @param data the data to be processed.
	 * @param offset the offset to start from in the array of bytes.
	 * @param length the number of bytes to use, starting at offset.
	 * @return void.
	 * @throws OTRCryptException
	 */
	public void update(byte[] data, int offset, int length) throws OTRCryptException;
	
	
	/**
	 * Completes the hash computation by performing final 
	 * operations such as padding. The digest is reset after this call is made. 
	 * 
	 * @param void.
	 * @return the digest.
	 * @throws OTRCryptException
	 */
	public byte[] hash() throws OTRCryptException;
	
	/**
	 * Hashes the data provided.
	 * 
	 * @param data the data to be hashed.
	 * @return the digest.
	 * @throws OTRCryptException
	 */
	public byte[] hash(byte[] data) throws OTRCryptException;

	/**
	 * Hashes the data provided using the given offset and length.
	 * 
	 * @param data the data to be hashed.
	 * @param offset the offset to start from the array of bytes.
	 * @param length the number of bytes to use following the offset.
	 * @return the digest.
	 * @throws OTRCryptException
	 */
	public byte[] hash(byte[] data, int offset, int length)
			throws OTRCryptException;

	/**
	 * Verifies the digest for the data provided.
	 * 
	 * @param digest the digest bytes to be verified.
	 * @param data the data to be verified against.
	 * @return true if the digest is verified, false otherwise.
	 * @throws OTRCryptException
	 */
	public boolean verify(byte[] digest, byte[] data)
			throws OTRCryptException;

	/**
	 * Verifies the digest for the data provided, starting at the
	 * provided offset.
	 * 
	 * @param digest the digest bytes to be verified.
	 * @param data the data to be verified against.
	 * @param offset the offset to start from in the array of bytes.
	 * @param length the number of bytes to use following the offset.
	 * @return true if the digest is verified, false otherwise.
	 * @throws OTRCryptException
	 */
	public boolean verify(byte[] digest, byte[] data, int offset,
			int length) throws OTRCryptException;
}
