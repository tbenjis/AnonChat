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
 * Interface for signing and verifying data. To use this class, a secret key 
 * must first be specified using setKey(). Following this, the tag() 
 * and verify() methods can then be used to tag/verify data.
 * 
 * @author Can Tang (c24tang@gmail.com)
 */
public interface MAC {
	/**
	 * Returns the name of the algorithm used for signatures.
	 * 
	 * @return the name of the algorithm used for signatures.
	 */
	public String getAlgorithm();

	/**
	 * Returns the string representation of the MAC's current state.
	 * 
	 * @return the string representation of the MAC's current state.
	 */
	public String toString();

	/**
	 * Returns the key used by the MAC algorithm.
	 * 
	 * @return the key used by the MAC algorithm.
	 */
	public Key getKey();

	/**
	 * Set the key used by the MAC algorithm.
	 * 
	 * @param key the key used by the MAC algorithm.
	 * @throws OTRCryptException
	 */
	public void setKey(Key key) throws OTRCryptException;

	/**
	 * Processes the given bytes. 
	 * 
	 * @param data the data to be processed.
	 * @return void.
	 * @throws OTRCryptException
	 */
	public void update(byte[] data)
			throws OTRCryptException;
	/**
	 * Processes the first length bytes in input, starting at offset inclusive. 
	 * 
	 * @param data the data to be processed.
	 * @param offset the offset in input where the input starts.
	 * @param length the number of bytes to process. 
	 * @return void.
	 * @throws OTRCryptException
	 */
	public void update(byte[] data, int offset, int length)
			throws OTRCryptException;
	
	/**
	 * Tags the data provided.
	 * 
	 * @param data the data to be tagged.
	 * @return the signature.
	 * @throws OTRCryptException
	 */
	public byte[] tag(byte[] data) throws OTRCryptException;



	/**
	 * Verifies the tag for the data provided.
	 * 
	 * @param tag the tag bytes to be verified.
	 * @param data the data to be verified against.
	 * @return true if the tag is verified, false otherwise.
	 * @throws OTRCryptException
	 */
	public byte[] tag(byte[] data, int offset, int length)
	throws OTRCryptException;

/**
* Verifies the tag for the data provided.
* 
* @param tag the tag bytes to be verified.
* @param data the data to be verified against.
* @return true if the tag is verified, false otherwise.
* @throws OTRCryptException
*/
	
	public boolean verify(byte[] tag, byte[] data)
			throws OTRCryptException;

	/**
	 * Verifies the tag for the data provided, starting at the
	 * provided offset.
	 * 
	 * @param tag the tag bytes to be verified.
	 * @param data the data to be verified against.
	 * @param offset the offset to start from in the array of bytes.
	 * @param length the number of bytes to use following the offset.
	 * @return true if the tag is verified, false otherwise.
	 * @throws OTRCryptException
	 */
	public boolean verify(byte[] tag, byte[] data, int offset,
			int length) throws OTRCryptException;
}
