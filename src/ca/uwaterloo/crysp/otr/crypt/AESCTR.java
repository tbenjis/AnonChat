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

import ca.uwaterloo.crysp.otr.crypt.MPI;

/**
 * Abstract class for AES in counter mode. This is a symmetric algorithm
 * with the following parameters:
 * 
 * <ul>
 * 	<li>key - Key used to encrypt the control block (described later)</li>
 * 	<li>high - Significant 8 bytes used as part of the control block.</li>
 * 	<li>counter - Lower 8 bytes used as part of the control block.</li>
 * </ul>
 * 
 * To encrypt a given plaintext, the following steps are performed:
 * 
 * <ol>
 * 	<li>CTRBLK is made up of 8 high bytes (specified by constructor), and 
 * 	8 lower bytes (the counter)</li>
 * 	<li>The plaintext is partitioned into 128-bit blocks.</li>
 * 	<li>Each block of plaintext is XORed with AES(CTRBLK) under the given key</li>
 *	<li>CTRBLK's counter is incremented by 1 for each successive block of plaintext.</li> 	
 * </ol>
 * 
 * Decryption behaves in the same manner as encryption.
 * 
 * The RFC can be located at: <a href="http://www.rfc-editor.org/rfc/rfc3686.txt">http://www.rfc-editor.org/rfc/rfc3686.txt</a>
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public abstract class AESCTR extends AbstractCipher {
	/**
	 * The secret key.
	 */
	protected SecretKey secretKey;
	
	// 8 bytes high bits
	private byte[] high;
	
	/**
	 * Encrypts the given control block byte array.
	 * 
	 * @param controlBlock
	 * @return The enncrypted AES Control Block as a byte array.
	 * @throws OTRCryptException 
	 */
	protected abstract byte[] aesControlBlock(byte[] controlBlock) throws OTRCryptException;
	
	/**
	 * Constructs an instance of the AES cipher with the given key and high bits.
	 * 
	 * @param key The secret key.
	 * @param inputHigh The significant 16 bits used in the control block.
	 */
	public AESCTR(SecretKey key, byte[] inputHigh) {
		secretKey = key;
		
		high = new byte[8];
		// Copy the first 8 bytes of newHigh into the high bits
		System.arraycopy(inputHigh, 0, high, 0, 8);
	}
	
	public final String getAlgorithm() {
		return "AES CTR";
	}
	
	/**
	 * Returns the high bits used in the control block.
	 * @return the high bits used in the control block.
	 */
	public byte[] getHigh() {
		return high;
	}
	
	/**
	 * Sets the high bits used in the control block. Only the first 8 bytes are copied.
	 * @param newHigh The new high bits to use.
	 */
	public void setHigh(byte[] newHigh) {
		// Copy the first 8 bytes of newHigh into the high bits
		System.arraycopy(newHigh, 0, high, 0, 8);
	}
	
	public Key getKey() {
		return secretKey;
	}

	public byte[] doFinal(byte[] data, int offset, int length) throws OTRCryptException {
		byte[] ciphertext = new byte[data.length];
		
		byte[] controlBlock = new byte[16];
		byte[] encryptedControlBlock;
		long counter = 0;
		int blockLength;
		
		// Upper 8 bytes of control are the high bits
		System.arraycopy(high, 0, controlBlock, 0, 8);
		
		// Partition string into 128 bit (16 byte) blocks
		int numBlocks = (int)Math.ceil((double)data.length / 16);
		for (int i = 0; i < numBlocks; i++) {
			if (i == numBlocks - 1) {
				// For the last block, copy up to the last 16 bytes
				blockLength = data.length % 16 == 0 ? 16 : data.length % 16;
			}
			else {
				blockLength = 16;
			}
			
			// Copy counter to lower 8 bytes of control block
			System.arraycopy(MPI.toBytes(counter), 0, controlBlock, 8, 8);
			
			// Run controlBlock through AES
			encryptedControlBlock = aesControlBlock(controlBlock);
			
			// XOR plaintext with the front bytes of the output of AES
			for (int j = 0; j < blockLength; j++) {
				ciphertext[16*i + j] = (byte)(data[16*i + j] ^ encryptedControlBlock[j]); 
			}
			
			counter++;
		}
		
		return ciphertext;
	}
}
