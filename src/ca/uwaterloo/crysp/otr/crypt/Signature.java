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
 * Interface for signing and verifying data. To use this class, a key pair  
 * must first be specified using setKeyPair(). Following this, the sign() 
 * and verify() methods can then be used to sign/verify data.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public interface Signature {
        /**
         * Returns the name of the algorithm used for signatures.
         * 
         * @return the name of the algorithm used for signatures.
         */
        public String getAlgorithm();

        /**
         * Signs the data provided.
         * 
         * @param data the data to be signed.
         * @return the signature.
         * @throws OTRCryptException
         */
        public byte[] sign(PrivateKey priv, byte[] data) throws OTRCryptException;

        /**
         * Verifies the signature for the data provided.
         * 
         * @param signature the signature bytes to be verified.
         * @param data the data to be verified against.
         * @return true if the signature is verified, false otherwise.
         * @throws OTRCryptException
         */
        public boolean verify(PublicKey pub, byte[] signature, byte[] data)
                        throws OTRCryptException;
}
