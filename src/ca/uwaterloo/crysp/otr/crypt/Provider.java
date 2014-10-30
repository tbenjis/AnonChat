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

import ca.uwaterloo.crysp.otr.OTRException;

/**
 * A class representing a crypto provider (for example, JCA or RIM).
 *
 * @author Ian Goldberg <iang@cs.uwaterloo.ca>
 */
public abstract class Provider {
        
    /**
     * Compare the value of two MPIs
     * @return an integer greater than 0, if ours is greater than theirs;
     * an integer less than 0, if ours is less than theirs;
     * 0, if the two are equal
     */
    public abstract int compareMPI(MPI ours, MPI theirs);
    
    public abstract MPI powm(MPI base, MPI exp, MPI mod) throws OTRException;
    
    public abstract MPI mulm(MPI a, MPI b, MPI mod) throws OTRException;
    
    public abstract MPI subm(MPI a, MPI b, MPI mod) throws OTRException;
    
    public abstract MPI invm(MPI a, MPI mod) throws OTRException;
    /**
     * Returns an instance of the Raw DSA Signature scheme.
     * 
     * @return an instance of the Raw DSA Signature scheme.
     */
    public abstract RawDSA getRawDSA();
    
    /**
     * Returns an instance of the DSAPublicKey.
     * 
     * @return an instance of the DSAPublicKey.
     */
    public abstract DSAPublicKey getDSAPublicKey
    (MPI p, MPI q, MPI g, MPI y) throws Exception;
    
    /**
     * Returns a DSAKeyPairGenerator instance.
     * 
     * @return an instance of DSAKeyPairGenerator.
     */
    public abstract DSAKeyPairGenerator getDSAKeyPairGenerator();
    
    /**
     * Returns a DHKeyPairGenerator instance.
     * 
     * @return an instance of DHKeyPairGenerator.
     */
    public abstract DHKeyPairGenerator getDHKeyPairGenerator();
    
    /**
     * Returns an instance of the DHPublicKey.
     * 
     * @return an instance of the DHPublicKey.
     */
    public abstract DHPublicKey getDHPublicKey(MPI val);
    
    /**
     * Returns an instance of the DHKeyAgreement.
     * 
     * @return an instance of the DHKeyAgreement.
     */
    public abstract DHKeyAgreement getDHKeyAgreement();
    
    /**
     * Returns a SHA1 instance.
     * 
     * @return an instance of SHA1.
     */   
    public abstract SHA1 getSHA1();
    
    /**
     * Returns a SHA256 instance.
     * 
     * @return an instance of SHA1.
     */   
    public abstract SHA256 getSHA256();

    /**
     * Returns an HMACKey instance.
     * 
     * @return an instance of HMACKey.
     */    
    public abstract HMACKey getHMACKey(byte[] encoded);
    
    /**
     * Returns an HMACKey instance.
     * 
     * @return an instance of HMACKey.
     */    
    public abstract HMACKeyGenerator getHMACKeyGenerator();
    
    /**
     * Returns an HMAC instance.
     * 
     * @return an instance of HMAC.
     */   
    public abstract HMAC getHMACSHA1();

    /**
     * Returns an HMAC instance.
     * 
     * @return an instance of HMAC.
     */   
    public abstract HMAC getHMACSHA256();
    
    /**
     * Returns an AESKey instance.
     * 
     * @return an instance of AESKey.
     */   
    public abstract AESKey getAESKey(byte[] r);
    
    /**
     * Returns an instance of AES in Counter Mode.
     * @param key The key used by AES.
     * @param ctrHigh The upper 8 bytes of the counter.
     * @return an instance of AES in Counter Mode.
     * @throws OTRCryptException
     */
    public abstract AESCTR getAESCounterMode(SecretKey key, byte[] ctrHigh) throws OTRCryptException;
    
    
    /**
     * Returns a SecureRandom instance.
     * 
     * @return an instance of SecureRandom.
     */
    public abstract SecureRandom getSecureRandom();
}
