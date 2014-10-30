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
 * A KeyPair is a public/private key pair for a digital signature system.
 *
 * @author Ian Goldberg <iang@cs.uwaterloo.ca>
 */
public class KeyPair{
    private PrivateKey privateKey;
    private PublicKey publicKey;

    /**
     * Create a key pair with the given keys.
     * @param priv the private key.
     * @param pub the public key.
     */
    public KeyPair(PrivateKey priv, PublicKey pub) {
    	privateKey = priv;
    	publicKey = pub;
    }
    
    /**
     * Returns the private key.
     * 
     * @return the private key.
     */
    public PrivateKey getPrivateKey() {
    	return privateKey;
    }
    
    /**
     * Returns the public key.
     * 
     * @return the public key.
     */
    public PublicKey getPublicKey() {
    	return publicKey;
    }
}
