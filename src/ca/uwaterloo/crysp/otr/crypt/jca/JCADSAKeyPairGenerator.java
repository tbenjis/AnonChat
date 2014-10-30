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


import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import ca.uwaterloo.crysp.otr.crypt.KeyPair;
import ca.uwaterloo.crysp.otr.crypt.OTRCryptException;

/**
 * Generates DSA KeyPairs via the JCA classes.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public class JCADSAKeyPairGenerator extends ca.uwaterloo.crysp.otr.crypt.DSAKeyPairGenerator {

	public KeyPair generateKeyPair() throws OTRCryptException {
	    java.security.KeyPairGenerator keyGen;
		
	    try {
		    keyGen = java.security.KeyPairGenerator.getInstance("DSA");
			java.security.SecureRandom random =
				java.security.SecureRandom.getInstance("SHA1PRNG", "SUN");
			    
		    keyGen.initialize(1024, random);
		    java.security.KeyPair pair = keyGen.generateKeyPair();
		    
		    java.security.PrivateKey priv =  pair.getPrivate();
		    java.security.PublicKey pub = pair.getPublic();
		    
		    // Ensure the right key types are being returned before casting
		    if (!(priv instanceof java.security.interfaces.DSAPrivateKey) ||
		    		!(pub instanceof java.security.interfaces.DSAPublicKey)) {
		    	throw new OTRCryptException("Wrong key types returned by DSAKeyPairGenerator");
		    }

		    // Wrap the JCA DSA Keys into the generic DSA keys		    
		    return new KeyPair(
	    		new JCADSAPrivateKey((java.security.interfaces.DSAPrivateKey) priv), 
	    		new JCADSAPublicKey((java.security.interfaces.DSAPublicKey) pub)
    		);
	    } catch (NoSuchAlgorithmException e) {
	    	throw new OTRCryptException(e.getMessage());
	    } catch (NoSuchProviderException e) {
	    	throw new OTRCryptException(e.getMessage());
		}
	}
	
	/*
	public static void main(String[] args) {
	    while(true) {
		JCADSAKeyPairGenerator kg = new JCADSAKeyPairGenerator();
		if (!kg.getAlgorithm().equals("DSA")) {
			System.out.println("FAILURE: Not correct algorithm type.");
		}
		
		// Check that keys were generated properly
		try {
			KeyPair kp = kg.generateKeyPair();
			System.out.println("Keys generated:");
			JCADSAPublicKey pubkey = (JCADSAPublicKey)kp.getPublicKey();
			JCADSAPrivateKey privkey = (JCADSAPrivateKey)kp.getPrivateKey();
			
			System.out.println("Public: " + new java.math.BigInteger(pubkey.getY()).toString());
			System.out.println("Private: " + new java.math.BigInteger(privkey.getX()).toString());
		} catch (OTRCryptException e) {
			System.out.println("FAILURE: Key generation failure.");
			System.out.println(e.getMessage());
		}
		System.out.println("Tests complete. If there were no errors, test was successful.");
	    }
	}
	*/
}
