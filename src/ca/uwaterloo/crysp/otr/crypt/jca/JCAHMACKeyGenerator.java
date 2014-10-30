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


import ca.uwaterloo.crysp.otr.crypt.Key;
import ca.uwaterloo.crysp.otr.crypt.OTRCryptException;

/**
 * Generates MAC Key.
 * 
 * @author Can Tang (c24tang@gmail.com)
 */
public class JCAHMACKeyGenerator extends ca.uwaterloo.crysp.otr.crypt.HMACKeyGenerator {


	public Key generateKey() throws OTRCryptException {
	    javax.crypto.KeyGenerator keyGen;
		
		    try {
				keyGen = javax.crypto.KeyGenerator.getInstance("HmacSHA1");
				java.security.SecureRandom random =
					java.security.SecureRandom.getInstance("SHA1PRNG", "SUN");
				    
			    keyGen.init(1024, random);
			    java.security.Key key = keyGen.generateKey();
			    return new JCAHMACKey(
		    		key
	    		);		    
		    }catch (NoSuchAlgorithmException e){
		    	throw new OTRCryptException(e.getMessage());
		    }catch (NoSuchProviderException e){
		    	throw new OTRCryptException(e.getMessage());
		    }
	}
}
