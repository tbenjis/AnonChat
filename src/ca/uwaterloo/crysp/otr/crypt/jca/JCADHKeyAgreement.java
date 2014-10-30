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

import java.math.BigInteger;

import ca.uwaterloo.crysp.otr.crypt.PrivateKey;
import ca.uwaterloo.crysp.otr.crypt.PublicKey;

/**
 * This class computes the shared secret of two parties using BigInteger.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public class JCADHKeyAgreement extends ca.uwaterloo.crysp.otr.crypt.DHKeyAgreement {
	private JCADHPrivateKey priv;
	private byte[] lastSharedSecret;
	
	public byte[] generateSecret(PublicKey otherKey) {
		byte[] result;
		// Get x, g^y, and p from the keys
		BigInteger privateValue = JCAMPI.fromBytes(priv.getX());
		BigInteger publicValue = JCAMPI.fromBytes(((JCADHPublicKey)otherKey).getY());
		BigInteger p = JCAMPI.fromBytes(priv.getP());
		
		// Shared secret is (g^y)^x mod p
		BigInteger sharedSecret = publicValue.modPow(privateValue, p);
		
		result = trim(sharedSecret.toByteArray());
		
		// Store the shared secret in case it is needed later
		lastSharedSecret = new byte[result.length];
		System.arraycopy(result, 0, lastSharedSecret, 0, result.length);
		
		return result;
	}

	public void init(PrivateKey initKey) {
		priv = (JCADHPrivateKey)initKey;
	}

	public byte[] getSharedSecret() {
		return lastSharedSecret;
	}
	
	byte[] trim(byte[] in){
		int i=0;
		while(in[i]==0){
			i++;
		}
		if(i==in.length) return null;
		byte[] res = new byte[in.length-i];
		System.arraycopy(in, i, res, 0, res.length);
		return res;
	}
	
}
