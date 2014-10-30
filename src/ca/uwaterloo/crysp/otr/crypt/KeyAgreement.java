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
 * <p>The interface that allows 2 parties to generate a shared secret
 * by exchanging their public keys with each other.</p>
 * 
 * <ol>
 * 	<li>Initially, each user calls init() with their own public keys.</li>
 * 	<li>Both users exchange public keys with each other.</li>
 * 	<li>Each user calls generateSecret() using the public key they received.</li>
 * 	<li>The result of generateSecret() is the shared secret that both parties know.</li>
 * </ol>
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public interface KeyAgreement {
	
	/**
	 * Returns the name of the algorithm used.
	 * @return the name of the algorithm used.
	 */
	public String getAlgorithm();
	
	/**
	 * Computes the shared secret. The result is in MPI form.
	 * @param otherKey The other party's public key.
	 * @return The shared secret (in MPI form).
	 */
	public byte[] generateSecret(PublicKey otherKey);
	
	/**
	 * Returns the shared secret computed using the last public key
	 * used by generateSecret(). The result is returned in MPI form.
	 * If generateSecret() has not been called before invoking this
	 * method, null is returned.
	 * 
	 * @return the shared secret. Returns null if a shared secret has not been computed.
	 */
	public byte[] getSharedSecret();
	
	/**
	 * Initializes the key agreement using the private key.
	 * 
	 * @param initKey The user's private key.
	 */
	public void init(PrivateKey initKey);
}
