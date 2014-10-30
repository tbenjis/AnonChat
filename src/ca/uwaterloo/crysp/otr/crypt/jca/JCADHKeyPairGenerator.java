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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import ca.uwaterloo.crysp.otr.OTRException;
import ca.uwaterloo.crysp.otr.crypt.KeyPair;
import ca.uwaterloo.crysp.otr.crypt.OTRCryptException;

/**
 * Generates a public/private keypair for the Diffie-Hellman key exchange.
 * The private key (x) is a randomly generated sequence of bits, and the public
 * key is computed using g<sup>x</sup> mod p. The parameters x, g, and p are the constants 
 * DH_P, DH_G, DH_L defined in this class.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public class JCADHKeyPairGenerator extends ca.uwaterloo.crysp.otr.crypt.DHKeyPairGenerator {
	
	/**
	 * 1536-bit MODP group
	 */
	public static final BigInteger DH_P = new BigInteger("00" +
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16);

	/**
	 * Generator for the DH_P group.
	 */
	public static final BigInteger DH_G = BigInteger.valueOf(2);
	
	/**
	 * Length of the random exponent (in bits)
	 */
	public static final BigInteger DH_L = BigInteger.valueOf(320);

	public KeyPair generateKeyPair() throws OTRException {

		SecureRandom random;
		// Private key is x
		BigInteger x;
		// Public key is g^x mod p
		BigInteger gx;
		
		try {
			// Instantiate the JCA random number generator
			random = SecureRandom.getInstance("SHA1PRNG");
			// Compute the public and private keys
			x = new BigInteger((int)DH_L.longValue(), random);
			gx = DH_G.modPow(x, DH_P);
		    // Wrap the JCA DH Keys into the generic DH keys
			JCADHPrivateKey priv = new JCADHPrivateKey(x);
			JCADHPublicKey pub = new JCADHPublicKey(JCAMPI.toMPI(gx));
			KeyPair kp = new KeyPair(priv, pub);
			return kp;
		}
		catch (NoSuchAlgorithmException e) {
			throw new OTRCryptException(e);
		} 
	}
	
	/*public static void main(String[] args) {
		
		DHKeyPairGenerator kg = new DHKeyPairGenerator();

		if (!kg.getAlgorithm().equals("DH")) {
			System.out.println("FAILURE: Not correct algorithm type.");
		}
		
		// Check that keys were generated properly
		try {
			KeyPair kp = kg.generateKeyPair();
			System.out.println("Keys generated:");
			DHPublicKey pubkey = (DHPublicKey)kp.getPublicKey();
			DHPrivateKey privkey = (DHPrivateKey)kp.getPrivateKey();
			
			byte[] y = pubkey.getY();
			byte[] x = privkey.getX();
			
			System.out.println("Private: " + MPI.fromBytes(x).toString());
			System.out.println("Public: " + MPI.fromBytes(y).toString());
		} catch (OTRCryptException e) {
			System.out.println("FAILURE: Key generation failure.");
			System.out.println(e.getMessage());
		} catch (OTRException e) {
			System.out.println("FAILURE: Key generation failure.");
			System.out.println(e.getMessage());
		}
		System.out.println("Tests complete. If there were no errors, test was successful.");
	}*/
}
