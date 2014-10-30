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

package ca.uwaterloo.crysp.otr;

import ca.uwaterloo.crysp.otr.crypt.DSAKeyPairGenerator;
import ca.uwaterloo.crysp.otr.crypt.Provider;
import ca.uwaterloo.crysp.otr.crypt.KeyPair;
import ca.uwaterloo.crysp.otr.crypt.SHA1;

/**
 * A PrivKey stores the private and public long-term authentication keys for an
 * individual account. Note that encryption keys are not stored anywhere, in
 * order to achieve forward secrecy.
 * 
 * @author Ian Goldberg <iang@cs.uwaterloo.ca>
 */
public class PrivKey {
	/** The account corresponding to this key. */
	//private Account account;

	/** What type of key is this? */
	private int pubkey_type;

	/** A DSA key */
	public static final int TYPE_DSA = 0;

	/** The private key */
	//private PrivateKey privkey;

	/** The serialized public key */
	public byte[] pubkey_data;

	/** The keypair */
	private KeyPair kp;

	/** Create a new PrivKey for the given Account. */
	public PrivKey(Account acc, Provider crypt) throws OTRException {
		//account = acc;
		pubkey_type = TYPE_DSA;
		DSAKeyPairGenerator gen = crypt.getDSAKeyPairGenerator();

		kp = gen.generateKeyPair();
		//privkey = kp.getPrivateKey();
		pubkey_data = kp.getPublicKey().serialize();
	}

	public PrivKey(KeyPair kp) {
		this.kp = kp;
		//privkey = kp.getPrivateKey();
		pubkey_data = kp.getPublicKey().serialize();
	}

	/*public void dump() {
		for (int i = 0; i < pubkey_data.length; ++i) {
			System.out.print(" " + pubkey_data[i]);
		}
		System.out.println("");
	}*/

	public int pubkeySize() {
		return pubkey_data.length;
	}

	public int pubkeyType() {
		return pubkey_type;
	}

	public KeyPair getKeyPair() {
		return kp;
	}
	
	/* Calculate a raw hash of our DSA public key. */
	public static byte[] fingerprintRaw(UserState us,String accountname, String protocol, Provider prov) throws OTRException
	{
	    PrivKey p = us.getPrivKey(new Account(accountname, protocol), false);

	    if (p!=null) {
		/* Calculate the hash */
		SHA1 sha = prov.getSHA1();
		byte[] hash = sha.hash(p.pubkey_data);
		return hash;
	    } else {
	    	return null;
	    }
	}

}
