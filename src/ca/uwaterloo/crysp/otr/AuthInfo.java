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

/**
 * This class contains information and state about authentication
 * with a remote buddy.
 *
 * @author Can Tang <c24tang@gmail.com>
 */

import ca.uwaterloo.crysp.otr.crypt.*;
import ca.uwaterloo.crysp.otr.message.*;

public class AuthInfo {
	AuthState authstate = new AuthState(); // Our state

	KeyPair our_dh; // Our D-H key
	int our_keyid; // ...and its keyid
	byte[] encgx; // The encrypted value of g^x
	byte[] r = new byte[16]; // The encryption key
	byte[] hashgx = new byte[32]; // SHA256(g^x)

	DHPublicKey their_pub; // Their D-H public key
	int their_keyid; // ...and its keyid

	AESKey enc_c, enc_cp; // c and c' encryption keys
	HMACKey mac_m1, mac_m1p; // m1 and m1' MAC keys
	HMACKey mac_m2, mac_m2p; // m2 and m2' MAC keys

	byte[] their_fingerprint = new byte[20]; // The fingerprint of their
	// long-term signing key
	int initiated; // Did we initiate this authentication?
	
	byte[] secure_session_id = new byte[20];  // The secure session id
	int sessionid_len;				//The length of it
	
	String lastauthmsg; // The last auth message (base-64 encoded) we sent,
	// in case we need to retransmit it.
	int havemsgp; // if havemsgp is 1, the message to send
	// will be left in lastauthmsg

	Provider prov;

	public static final byte[] DH_MODULUS = Util.hexStringToBytes(
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF");
	
	public static final byte[] DH_MODULUS_MINUS_2 = Util.hexStringToBytes(
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFD");
	
	
	public AuthInfo(Provider prov) {
		this.prov = prov;
	}

	/**
	 * Start a fresh AKE. Generate a fresh DH keypair to use. The message to
	 * transmit will be contained in lastauthmsg.
	 * 
	 * @throws OTRException
	 */
	public void startAKE(KeyPair dhkp) throws OTRException {
		initiated = 1;

		if (dhkp == null) {
			DHKeyPairGenerator dhkpg = prov.getDHKeyPairGenerator();
			our_dh = dhkpg.generateKeyPair();
		} else {
			our_dh = dhkp;
		}
		our_keyid = 1;
		
		// Pick an encryption key
		SecureRandom rand = prov.getSecureRandom();
		rand.nextBytes(r);

		// get our g^x
		DHPublicKey dhp = (DHPublicKey) our_dh.getPublicKey();
		encgx = dhp.getY();

		// Hash g^x
		hashgx = prov.getSHA256().hash(encgx);

		// Encrypt g^x using the key r
		SecretKey secKey = prov.getAESKey(r);
		byte[] ctr = new byte[16];
		AESCTR aes;
		aes = prov.getAESCounterMode(secKey, ctr);
		encgx = aes.doFinal(encgx);

		DHCommitMessage dhcm = new DHCommitMessage((short) 0x2,
				new Data(encgx), new Data(hashgx));
		lastauthmsg = new String(Base64Coder.encode(dhcm.getContent()));
		havemsgp = 1;
		authstate.processEvent(AuthState.EVT_DH_COMMIT_SENT);
	}

	/**
	 * Create a D-H Key Message using the our_dh value, and store it in
	 * lastauthmsg.
	 */
	void createKeyMessage() throws OTRException {

		DHPublicKey dhp = (DHPublicKey) our_dh.getPublicKey();
		byte[] pub = dhp.getY();

		DHKeyMessage dhkm = new DHKeyMessage((short) 2, MPI.readMPI(new InBuf(
				pub)));

		lastauthmsg = new String(Base64Coder.encode(dhkm.getContent()));
		havemsgp = 1;
	}

	/**
	 * Handle an incoming D-H Commit Message. If no error is returned, the
	 * message to send will be left in lastauthmsg. Generate a fresh keypair to
	 * use.
	 */
	void handleCommit(byte[] commitmsg, KeyPair dhkpa) throws OTRException {

		byte[] res = commitmsg;

		DHCommitMessage dhcm = DHCommitMessage.readDHCommitMessage(new InBuf(
				res, 3, res.length - 3), (short) 2);
		// Header
		if (res.length < 3 || res[0] != 0x00 || res[1] != 0x02
				|| res[2] != 0x02) {
			throw new OTRException("Invalid version or message type");
		}

		// Encrypted g^x
		byte[] encbuf = dhcm.getEncryptedGx().getValue();
		// Hashed g^x

		byte[] hashbuf = dhcm.getHashedGx().getValue();
		if (hashbuf.length != 32) {
			throw new OTRException("Invalid hash length");
		}

		switch (authstate.curState) {
		case AuthState.ST_NONE:
		case AuthState.ST_AWAITING_SIG:

			// Store the incoming information
			if (dhkpa == null) {
				our_dh = prov.getDHKeyPairGenerator().generateKeyPair();
			} else {
				our_dh = dhkpa;
			}
			our_keyid = 1;
			encgx = encbuf;
			hashgx = hashbuf;

			// Create a DH Key Message
			createKeyMessage();
			authstate.processEvent(AuthState.EVT_DH_KEY_SENT);
			break;
		case AuthState.ST_AWAITING_DHKEY:
			// We sent a D-H Commit Message, and we also received one
			// back. Compare the hashgx values to see which one wins.
			if (new String(hashgx).compareTo(new String(hashbuf)) > 0) {
				// Ours wins. Ignore the message we received, and just
				// resend the same D-H Commit message again.
			} else {
				// Ours loses. Use the incoming parameters instead.
				our_dh = prov.getDHKeyPairGenerator().generateKeyPair();
				our_keyid = 1;
				encgx = encbuf;
				hashgx = hashbuf;

				// Create a DH Key Message
				createKeyMessage();
				authstate.processEvent(AuthState.EVT_DH_KEY_SENT);
			}
			break;
		case AuthState.ST_AWAITING_REVEALSIG:
			// Use the incoming parameters, but just retransmit the old
			// D-H Key Message.
			encgx = encbuf;
			hashgx = hashbuf;
			break;
		}

	}

	/**
	 * Calculate the encrypted part of the Reveal Signature and Signature
	 * Messages, given a MAC key, an encryption key and an authentication public
	 * key.
	 * 
	 * @throws OTRException
	 */

	byte[] calculatePubkeyAuth(PrivKey privkey, HMACKey mackey, AESKey enckey)
			throws OTRException {
		// Get the DH public keys
		byte[] ourpubbuf = ((DHPublicKey) our_dh.getPublicKey()).getY();
		byte[] theirpubbuf = ((DHPublicKey) their_pub).getY();
		// How big is the total structure to be MAC'd?
		int totallen = ourpubbuf.length + theirpubbuf.length + 2
				+ privkey.pubkeySize() + 4;
		byte[] buf = new byte[totallen];

		// Write the data to be MAC'd
		int lenp = 0;
		System.arraycopy(ourpubbuf, 0, buf, lenp, ourpubbuf.length);
		lenp += ourpubbuf.length;
		System.arraycopy(theirpubbuf, 0, buf, lenp, theirpubbuf.length);
		lenp += theirpubbuf.length;
		buf[lenp] = (byte) ((privkey.pubkeyType() >> 16) & 0xff);
		buf[lenp + 1] = (byte) (privkey.pubkeyType() & 0xff);
		lenp += 2;

		System.arraycopy(privkey.pubkey_data, 0, buf, lenp, privkey
				.pubkeySize());
		lenp += privkey.pubkeySize();
		writeInt(buf, lenp, our_keyid);
		lenp += 4;
		if (lenp != buf.length) {
			throw new OTRException("Invalid length");
		}
		// Do the MAC
		HMAC hmac = prov.getHMACSHA256();
		hmac.setKey(mackey);
		byte[] macbuf = hmac.tag(buf);
		// Sign the MAC
		RawDSA dsa = prov.getRawDSA();
		byte[] sigbuf = dsa.sign((DSAPrivateKey) privkey.getKeyPair()
				.getPrivateKey(), macbuf);
		// Calculate the total size of the structure to be encrypted
		totallen = 2 + privkey.pubkeySize() + 4 + sigbuf.length;
		buf = new byte[totallen];
		lenp = 0;
		
		// Write the data to be encrypted
		buf[lenp] = (byte) ((privkey.pubkeyType() >> 16) & 0xff);
		buf[lenp + 1] = (byte) (privkey.pubkeyType() & 0xff);
		lenp += 2;

		System.arraycopy(privkey.pubkey_data, 0, buf, lenp, privkey
				.pubkeySize());
		lenp += privkey.pubkeySize();
		writeInt(buf, lenp, our_keyid);
		lenp += 4;

		System.arraycopy(sigbuf, 0, buf, lenp, sigbuf.length);
		lenp += sigbuf.length;
		if (lenp != buf.length) {
			throw new OTRException("Invalid length");
		}
		// Now do the encryption
		byte[] high = new byte[8];
		AESCTR aes = prov.getAESCounterMode(enckey, high);
		buf = aes.doFinal(buf);

		return buf;

	}

	/**
	 * Decrypt the authenticator in the Reveal Signature and Signature Messages,
	 * given a MAC key, and encryption key. The fingerprint of the received
	 * public key will get put into their_fingerprint, and the received keyid
	 * will get put in their_keyid. The encrypted data pointed to by authbuf
	 * will be decrypted in place.
	 * 
	 * @throws Exception
	 */
	void checkPubkeyAuth(byte[] authbuf, HMACKey mackey, AESKey enckey)
			throws OTRException {

		// Start by decrypting it
		byte[] high = new byte[8];
		AESCTR aes = prov.getAESCounterMode(enckey, high);
		authbuf = aes.doFinal(authbuf);

		int lenp = 0;

		// Get the public key and calculate its fingerprint
		if (authbuf.length < 2) {
			throw new OTRException("Invalid length.");
		}

		int pubkey_type = (authbuf[0] << 8) + authbuf[1];
		lenp += 2;
		if (pubkey_type != PrivKey.TYPE_DSA) {
			throw new OTRException("Public key type is not DSA.");
		}

		int len_p = readInt(authbuf, lenp);
		byte[] mpibuf = new byte[len_p];
		System.arraycopy(authbuf, lenp+4, mpibuf, 0, len_p);
		MPI p = new MPI(mpibuf);
		lenp += (len_p + 4);

		int len_q = readInt(authbuf, lenp);
		mpibuf = new byte[len_q];
		System.arraycopy(authbuf, lenp+ 4, mpibuf, 0, len_q );
		MPI q = new MPI(mpibuf);
		lenp += (len_q + 4);

		int len_g = readInt(authbuf, lenp);
		mpibuf = new byte[len_g];
		System.arraycopy(authbuf, lenp + 4, mpibuf, 0, len_g);
		MPI g = new MPI(mpibuf);
		lenp += (len_g + 4);

		int len_y = readInt(authbuf, lenp);
		mpibuf = new byte[len_y];
		System.arraycopy(authbuf, lenp + 4, mpibuf, 0, len_y);
		MPI y = new MPI(mpibuf);
		lenp += (len_y + 4);

		their_fingerprint = prov.getSHA1().hash(authbuf, 2, lenp-2);
		int publen = lenp - 2;

		// Get the keyid
		int received_keyid = readInt(authbuf, lenp);
		if (received_keyid == 0) {
			throw new OTRException("Invalid value");
		}

		// Get the signature
		lenp += 4;
		byte[] sigbuf = new byte[authbuf.length - lenp];
		System.arraycopy(authbuf, lenp, sigbuf, 0, sigbuf.length);

		// How big are the DH public keys?
		byte[] their_pub_buf = their_pub.serialize();
		byte[] our_pub_buf = our_dh.getPublicKey().serialize();
		int ourpublen = our_pub_buf.length - 4;
		int theirpublen = their_pub_buf.length - 4;

		// Now calculate the message to be MAC'd.
		int totallen = 4 + ourpublen + 4 + theirpublen + 2 + publen + 4;
		byte[] buf = new byte[totallen];
		lenp = 0;

		System.arraycopy(their_pub_buf, 0, buf, lenp, their_pub_buf.length);
		lenp += their_pub_buf.length;
		System.arraycopy(our_pub_buf, 0, buf, lenp, our_pub_buf.length);
		lenp += our_pub_buf.length;
		buf[lenp] = (byte) ((pubkey_type >> 16) & 0xff);
		buf[lenp + 1] = (byte) (pubkey_type & 0xff);
		lenp += 2;
		System.arraycopy(authbuf, 2, buf, lenp, publen);

		lenp += publen;
		writeInt(buf, lenp, received_keyid);
		lenp += 4;
		if (lenp != buf.length) {
			throw new OTRException("Invalid length");
		}
		
		DSAPublicKey pk;
		try {
			pk = prov.getDSAPublicKey(p, q, g, y);
		} catch (Exception e) {
			throw new OTRException("Failed to get DSA public key");
		}

		// Do the MAC
		HMAC hmac = prov.getHMACSHA256();
		hmac.setKey(mackey);
		byte[] macbuf = hmac.tag(buf);

		// Verify the signature on the MAC
		RawDSA dsa = prov.getRawDSA();
		if (!dsa.verify(pk, sigbuf, macbuf)) {
			throw new OTRException("Signature verification failed.");
		}

		// Everything checked out
		their_keyid = received_keyid;
	}

	/**
	 * Create a Reveal Signature Message using the values in AuthInfo, and store
	 * it in lastauthmsg. Use the given privkey to sign the message.
	 * 
	 * @throws OTRException
	 */

	void createRevealsigMessage(PrivKey privkey) throws OTRException {

		// Get the encrypted authenticator
		byte[] authbuf = calculatePubkeyAuth(privkey, mac_m1, enc_c);
		byte[] buf = new byte[4 + authbuf.length];


		// Encrypted authenticator
		writeInt(buf, 0, authbuf.length);
		System.arraycopy(authbuf, 0, buf, 4, authbuf.length);
		// MAC it, but only take the first 20 bytes
		HMAC hmac = prov.getHMACSHA256();
		hmac.setKey(mac_m2);
		byte[] macbuf = hmac.tag(buf, 0, 4 + authbuf.length);
		byte[] trimmac = new byte[20];
		System.arraycopy(macbuf, 0, trimmac, 0, 20);
		
		RevealSignatureMessage rsm = new RevealSignatureMessage((short)2, new Data(r), 
				new Data(authbuf), new Data(trimmac));
		
		lastauthmsg = new String(Base64Coder.encode(rsm.getContent()));
		havemsgp = 1;

	}

	/**
	 * Create a Signature Message using the values in AuthInfo, and store it in
	 * lastauthmsg. Use the given privkey to sign the message.
	 * 
	 * @throws OTRException
	 */

	void createSignatureMessage(PrivKey privkey) throws OTRException {

		// Get the encrypted authenticator
		byte[] authbuf = calculatePubkeyAuth(privkey, mac_m1p, enc_cp);

		// Encrypted authenticator
		byte[] authbuf_w_len = new byte[4 + authbuf.length];
		writeInt(authbuf_w_len, 0, authbuf.length);
		System.arraycopy(authbuf, 0, authbuf_w_len, 4, authbuf.length);

		// MAC it, but only take the first 20 bytes
		HMAC hmac = prov.getHMACSHA256();
		hmac.setKey(mac_m2p);

		byte[] macbuf = hmac.tag(authbuf_w_len);
		byte[] trimmed = new byte[20];
		System.arraycopy(macbuf,0,trimmed,0,20);
		SignatureMessage sigm = new SignatureMessage((short)2, new Data(authbuf), trimmed);
		lastauthmsg = new String(Base64Coder.encode(sigm.getContent()));
	}

	/**
	 * Handle an incoming D-H Key Message.If no Exception is thrown, the message
	 * to sent will be left in lastauthmsg. Use the given private authentication
	 * key to sign messages.
	 * 
	 * @throws OTRException
	 */
	void handleKey(byte[] keymsg, PrivKey privkey) throws OTRException {
		if(keymsg.length<3){
			throw new OTRException("Invalid key message length");
		}
		byte[] res = new byte[keymsg.length-3];
		System.arraycopy(keymsg, 3, res, 0, res.length);

		havemsgp = 0;
		
		DHKeyMessage dhkm = DHKeyMessage.readDHKeyMessage(new InBuf(res), (short)2);

		MPI incoming_pub = dhkm.getGy();

		switch (authstate.curState) {
		case AuthState.ST_AWAITING_DHKEY:
			// store the incoming public key
			their_pub = prov.getDHPublicKey(incoming_pub);

			// Compute the encryption and MAC keys
			computeAuthKeys();
			// Create the Reveal Signature Message
			createRevealsigMessage(privkey);
			havemsgp = 1;
			authstate.processEvent(AuthState.EVT_DH_KEY_RCVD);
			break;

		case AuthState.ST_AWAITING_SIG:
			byte[] pub1 = their_pub.getY();
			byte[] pub2 = incoming_pub.toBytes();
			if (Util.arrayEquals(pub1, pub2)) {
				// Retransmit the Reveal Signature Message
				havemsgp = 1;
			} else {
				// Ignore this message
				havemsgp = 0;
			}
			break;

		case AuthState.ST_NONE:
		case AuthState.ST_AWAITING_REVEALSIG:
			// Ignore this message
			havemsgp = 0;
			break;
		}
	}

	/**
	 * Handle an incoming Reveal Signature Message. If no Exception is raised,
	 * and havemsgp is 1, the message to be sent will be left in lastauthmsg.
	 * Use the given private authentication key to sign messages.
	 * 
	 * @throws OTRException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 */

	void handleRevealsig(byte[] revealmsg, PrivKey privkey) throws OTRException {

		havemsgp = 0;
		if(revealmsg.length<3){
			throw new OTRException("Invalid revealsignature message length");
		}
		byte[] tmp = new byte[revealmsg.length-3];
		System.arraycopy(revealmsg, 3, tmp, 0, tmp.length);
		RevealSignatureMessage rsm = RevealSignatureMessage.readRevealSignatureMessage(new InBuf(tmp), (short)2);

		// r
		if (rsm.getRevealedKey().getValue().length != 16) {
			throw new OTRException("Invalid length.");
		}
		System.arraycopy(rsm.getRevealedKey().getValue(), 0, r, 0, 16);


		// auth
		int authlen = rsm.getEncryptedSignature().getLength();

		byte[] auth = new byte[4 + authlen];
		writeInt(auth, 0, authlen);
		System.arraycopy(rsm.getEncryptedSignature().getValue(), 0, auth, 4, auth.length-4);

		switch (authstate.curState) {
		case AuthState.ST_AWAITING_REVEALSIG:

			// Use r to decrypt the value of g^x we received earlier
			SecretKey secKey = prov.getAESKey(r);
			byte[] ctr = new byte[16];
			AESCTR aes;
			aes = prov.getAESCounterMode(secKey, ctr);
			byte[] gxbuf = aes.doFinal(encgx);
			byte[] gxbuf_trim = new byte[gxbuf.length - 4];
			System.arraycopy(gxbuf, 4, gxbuf_trim, 0, gxbuf_trim.length);

			// Check the hash
			byte[] hashbuf = prov.getSHA256().hash(gxbuf);
			if (!Util.arrayEquals(hashbuf, hashgx)) {
				throw new OTRException("Hash checking failed");
			}

			// Extract g^x
			MPI incoming_pub = new MPI(gxbuf_trim);
			their_pub = prov.getDHPublicKey(incoming_pub);

			// Compute the encryption and MAC keys
			computeAuthKeys();

			// Check the MAC
			HMAC hmac = prov.getHMACSHA256();
			hmac.setKey(mac_m2);
			byte[] macbuf = new byte[20];
			System.arraycopy(hmac.tag(auth), 0, macbuf, 0, 20);
			if (!Util.arrayEquals(macbuf, rsm.getSigMac().getValue())) {
				throw new OTRException("MAC checking failed");
			}

			// Check the auth
			byte[] auth_trim = new byte[authlen];

			System.arraycopy(auth, 4, auth_trim, 0, authlen);
			checkPubkeyAuth(auth_trim, mac_m1, enc_c);

			// Create the Signature Message
			createSignatureMessage(privkey);

			// We've completed our end of the authentication
			havemsgp = 1;
			authstate.processEvent(AuthState.EVT_REVEALSIG_RCVD);
			break;
		case AuthState.ST_NONE:
		case AuthState.ST_AWAITING_DHKEY:
		case AuthState.ST_AWAITING_SIG:
			// Ignore this message
			havemsgp = 0;
			break;
		}
	}

	/**
	 * Handle an incoming Signature Message. If no Exception is raised, and
	 * havemsgp is 1, the message to be sent will be left in lastauthmsg.
	 * 
	 * @throws OTRException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 */

	void handleSignature(byte[] sigmsg) throws OTRException {

		havemsgp = 0;

		byte[] tmp = new byte[sigmsg.length-3];
		System.arraycopy(sigmsg, 3, tmp, 0, tmp.length);
		SignatureMessage sm = SignatureMessage.readSignatureMessage(new InBuf(tmp), (short)2);

		// auth
		int authlen = sm.getEncryptedSignature().getLength();
		byte[] auth = new byte[authlen + 4];
		writeInt(auth, 0, authlen);
		System.arraycopy(sm.getEncryptedSignature().getValue(), 0, auth, 4, auth.length-4);

		switch (authstate.curState) {
		case AuthState.ST_AWAITING_SIG:
			
			// Check the MAC
			HMAC hmac = prov.getHMACSHA256();
			hmac.setKey(mac_m2p);
			byte[] macbuf = new byte[20];
			System.arraycopy(hmac.tag(auth), 0, macbuf, 0, 20);

			if (!Util.arrayEquals(macbuf, sm.getMacSignature())) {
				throw new OTRException("MAC checking failed");
			}

			// Check the auth
			byte[] auth_nolen = new byte[authlen];
			System.arraycopy(auth, 4, auth_nolen, 0, authlen);
			try {
				checkPubkeyAuth(auth_nolen, mac_m1p, enc_cp);
			} catch (Exception e) {
				e.printStackTrace();
				return;
			}

			// We've completed our end of the authentication.
			lastauthmsg = null;
			havemsgp = 0;
			authstate.processEvent(AuthState.EVT_SIG_RCVD);
			break;

		case AuthState.ST_NONE:
		case AuthState.ST_AWAITING_DHKEY:
		case AuthState.ST_AWAITING_REVEALSIG:
			// Ignore this message
			havemsgp = 0;
			break;
		}

	}

	void writeInt(byte[] dst, int index, int src) {
		dst[index] = (byte) ((src >> 24) & 0xff);
		dst[index + 1] = (byte) ((src >> 16) & 0xff);
		dst[index + 2] = (byte) ((src >> 8) & 0xff);
		dst[index + 3] = (byte) (src & 0xff);
	}

	int readInt(byte[] src, int index) {
		int ret = ((int) src[index] << 24)
				| ((int) (src[index + 1] << 16) & 0xff0000)
				| ((int) (src[index + 2] << 8) & 0xff00)
				| ((int) src[index + 3] & 0xff);
		return ret;
	}

	void computeAuthKeys() throws OTRCryptException {
		
		/* Check that their_pub is in range */
		byte[] two = {2};
		byte[] their_y = their_pub.getY();
		byte[] trimmedy = new byte[their_y.length-4];
		System.arraycopy(their_y, 4, trimmedy, 0, trimmedy.length);
	    if (prov.compareMPI(new MPI(trimmedy), new MPI(two)) < 0 ||
	    		prov.compareMPI(new MPI(trimmedy), new MPI(AuthInfo.DH_MODULUS_MINUS_2)) > 0) {
		/* Invalid pubkey */
			throw new OTRCryptException("Invalid pubkey");
	    }
	    
	    // Calculate the shared secret MPI
		DHKeyAgreement agreement = prov.getDHKeyAgreement();
		agreement.init(our_dh.getPrivateKey());
		byte[] secret = agreement.generateSecret(their_pub);

		byte[] sdata = new byte[5 + secret.length];
		sdata[1] = (byte) ((secret.length >> 24) & 0xff);
		sdata[2] = (byte) ((secret.length >> 16) & 0xff);
		sdata[3] = (byte) ((secret.length >> 8) & 0xff);
		sdata[4] = (byte) (secret.length & 0xff);
		System.arraycopy(secret, 0, sdata, 5, secret.length);
	    
	    /* Calculate the session id */
		sdata[0] = 0x00;
		byte[] res = prov.getSHA256().hash(sdata);
		System.arraycopy(res, 0, secure_session_id, 0, 8);  
		this.sessionid_len = 8;
		
		// Calculate the encryption keys
		sdata[0] = 0x01;
		res = prov.getSHA256().hash(sdata);
		byte[] aesSeed = new byte[16];
		System.arraycopy(res, 0, aesSeed, 0, 16);
		enc_c = prov.getAESKey(aesSeed);
		System.arraycopy(res, 16, aesSeed, 0, 16);
		enc_cp = prov.getAESKey(aesSeed);

		// Calculate the MAC keys
		sdata[0] = 0x02;
		mac_m1 = prov.getHMACKey(prov.getSHA256().hash(sdata));
		sdata[0] = 0x03;
		mac_m2 = prov.getHMACKey(prov.getSHA256().hash(sdata));
		sdata[0] = 0x04;
		mac_m1p = prov.getHMACKey(prov.getSHA256().hash(sdata));
		sdata[0] = 0x05;
		mac_m2p = prov.getHMACKey(prov.getSHA256().hash(sdata));

	}

}
