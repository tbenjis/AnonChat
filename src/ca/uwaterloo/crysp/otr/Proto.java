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
 * This is the class that performs actual encryption and
 * decryption of the messages
 *
 * @author Can Tang <c24tang@gmail.com>
 */

import ca.uwaterloo.crysp.otr.crypt.*;
import ca.uwaterloo.crysp.otr.iface.OTRTLV;
import ca.uwaterloo.crysp.otr.message.*;

public class Proto {

	/**
	 * Make a new DH key for us, and rotate old old ones. Be sure to keep the
	 * sesskeys array in sync.
	 * 
	 * @throws OTRException
	 */

	public static final int FRAGMENT_UNFRAGMENTED = 0;
	public static final int FRAGMENT_INCOMPLETE = 1;
	public static final int FRAGMENT_COMPLETE = 2;
	
	// The possible flags contained in a Data Message
	public static final byte MSGFLAGS_IGNORE_UNREADABLE=0x01;

	
	public static int fragmentAccumulate(ConnContext context, String msgstr){
	    int res = FRAGMENT_INCOMPLETE;
	    int tag = msgstr.indexOf("?OTR,");
	    if(tag==-1){
	    	context.fragment=null;
	    	context.fragment_k=0;
	    	context.fragment_n=0;
	    	return FRAGMENT_UNFRAGMENTED;
	    }
    	int n=0,k=0,secondcomma=0, thirdcomma=0;
    	secondcomma = msgstr.indexOf(",", 5);
    	thirdcomma = msgstr.indexOf(",", secondcomma+1);
    	k=Integer.parseInt(msgstr.substring(5, secondcomma));
    	n=Integer.parseInt(msgstr.substring(secondcomma+1, thirdcomma));
    	if(k>n) return res;
    	if(k==1){
    		context.fragment=msgstr.substring(thirdcomma+1, msgstr.length()-1);
    		context.fragment_k=k;
    		context.fragment_n=n;
    	}else if (n==context.fragment_n && k==context.fragment_k+1){
    		context.fragment=context.fragment+msgstr.substring(thirdcomma+1, msgstr.length()-1);
    		context.fragment_k=k;
    	}else{
	    	context.fragment=null;
	    	context.fragment_k=0;
	    	context.fragment_n=0;
    	}
    	if(context.fragment_n>0 && context.fragment_n==context.fragment_k){
    		// We've got a complete message
    		context.complete_msg=context.fragment;
	    	context.fragment=null;
	    	context.fragment_k=0;
	    	context.fragment_n=0;
	    	res=FRAGMENT_COMPLETE;
    	}
		return res;
	}
	
	public static String[] fragmentCreate(int mms, int fragcount, String msg){
		String fragdata;
		int fragdatalen = 0;
		int index = 0;
		int headerlen = 19; // Should vary by number of msgs

		String[] fragarray = new String[fragcount];

		// Find the next message fragment and store it in the array.
		for(int curfrag = 0; curfrag < fragcount; curfrag++) {
			if (msg.length() - index < mms - headerlen) {
				fragdatalen = msg.length() - index;
			} else {
				fragdatalen = mms - headerlen;
			}
			fragdata = msg.substring(index, index+fragdatalen);

		// Create the actual fragment and store it in the array
			fragarray[curfrag]="?OTR,"+(curfrag+1)+","+fragcount+","+fragdata+",";
			index += fragdatalen;
		}
		return fragarray;
	}
	
	//Store some MAC keys to be revealed later
	
	static void revealMacs(ConnContext conn, DHSesskeys sess1, DHSesskeys sess2){
		int numnew = sess1.rcvmacused + sess1.sendmacused +
			sess2.rcvmacused + sess2.sendmacused;
		
		// Is there anything to do?
		if(numnew == 0) return;
		int newnumsaved = conn.numSavedKeys + numnew;
		byte[] newmacs = new byte[newnumsaved*20];
		System.arraycopy(conn.savedMacKeys, 0, newmacs, 0, conn.savedMacKeys.length);
		if(sess1.rcvmacused!=0){
			System.arraycopy(sess1.rcvmackey, 0, newmacs, conn.numSavedKeys*20, 20);
			conn.numSavedKeys++;
		}
		if(sess1.sendmacused!=0){
			System.arraycopy(sess1.sendmackey, 0, newmacs, conn.numSavedKeys*20, 20);
			conn.numSavedKeys++;
		}
		if(sess2.rcvmacused!=0){
			System.arraycopy(sess2.rcvmackey, 0, newmacs, conn.numSavedKeys*20, 20);
			conn.numSavedKeys++;
		}
		if(sess2.sendmacused!=0){
			System.arraycopy(sess2.sendmackey, 0, newmacs, conn.numSavedKeys*20, 20);
			conn.numSavedKeys++;
		}
		conn.savedMacKeys = newmacs;
	}
	
	public static void rotateDHKeys(ConnContext conn) throws OTRException {
		// Rotate the keypair
		conn.our_old_dh_key = conn.our_dh_key;

		// Rotate the session keys
		revealMacs(conn, conn.sesskeys[1][0],
				conn.sesskeys[1][1]);
		conn.sesskeys[1][0] = conn.sesskeys[0][0];
		conn.sesskeys[1][1] = conn.sesskeys[0][1];

		// Create a new DH key
		conn.our_dh_key = conn.prov.getDHKeyPairGenerator().generateKeyPair();
		conn.our_keyid++;

		// Make the session keys
		if (conn.their_y != null) {
			conn.sesskeys[0][0] = new DHSesskeys(conn.prov);
			conn.sesskeys[0][0].computeSession(conn.our_dh_key, conn.their_y);
		}

		if (conn.their_old_y != null) {
			conn.sesskeys[0][1] = new DHSesskeys(conn.prov);
			conn.sesskeys[0][1].computeSession(conn.our_dh_key,conn.their_old_y);
		}

	}

	/**
	 * Rotate in a new DH public key for our correspondent. Be sure to keep the
	 * sesskeys array in sync.
	 * 
	 * @throws OTRException
	 */
	public static void rotateYKeys(ConnContext conn, DHPublicKey new_y)
			throws OTRException {
		// Rotate the public key
		conn.their_old_y = conn.their_y;

		// Rotate the session keys
		revealMacs(conn, conn.sesskeys[0][1],
				conn.sesskeys[1][1]);
		conn.sesskeys[0][1] = conn.sesskeys[0][0];
		conn.sesskeys[1][1] = conn.sesskeys[1][0];

		// Copy in the new public key
		conn.their_y = new_y;
		conn.their_keyid++;

		// Make the session keys
		conn.sesskeys[0][0] = new DHSesskeys(conn.prov);
		conn.sesskeys[1][0] = new DHSesskeys(conn.prov);
		conn.sesskeys[0][0].computeSession(conn.our_dh_key, new_y);
		conn.sesskeys[1][0].computeSession(conn.our_old_dh_key, new_y);

	}

	public static DataMessage createData(ConnContext conn, byte[] msg, byte flags, OTRTLV[] tlvs)
			throws OTRException {
		
		// Make sure we're actually supposed to be able to encrypt
		if(conn.msgState.getCurState() != MsgState.ST_ENCRYPTED ||
				conn.their_keyid == 0){
			throw new OTRException("Not able to encrypt message");
		}

		byte[] b2send=null;
        if(tlvs!=null){
            byte[] tlvb = new TLV().serialize(tlvs);
            b2send=new byte[msg.length+tlvb.length+1];
            System.arraycopy(tlvb, 0, b2send, msg.length+1, tlvb.length);
        }else{
            b2send=new byte[msg.length+1];
        }
        System.arraycopy(msg, 0, b2send, 0, msg.length);
        msg=b2send;
		
		DHSesskeys sess = conn.sesskeys[1][0];

		if (conn.msgState.getCurState() != MsgState.ST_ENCRYPTED
				|| conn.their_keyid == 0) {
			throw new OTRException("MsgState not encrypted");
		}

		byte[] ourdh = ((DHPublicKey) conn.our_dh_key.getPublicKey()).getY();
		MPI ourdh_big = MPI.readMPI(new InBuf(ourdh));

		// Top half of the counter
		byte[] tophalf = new byte[8];
		sess.incctr();
		System.arraycopy(sess.sendctr, 0, tophalf, 0, 8);

		// Encrypted data
		AESCTR aes;
		aes = conn.prov.getAESCounterMode(sess.sendenc, sess.sendctr);
		byte[] enc = aes.doFinal(msg);

		byte[] msg2mac = new byte[2 + 1 + 1 + 4 + 4 + ourdh.length + 8 + 4
				+ enc.length];
		msg2mac[1] = 2;
		msg2mac[2] = 3;
		Util.writeInt(msg2mac, 4, conn.our_keyid - 1);
		Util.writeInt(msg2mac, 8, conn.their_keyid);
		System.arraycopy(ourdh, 0, msg2mac, 12, ourdh.length);
		System.arraycopy(tophalf, 0, msg2mac, 12 + ourdh.length, 8);
		Util.writeInt(msg2mac, 12 + ourdh.length + 8, enc.length);
		System.arraycopy(enc, 0, msg2mac, 12 + ourdh.length + 12, enc.length);

		// MAC authenticator
		HMAC hmac = conn.prov.getHMACSHA1();
		hmac.setKey(conn.prov.getHMACKey(sess.sendmackey));

		byte[] macbuf = hmac.tag(msg2mac);
		byte[] trimmed = new byte[20];

		System.arraycopy(macbuf, 0, trimmed, 0, 20);
		DataMessage dm = new DataMessage((short) 2, flags,
				conn.our_keyid - 1, conn.their_keyid, ourdh_big, tophalf,
				new Data(enc), trimmed, new Data(conn.savedMacKeys));
		conn.savedMacKeys=new byte[0];
		conn.numSavedKeys=0;

		return dm;
	}

	/**
	 * Accept an OTR Data Message in datamsg. Decrypt it and return the
	 * plaintext
	 */
	public static byte[] acceptData(ConnContext context, DataMessage msg,
			byte[] flags) throws OTRException {

		if (msg.getProtocolVersion() != 2) {
			throw new OTRException("Wrong protocol version");
		}
		long sender_keyid = msg.getSenderKeyId();
		long recipient_keyid = msg.getRecipientKeyId();
		MPI nexty = msg.getNextSenderKey();
		byte[] their_y = nexty.toBytes();
		byte[] ctr = msg.getCounterInit();
		byte[] data = msg.getEncryptedMessage().getValue();
		byte[] givenmac = msg.getAuthenticator();

		/*
		 * We don't take any action on this message (especially rotating keys)
		 * until we've verified the MAC on this message. To that end, we need to
		 * know which keys this message is claiming to use.
		 */
		if (context.their_keyid == 0
				|| (sender_keyid != context.their_keyid && sender_keyid != context.their_keyid - 1)
				|| (recipient_keyid != context.our_keyid && recipient_keyid != context.our_keyid - 1)
				|| sender_keyid == 0
				|| recipient_keyid == 0
				|| (sender_keyid == context.their_keyid - 1 && context.their_old_y == null)) {
			throw new OTRException("Key id conflict");
		}
		/* These are the session keys this message is claiming to use. */

		DHSesskeys sess = context.sesskeys[context.our_keyid
				- (int) recipient_keyid][context.their_keyid
				- (int) sender_keyid];
		byte[] msg2mac = new byte[2 + 2 + 4 + 4 + their_y.length + 8 + 4
				+ data.length];
		msg2mac[1] = 2;
		msg2mac[2] = 3;
		Util.writeInt(msg2mac, 4, (int) sender_keyid);
		Util.writeInt(msg2mac, 8, (int) recipient_keyid);
		System.arraycopy(their_y, 0, msg2mac, 12, their_y.length);
		System.arraycopy(ctr, 0, msg2mac, 12 + their_y.length, 8);
		Util.writeInt(msg2mac, 12 + their_y.length + 8, data.length);
		System.arraycopy(data, 0, msg2mac, 12 + their_y.length + 12,
				data.length);

		// MAC authenticator
		HMAC hmac = context.prov.getHMACSHA1();
		hmac.setKey(context.prov.getHMACKey(sess.rcvmackey));
		byte[] macbuf = hmac.tag(msg2mac);
		byte[] trimmed = new byte[20];
		System.arraycopy(macbuf, 0, trimmed, 0, 20);

		if (!Util.arrayEquals(trimmed, givenmac)) {
			/* The MACs didn't match! */
			throw new OTRException("Mac checking failed");
		}
		sess.rcvmacused=1;
		
		/*
		 * Check to see that the counter is increasing; i.e. that this isn't a
		 * replay.
		 */
		if (sess.cmpctr(ctr, false) == 0) {
			throw new OTRException("Counter not increasing");
		}

		/* Decrypt the message */
		System.arraycopy(ctr, 0, sess.rcvctr, 0, 8);

		AESCTR aes = context.prov.getAESCounterMode(sess.rcvenc, sess.rcvctr);
		byte[] plaintext = aes.doFinal(data);

		/* See if either set of keys needs rotating */

		if (recipient_keyid == context.our_keyid) {
			/* They're using our most recent key, so generate a new one */
			rotateDHKeys(context);
		}

		if (sender_keyid == context.their_keyid) {
			/* They've sent us a new public key */
			DHPublicKey their_pub = context.prov.getDHPublicKey(nexty);
			rotateYKeys(context, their_pub);
		}
		return plaintext;
	}

}
