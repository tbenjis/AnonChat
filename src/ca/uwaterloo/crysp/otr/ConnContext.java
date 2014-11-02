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

import java.util.Hashtable;

import ca.uwaterloo.crysp.otr.crypt.DHPublicKey;
import ca.uwaterloo.crysp.otr.crypt.DHSesskeys;
import ca.uwaterloo.crysp.otr.crypt.KeyPair;
import ca.uwaterloo.crysp.otr.crypt.MPI;
import ca.uwaterloo.crysp.otr.crypt.Provider;
import ca.uwaterloo.crysp.otr.message.DataMessage;
import ca.uwaterloo.crysp.otr.message.ErrorMessage;
import ca.uwaterloo.crysp.otr.message.OTRMessage;
import ca.uwaterloo.crysp.otr.message.QueryMessage;
import ca.uwaterloo.crysp.otr.message.TaggedPlaintextMessage;
import ca.uwaterloo.crysp.otr.iface.*;

/**
 * The class which stores the state for a conversation context and processes
 * messages
 * 
 * @author Can Tang <c24tang@gmail.com>
 */

public class ConnContext implements OTRContext {

    String accountName; // The recName is relative to this account...
    String recName; // The recipient name
    String protocol; // ... and this protocol
    MsgState msgState = new MsgState(); // The state of message disposition with
                                        // this user
    
    String fragment;             // The part of the fragmented message
                                //we've seen so far 
    int fragment_n;         //The total number of fragments in this message
    int fragment_k;         // The highest fragment number
                            //we've seen so far for this message
    String complete_msg;    // The completed message from fragments
    
    AuthInfo auth;

    Hashtable fingerprintTable = new Hashtable(); // The table of Fingerprints
    // entries
    FingerPrint activeFingerprint; // Which fingerprint is in use now?
    // A reference into the above list

    int their_keyid; // current keyid used by other side;
    // this is set to 0 if we get a TLV.DISCONNECTED
    // message from them.

    DHPublicKey their_y;
    DHPublicKey their_old_y;

    int our_keyid; // current keyid used by us

    KeyPair our_dh_key;
    KeyPair our_old_dh_key;

    DHSesskeys sesskeys[][] = new DHSesskeys[2][2]; // sesskeys[i][j] are the
                                                    // session keys
    // derived from DH key[our_keyid-i]
    // and mpi Y[their_keyid-j] */

    byte[] sessionId = new byte[20]; // The sessionid
    int sessionid_len;// Its length

    byte[] presharedSecret; // A secret you share with this user, in order to do
    // authentication.

    /* saved mac keys to be revealed later */
    int numSavedKeys;
    byte[] savedMacKeys = new byte[0];

    /*
     * generation number: increment every time we go private, and never reset to
     * 0 (unless we remove the context entirely)
     */
    int generation;

    long lastSent; // The last time a Data Message was sent
    String lastMessage; // The plaintext of the last Data Message sent
    int mayRetransmit; // Is the last message eligible for retransmission?
    
    SMState smstate = new SMState();

    /* Has this correspondent responded to our OTR offers? */
    public static final int OFFER_NOT = 0;
    public static final int OFFER_SENT = 1;
    public static final int OFFER_REJECTED = 2;
    public static final int OFFER_ACCEPTED = 3;
    int otr_offer;

    public static final String OTRL_MESSAGE_TAG_BASE = " \t  \t\t\t\t \t \t \t  ";
    public static final String OTRL_MESSAGE_TAG_V2 = "  \t\t  \t ";

    Provider prov;
    UserState us;
	int gone_encrypted;
    int ignore_message;
    

    public ConnContext(String aname, String rname, String prot, Provider prov, 
    		UserState us) {
        this.accountName = aname;
        this.recName = rname;
        this.protocol = prot;
        this.prov = prov;
        this.us = us;
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                sesskeys[i][j] = new DHSesskeys(prov);
            }
        }
        auth = new AuthInfo(prov);
    }

    public String getRecipient() {
        return recName;
    }

    public String getAccountName() {
        return accountName;
    }

    public String getProtocol() {
        return protocol;
    }

    FingerPrint findFingerPrint(byte[] fingerprint, boolean add, OTRCallbacks callback) {
        String key = new String(fingerprint);
        FingerPrint ret = (FingerPrint) fingerprintTable.get(key);
        if (ret != null)
            return ret;
        if (!add)
            return null;
        ret = new FingerPrint();
        ret.fingerPrint = new byte[fingerprint.length];
        System
                .arraycopy(fingerprint, 0, ret.fingerPrint, 0,
                        fingerprint.length);
        ret.context = this;
        fingerprintTable.put(key, ret);
        /* Inform the user of the new fingerprint */
        callback.newFingerprint(us, accountName, key, recName, ret.fingerPrint);
        /* Arrange that the new fingerprint be written to disk */
        callback.writeFingerprints();
        return ret;
    }
    
    // Send a message to the network, fragmenting first if necessary.
    // All messages to be sent to the network should go through this
    // method immediately before they are sent, ie after encryption. 
    String fragmentAndSend(String message,
    	int fragPolicy, OTRCallbacks callback)
    {
        int mms = callback.maxMessageSize(this);
    	// Don't incur overhead of fragmentation unless necessary 
        if(mms==0 || message.length() <= mms){
        	// No fragmentation necessary 
        	if (fragPolicy == Policy.FRAGMENT_SEND_ALL) {
        		callback.injectMessage(this.accountName, 
        				this.protocol, this.recName, message);
        		return null;
        	} else {
        		// return the entire given message. 
        		return message;
        	}
        }
	    int fragment_count = ((message.length() - 1) / (mms -19)) + 1;
		// like ceil(msglen/(mms - 19)) 

	    String[] frags = Proto.fragmentCreate(mms, fragment_count, message);
	    String returnFragment=null;
	    
    	// Determine which fragments to send and which to return
    	// based on given Fragment Policy.  If the first fragment
    	// should be returned instead of sent, store it. 
    	    if (fragPolicy == Policy.FRAGMENT_SEND_ALL_BUT_FIRST) {
    	    	returnFragment = frags[0];
    	    } else {
    	    	callback.injectMessage(accountName, 
        				protocol, recName, frags[0]);
    	    }
    	    
    	    // Prevent the demo receiver to receive all the messages in a single read
	    	try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
    	    for (int i=1; i<fragment_count-1; i++) {
    	    	callback.injectMessage(accountName, 
        				protocol, recName, frags[i]);
    	    	try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
    	    }
    	    // If the last fragment should be stored instead of sent,
    	    // store it 
    	    if (fragPolicy == Policy.FRAGMENT_SEND_ALL_BUT_LAST) {
    	    	returnFragment = frags[fragment_count-1];
    	    } else {
    	    	callback.injectMessage(accountName, 
        				protocol, recName, frags[fragment_count-1]);
    	    }
	    return returnFragment;
    }

    void goEncrypted(OTRCallbacks callback) throws OTRException {

    	
        // See if we're talking to ourselves
    	byte[] theiry = auth.their_pub.serialize();
    	byte[] their_trim = new byte[theiry.length-4];
    	System.arraycopy(theiry, 4, their_trim, 0, their_trim.length);
    	byte[] oury = auth.our_dh.getPublicKey().serialize();
    	byte[] our_trim = new byte[oury.length-4];
    	System.arraycopy(oury, 4, our_trim, 0, our_trim.length);
    	
    	if(prov.compareMPI(new MPI(their_trim), new MPI(our_trim))==0){
    		// Yes, we are.
    		callback.handleMsgEvent(OTRCallbacks.OTRL_MSGEVENT_MSG_REFLECTED, 
    				this, null);
    		throw new OTRException("Message reflected");
    	}
    	
        // Find the fingerprint
        FingerPrint found_print = this.findFingerPrint(auth.their_fingerprint,
                true, callback);
        
        /* Is this a new session or just a refresh of an existing one? */
        if(this.msgState.getCurState()==MsgState.ST_ENCRYPTED &&
        		Util.arrayEquals(this.activeFingerprint.fingerPrint, found_print.fingerPrint)&&
        		this.our_keyid - 1 == this.auth.our_keyid &&
        		prov.compareMPI(MPI.readMPI(new InBuf
        				(this.our_old_dh_key.getPublicKey().serialize())), 
        				MPI.readMPI(new InBuf
        						(this.auth.our_dh.getPublicKey().serialize())))==0 &&
        		((this.their_keyid>0 &&
        		  this.their_keyid == auth.their_keyid &&
        		  prov.compareMPI(MPI.readMPI(new InBuf
        				  (this.their_y.serialize())), 
        				MPI.readMPI(new 
        						InBuf(this.auth.their_pub.serialize())))==0)
        			||
        				
        		(this.their_keyid > 1 && 
        				this.their_keyid-1 == this.auth.their_keyid &&
        				this.their_old_y != null &&
        				prov.compareMPI(MPI.readMPI(new InBuf(this.their_y.serialize())), 
                				MPI.readMPI(new InBuf(this.auth.their_pub.serialize())))==0))
            )
        {
        	/* This is just a refresh of the existing session. */
        	callback.stillSecure(this, auth.initiated);
        	ignore_message=1;
        	return;
        }
       
        
        // Copy the information from the auth into the context
        System.arraycopy(auth.secure_session_id, 0, this.sessionId, 0, 20);
        this.sessionid_len = auth.sessionid_len;
        
        // Copy the keys
        this.their_keyid = auth.their_keyid;
        this.their_y = auth.their_pub;
        this.their_old_y = null;

        if (our_keyid - 1 != auth.our_keyid) {
            this.our_old_dh_key = auth.our_dh;
            this.our_dh_key = prov.getDHKeyPairGenerator().generateKeyPair();
            this.our_keyid = auth.our_keyid + 1;
        }

        // Create the session keys from the DH keys
        this.sesskeys[0][0] = new DHSesskeys(prov);
        this.sesskeys[1][0] = new DHSesskeys(prov);
        this.sesskeys[0][0].computeSession(this.our_dh_key, this.their_y);
        this.sesskeys[1][0].computeSession(this.our_old_dh_key, this.their_y);

        this.generation++;
        this.activeFingerprint = found_print;
        int oldstate = msgState.getCurState();
        msgState.processEvent(MsgState.EVT_AUTHENTICATED);
        callback.updateContextList();
        if(oldstate == MsgState.ST_ENCRYPTED &&
        		Util.arrayEquals(this.activeFingerprint.fingerPrint, 
        				found_print.fingerPrint)){
        	callback.stillSecure(this, this.auth.initiated);
        }else{
        	//get our fingerprint
        	byte[] our_fp = PrivKey.fingerprintRaw(us, this.accountName, this.protocol, prov);
        	callback.goneSecure(this, our_fp);
        }
        this.gone_encrypted = 1;
    }
    
    void sendOrErrorAuth(boolean err, OTRCallbacks callback){
    	
    	if(!err){
    		String msg = this.auth.lastauthmsg;
    		if(msg!=null){
	    		this.fragmentAndSend(msg, Policy.FRAGMENT_SEND_ALL, callback);
	    		this.lastSent = System.currentTimeMillis();
    		}
    	}else{
    		callback.handleMsgEvent(OTRCallbacks.OTRL_MSGEVENT_SETUP_ERROR,
    				this, null);
    	}
    	
    }
    
    /** Handle a message about to be sent to the network.  It is safe to pass
     * all messages about to be sent to this routine. 
     *
     * tlvs is an array of OTRTLVs to append to the private message.  It is
     * usually correct to just pass null here.
     */
    public String messageSending(String message, OTRTLV[] tlvs, int fragPolicy,
    		OTRCallbacks callback) throws OTRException {

        int policy = Policy.DEFAULT;

        if (message == null)
            throw new OTRException("MessageSending: Null argument");

        // Check the policy
        policy = callback.getOtrPolicy(this);

        // Should we go on at all?
        if ((policy & Policy.VERSION_MASK) == 0) {
            throw new OTRException("Invalid protocol");
        }

        // If this is an OTR Query message, don't encrypt it.
        OTRMessage otrmessage = OTRMessage.parse(message);
        if (otrmessage.getType() == OTRMessage.MSG_QUERY) {
            // Replace the "?OTR?" with a custom message
            QueryMessage bettermsg = defaultQueryMessage(accountName, policy);
            String ret = new String(bettermsg.getContent());
            if(fragPolicy == Policy.FRAGMENT_SEND_SKIP) return ret;
            return this.fragmentAndSend(ret, fragPolicy, callback);
        }

        switch (msgState.getCurState()) {
        case MsgState.ST_UNENCRYPTED:
            if ((policy & Policy.REQUIRE_ENCRYPTION) != 0) {
                /*
                 * We're trying to send an unencrypted message with a policy
                 * that disallows that. Don't do that, but try to start up OTR
                 * instead.
                 */
            	callback.handleMsgEvent(OTRCallbacks.OTRL_MSGEVENT_ENCRYPTION_REQUIRED,
            			this, null);
                QueryMessage bettermsg = defaultQueryMessage(accountName,
                        policy);
                lastMessage = new String(bettermsg.getContent());
                lastSent = System.currentTimeMillis() % 1000;
                mayRetransmit = 2;
                String ret = new String(bettermsg.getContent());
                if(fragPolicy == Policy.FRAGMENT_SEND_SKIP) return ret;
                return this.fragmentAndSend(ret, fragPolicy, callback);
            } else {
                if ((policy & Policy.SEND_WHITESPACE_TAG) != 0
                        && otr_offer != OFFER_REJECTED) {
                    /*
                     * See if this user can speak OTR. Append the
                     * OTR_MESSAGE_TAG to the plaintext message, and see if he
                     * responds.
                     */
                    String taggedmsg = message + OTRL_MESSAGE_TAG_BASE
                            + OTRL_MESSAGE_TAG_V2;
                    otr_offer = OFFER_SENT;
                    if(fragPolicy == Policy.FRAGMENT_SEND_SKIP) return taggedmsg;
                    return this.fragmentAndSend(taggedmsg, fragPolicy, callback);
                }
            }
            break;
        case MsgState.ST_ENCRYPTED:
            // Create the new, encrypted message
            try {
                DataMessage dm = Proto.createData(this, message.getBytes(), (byte)0, tlvs);
                lastMessage = new String(dm.getContent());
                lastSent = System.currentTimeMillis() % 1000;
                String ret = new String(dm.getContent());
                if(fragPolicy == Policy.FRAGMENT_SEND_SKIP) return ret;
                return this.fragmentAndSend(ret, fragPolicy, callback);
            } catch (OTRException e) {
        		/* Uh, oh.  Whatever we do, *don't* send the message in the
        		 * clear. */
            	callback.handleMsgEvent(OTRCallbacks.OTRL_ERRCODE_ENCRYPTION_ERROR,
            			this, null);
            	callback.errorMessage(this, OTRCallbacks.OTRL_ERRCODE_ENCRYPTION_ERROR);
        		return null;
            }

        case MsgState.ST_FINISHED:
            callback.handleMsgEvent(OTRCallbacks.OTRL_MSGEVENT_CONNECTION_ENDED, this, null);
            String ret = new String(new ErrorMessage("").getContent());
            if(fragPolicy == Policy.FRAGMENT_SEND_SKIP) return ret;
            return this.fragmentAndSend(ret, fragPolicy, callback);
        }
        return null;
    }
    
    /* Set the trust level based on the result of the SMP */
    void setSmpTrust(OTRCallbacks callback, boolean trusted){
    	this.activeFingerprint.trust = trusted? "smp":"";
    	/* Write the new info to disk, redraw the ui, and redraw the
         * OTR buttons. */
    	callback.writeFingerprints();
    }


    void initRespondSmp(String question, 
    		String secret, boolean initiating, OTRCallbacks callback) throws OTRException
    	{
    	    if (msgState.getCurState()!=MsgState.ST_ENCRYPTED) return;
    	    /*
    	     * Construct the combined secret as a SHA256 hash of:
    	     * Version byte (0x01), Initiator fingerprint (20 bytes),
    	     * responder fingerprint (20 bytes), secure session id, input secret
    	     */
    	    byte[] our_fp = PrivKey.fingerprintRaw(us, this.accountName, this.protocol, prov);

    	    int combined_buf_len = 41 + this.sessionid_len + secret.length();
    	    byte[] combined_buf = new byte[combined_buf_len];
    	    combined_buf[0]=1;
    	    if(initiating){
    	    	System.arraycopy(our_fp, 0, combined_buf, 1, 20);
    	    	System.arraycopy(this.activeFingerprint.fingerPrint, 0, combined_buf, 21, 20);
    	    }else{
    	    	System.arraycopy(this.activeFingerprint.fingerPrint, 0, combined_buf, 1, 20);
    	    	System.arraycopy(our_fp, 0, combined_buf, 21, 20);
    	    }
    	    System.arraycopy(this.sessionId, 0, combined_buf, 41, this.sessionid_len);
    	    System.arraycopy(secret.getBytes(), 0, 
    	    		combined_buf, 41+this.sessionid_len, secret.length());
    	    
    	    byte[] combined_secret = prov.getSHA256().hash(combined_buf);
    	    byte[] smpmsg;
    	    if(initiating){
    	    	smpmsg = SM.step1(smstate, combined_secret, prov);
    	    }else{
    	    	smpmsg = SM.step2b(smstate, combined_secret, prov);
    	    }
    	    
    	    // If we've got a question, attach it to the smpmsg 
    	    if(question != null){
    	    	byte[] qsmpmsg = new byte[question.length() + 1 + smpmsg.length];
    	    	System.arraycopy(question.getBytes(), 0, qsmpmsg, 0, question.length());
    	    	System.arraycopy(smpmsg, 0, qsmpmsg, question.length()+1, smpmsg.length);
    	    	smpmsg = qsmpmsg;
    	    }
    	    
    	    //Send msg with next smp msg content 
    	    TLV sendtlv = new TLV(initiating? 
    	    		(question!=null? TLV.SMP1Q:TLV.SMP1):TLV.SMP2, smpmsg);
    	    TLV[] tlvs = new TLV[1];
    	    tlvs[0] = sendtlv;
    	    byte[] emptymsg = new byte[0];
    	    DataMessage dm = Proto.createData(this, emptymsg, Proto.MSGFLAGS_IGNORE_UNREADABLE, tlvs);
    	    
    	    fragmentAndSend(new String(dm.getContent()), Policy.FRAGMENT_SEND_ALL, callback);
    	    this.smstate.nextExpected = initiating? SM.EXPECT2 : SM.EXPECT3;
    	}
    
    /** Initiate the Socialist Millionaires' Protocol */
    public void initiateSmp(String secret, OTRCallbacks callback) throws OTRException{
    	initRespondSmp(null, secret, true, callback);
    }
    
    /** Initiate the Socialist Millionaires' Protocol and send a prompt
     * question to the buddy */
    public void initiateSmp_q(String question, String secret, OTRCallbacks callback) throws OTRException{
    	initRespondSmp(question, secret, true, callback);
    }
    
    /** Respond to a buddy initiating the Socialist Millionaires' Protocol */
    public void respondSmp(String secret, OTRCallbacks callback) throws OTRException{
    	initRespondSmp(null, secret, false, callback);
    }
    
    /** Abort the SMP.  Called when an unexpected SMP message breaks the
     * normal flow. */
    public void abortSmp(OTRCallbacks callback) throws OTRException{
    	TLV sendtlv = new TLV(TLV.SMP_ABORT, new byte[0]);
    	TLV[] tlvs = new TLV[1];
    	tlvs[0] = sendtlv;
    	this.smstate.nextExpected = SM.EXPECT1;
    	
    	DataMessage dm = 
    		Proto.createData(this, new byte[0], Proto.MSGFLAGS_IGNORE_UNREADABLE, tlvs);
    	// Send the abort signal so our buddy knows we've stopped 
    	this.fragmentAndSend(new String(dm.getContent()), Policy.FRAGMENT_SEND_ALL, callback);
    }

    /** Handle a message just received from the network.  It is safe to pass
     * all received messages to this routine. 
     * 
     * If no Exception is thrown, and the return value is not null,
     *  replace the received message with 
     * msg in the returned StringTLV, and deliver that to the user instead. 
     *
     * If the return value is null, then the message you received
	 * was an internal protocol message, and no message should be delivered
	 * to the user.
	 *
     */    
    public StringTLV messageReceiving(String inMessage, OTRCallbacks callback) throws OTRException {
    	
    	OTRMessage message = OTRMessage.parse(inMessage);

        /* Check the policy */
        int policy = callback.getOtrPolicy(this);

        /* Should we go on at all? */
        if ((policy & Policy.VERSION_MASK) == 0) {
            return null;
        }
        
        // See if we have a fragment 
        switch(Proto.fragmentAccumulate(this, new String(message.getContent()))) {
    	case Proto.FRAGMENT_UNFRAGMENTED:
    	    // Do nothing 
    	    break;
    	case Proto.FRAGMENT_INCOMPLETE:
    	    // We've accumulated this fragment, but we don't have a
    	    // complete message yet 
    	    return null;
    	case Proto.FRAGMENT_COMPLETE:
    	    // We've got a new complete message, in unfragmessage. 
    	    message = OTRMessage.parse(this.complete_msg);
    	    break;
        }

        byte msgtype = message.getType();

        /* See if they responded to our OTR offer */
        if ((policy & Policy.SEND_WHITESPACE_TAG) != 0) {
            if (msgtype != OTRMessage.MSG_NOTOTR) {
                otr_offer = OFFER_ACCEPTED;
            } else if (otr_offer == OFFER_SENT) {
                otr_offer = OFFER_REJECTED;
            }
        }
        
        gone_encrypted=0;
        ignore_message = -1;
        
        
        switch (msgtype) {
        case OTRMessage.MSG_QUERY:

            /* Start AKE */
        	try{
	            auth.startAKE(null);
	            this.sendOrErrorAuth(false, callback);
        	}catch (OTRException e){
        		this.sendOrErrorAuth(true, callback);
        	}
            if (auth.havemsgp != 0) {
                this.lastMessage = auth.lastauthmsg;
            }
            /* Don't display the Query message to the user. */
    	    if (ignore_message == -1) ignore_message = 1;
            break;
        case OTRMessage.MSG_DH_COMMIT:
            if ((policy & Policy.ALLOW_V2) != 0) {
            	try{
            		auth.handleCommit(message.getContent(), null);
    	            this.sendOrErrorAuth(false, callback);
            	}catch (OTRException e){
            		this.sendOrErrorAuth(true, callback);
            	}
            }
            if (ignore_message == -1) ignore_message = 1;
            break;
        case OTRMessage.MSG_DH_KEY:
            if ((policy & Policy.ALLOW_V2) != 0) {
                /* Get our private key */
                PrivKey privkey = us.getPrivKey(new Account(accountName,
                        protocol), true);
                try{
                	auth.handleKey(message.getContent(), privkey);
                	this.sendOrErrorAuth(false, callback);
            	}catch (OTRException e){
            		this.sendOrErrorAuth(true, callback);
            	}
            }
            if (ignore_message == -1) ignore_message = 1;
            break;

        case OTRMessage.MSG_REVEAL_SIGNATURE:
            if ((policy & Policy.ALLOW_V2) != 0) {
                /* Get our private key */
                PrivKey privkey = us.getPrivKey(new Account(accountName,
                        protocol), true);
                try {
                    auth.handleRevealsig(message.getContent(), privkey);
                    this.goEncrypted(callback);
                    this.sendOrErrorAuth(false, callback);
            	}catch (OTRException e){
            		this.sendOrErrorAuth(true, callback);
            	}
            }
            if (ignore_message == -1) ignore_message = 1;
            break;
        case OTRMessage.MSG_SIGNATURE:
            if ((policy & Policy.ALLOW_V2) != 0) {
                /* Get our private key */
                try {
                    auth.handleSignature(message.getContent());
                    this.goEncrypted(callback);
                    this.sendOrErrorAuth(false, callback);
            	}catch (OTRException e){
            		this.sendOrErrorAuth(true, callback);
            	}
            	
            }
            if (ignore_message == -1) ignore_message = 1;
            break;
        case OTRMessage.MSG_DATA:
            switch (msgState.getCurState()) {
            case MsgState.ST_UNENCRYPTED:
            case MsgState.ST_FINISHED:
            	callback.handleMsgEvent(OTRCallbacks.OTRL_ERRCODE_MSG_NOT_IN_PRIVATE,
            			this, null);
            	ignore_message = 1;
            	String err_msg = callback.errorMessage(this,
            			OTRCallbacks.OTRL_ERRCODE_MSG_NOT_IN_PRIVATE);
            	callback.injectMessage(accountName, protocol, recName, err_msg);
                break;
            case MsgState.ST_ENCRYPTED:
                byte[] res;
                StringTLV stlv = new StringTLV();
                OTRTLV[] tlvs;
                try {
                    DataMessage dm = (DataMessage) message;
                    res = Proto.acceptData(this, dm, null);
                } catch (OTRException otre) {
                    callback.handleMsgEvent(OTRCallbacks.OTRL_MSGEVENT_RCVDMSG_UNREADABLE, 
                    		this, null);
                    return null;
                }
                int end = 0;
                for (; end < res.length && res[end] != 0; end++) {
                }
                
                stlv.msg = new String(res, 0, end);
                if (end != res.length&&end+1!=res.length) {
                    end++;
                    tlvs = new TLV().parse(res, end, res.length - end);
                    stlv.tlvs = tlvs;
                    
                    
        		    /* If the other side told us he's disconnected his
        		     * private connection, make a note of that so we
        		     * don't try sending anything else to him. */
                    OTRTLV tlv = new TLV().find(tlvs, TLV.DISCONNECTED);
        		    if(tlv!=null){
						forceFinished();
        		    }

	                /* If TLVs contain SMP data, process it */
	    		    int nextMsg = this.smstate.nextExpected;
	                tlv = new TLV().find(tlvs, TLV.SMP1Q);
	    		    if (tlv != null && nextMsg == SM.EXPECT1) {
	    				/* We can only do the verification half now.
	    				 * We must wait for the secret to be entered
	    				 * to continue. */
	    				byte[] question = tlv.getValue();
	    				int qlen=0;
	    				for(; qlen!=question.length && question[qlen]!=0; qlen++){
	    				}
	    				if(qlen == question.length) qlen=0;
	    				else qlen++;
	    				byte[] input = new byte[question.length-qlen];
	    				System.arraycopy(question, qlen, input, 0, question.length-qlen);
	    				SM.step2a(this.smstate, input, 1, prov);
	    				if(qlen!=0)qlen--;
	    				byte[] plainq = new byte[qlen];
	    				System.arraycopy(question, 0, plainq, 0, qlen);
	    				if(this.smstate.smProgState != SM.PROG_CHEATED){
	    					callback.handleSmpEvent(OTRCallbacks.OTRL_SMPEVENT_ASK_FOR_ANSWER,
	    							this, 25, new String(plainq));
	    				}else{
	    					callback.handleSmpEvent(OTRCallbacks.OTRL_SMPEVENT_CHEATED,
	    							this, 0, null);
	    					this.smstate.nextExpected = SM.EXPECT1;
	    					this.smstate.smProgState = SM.PROG_OK;
	    				}
	                }else{
	                	callback.handleSmpEvent(OTRCallbacks.OTRL_SMPEVENT_ERROR,
	                			this, 0, null);
	                }
	    		    
	                tlv = new TLV().find(tlvs, TLV.SMP1);
	                if (tlv != null){
	                	if(nextMsg == SM.EXPECT1) {
		    				/* We can only do the verification half now.
		    				 * We must wait for the secret to be entered
		    				 * to continue. */
		                	SM.step2a(this.smstate, tlv.getValue(), 0, prov);
		                	if(this.smstate.smProgState!=SM.PROG_CHEATED){
		                		callback.handleSmpEvent(OTRCallbacks.OTRL_SMPEVENT_ASK_FOR_SECRET, this, 25, null);
		                	}else{
		                		callback.handleSmpEvent(OTRCallbacks.OTRL_SMPEVENT_CHEATED,
		    							this, 0, null);
		                		this.smstate.nextExpected = SM.EXPECT1;
		    					this.smstate.smProgState = SM.PROG_OK;
		                	}
	                	}else{
	                		callback.handleSmpEvent(OTRCallbacks.OTRL_SMPEVENT_ERROR,
		                			this, 0, null);
	                	}
	                }
	                
	                tlv = new TLV().find(tlvs, TLV.SMP2);
	                if (tlv != null && nextMsg == SM.EXPECT2) {
	                	byte[] nextmsg = SM.step3(this.smstate, tlv.getValue(), prov);
	                	if(this.smstate.smProgState != SM.PROG_CHEATED){
	                		/* Send msg with next smp msg content */
	                		OTRTLV sendtlv = new TLV(TLV.SMP3, nextmsg);
	                		OTRTLV[] stlvs = new OTRTLV[1];
	                		stlvs[0]=sendtlv;
	                		DataMessage dm = Proto.createData(this, new byte[0], 
	                				Proto.MSGFLAGS_IGNORE_UNREADABLE, stlvs);
	                		byte[] senddata = dm.getContent();
	                		this.fragmentAndSend(new String(senddata), Policy.FRAGMENT_SEND_ALL, callback);
	                		this.smstate.nextExpected = SM.EXPECT4;
	                	}else{
	                		callback.handleSmpEvent( OTRCallbacks.OTRL_SMPEVENT_CHEATED,
	    							this, 0, null);
	                		this.smstate.nextExpected = SM.EXPECT1;
	    					this.smstate.smProgState = SM.PROG_OK;
	                	}
	                }else if(tlv != null){
	                	callback.handleSmpEvent(OTRCallbacks.OTRL_SMPEVENT_ERROR,
	                			this, 0, null);
	                }
	                
	                
	                tlv = new TLV().find(tlvs, TLV.SMP3);
	                if (tlv != null && nextMsg == SM.EXPECT3) {
	                	byte[] nextmsg = SM.step4(this.smstate, tlv.getValue(), prov);
	                	/* Set trust level based on result */
	                	if(this.smstate.smProgState == SM.PROG_SUCCEEDED){
		                	this.setSmpTrust(callback,true);
	                	}else{
	                		this.setSmpTrust(callback,false);
	                	}
	                	if(this.smstate.smProgState != SM.PROG_CHEATED){
	                		/* Send msg with next smp msg content */
	                		OTRTLV[] stlvs = new TLV[1];
	                		stlvs[0] = new TLV(TLV.SMP4, nextmsg);
	                		DataMessage dm = Proto.createData(this, new byte[0], 
	                				Proto.MSGFLAGS_IGNORE_UNREADABLE, stlvs);
	                		byte[] senddata = dm.getContent();
	                		this.fragmentAndSend(new String(senddata), Policy.FRAGMENT_SEND_ALL, callback);
	                		int succorfail = this.smstate.smProgState == SM.PROG_SUCCEEDED?
	                				OTRCallbacks.OTRL_SMPEVENT_SUCCESS:OTRCallbacks.OTRL_SMPEVENT_FAILURE;
	                		callback.handleSmpEvent(succorfail, this, 100, null);
	                		this.smstate.nextExpected = SM.EXPECT1;
	                	}else{
	                		callback.handleSmpEvent(OTRCallbacks.OTRL_SMPEVENT_CHEATED,
	    							this, 0, null);
	                		this.smstate.nextExpected = SM.EXPECT1;
	                		this.smstate.smProgState = SM.PROG_OK;
	                	}
	                	
	                }else if(tlv != null){
	                	callback.handleSmpEvent(OTRCallbacks.OTRL_SMPEVENT_ERROR,
	                			this, 0, null);
	                }
	                
	                tlv = new TLV().find(tlvs, TLV.SMP4);
	                if (tlv != null && nextMsg == SM.EXPECT4) {
        	
	                	SM.step5(this.smstate, tlv.getValue(), prov);
	                	if(this.smstate.smProgState == SM.PROG_SUCCEEDED){
		                	this.setSmpTrust(callback,true);
		                }else{
		                	this.setSmpTrust(callback,false);
	                	}
	                	if(this.smstate.smProgState != SM.PROG_CHEATED){
	                		int succorfail = this.smstate.smProgState == SM.PROG_SUCCEEDED?
	                				OTRCallbacks.OTRL_SMPEVENT_SUCCESS:OTRCallbacks.OTRL_SMPEVENT_FAILURE;
	                		callback.handleSmpEvent(succorfail, this, 100, null);
	                		this.smstate.nextExpected = SM.EXPECT1;
	                	}else{
	                		callback.handleSmpEvent(OTRCallbacks.OTRL_SMPEVENT_CHEATED,
	    							this, 0, null);
	                		this.smstate.nextExpected = SM.EXPECT1;
	                		this.smstate.smProgState = SM.PROG_OK;
	                	}
	                	
	                }else if(tlv != null){
	                	callback.handleSmpEvent(OTRCallbacks.OTRL_SMPEVENT_ERROR,
	                			this, 0, null);
	                }
	                
	                tlv = new TLV().find(tlvs, TLV.SMP_ABORT);
	                if(tlv!=null){
	                	this.smstate.nextExpected = SM.EXPECT1;
	                }
              
                }
                return stlv;
            }
            break;
        case OTRMessage.MSG_TAGGED_WHITESPACE:
            /* Start AKE */
            if (msgState.getCurState() == MsgState.ST_UNENCRYPTED) {
                auth.startAKE(null);
                if (auth.havemsgp != 0) {
                    this.lastMessage = new String(auth.lastauthmsg);
                    fragmentAndSend(lastMessage, Policy.FRAGMENT_SEND_ALL, callback);
                    StringTLV stlv = new StringTLV();
                    stlv.msg = ((TaggedPlaintextMessage) message).getStripped();
                    return stlv;
                }
            } else {
                StringTLV stlv = new StringTLV();
                stlv.msg = ((TaggedPlaintextMessage) message).getStripped();
                return stlv;
            }
            break;
        case OTRMessage.MSG_NOTOTR:
        	if(this.msgState.getCurState() != MsgState.ST_UNENCRYPTED ||
        			(policy & Policy.REQUIRE_ENCRYPTION) != 0){
        		/* Not fine.  Let the user know. */
        		callback.handleMsgEvent(OTRCallbacks.OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED,
        				this, message.toString());
        	}
        	ignore_message = 1;
        	break;
        default:
        	/* We received an OTR message we didn't recognize.  Ignore
    	     * it, but make a log entry. */
        	callback.handleMsgEvent(OTRCallbacks.OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED,
    				this, null);
            ignore_message=1;
            break;
        }
        return null;
    }

    /**
     * Return a pointer to a newly-allocated OTR query message, customized with
     * our name.
     */
    QueryMessage defaultQueryMessage(String ourname, int policy) {
        String msg = "?OTR"
                + "v2?"
                + "\n<b>"
                + ourname
                + "</b> has requested an "
                + "<a href=\"http://otr.cypherpunks.ca/\">Off-the-Record "
                + "private conversation</a>.  However, you do not have a plugin "
                + "to support that.\nSee <a href=\"http://otr.cypherpunks.ca/\">"
                + "http://otr.cypherpunks.ca/</a> for more information.";
        return new QueryMessage(msg);
    }
    
    /** Put a connection into the PLAINTEXT state, first sending the
     * other side a notice that we're doing so if we're currently ENCRYPTED,
     * and we think he's logged in. 
     * @throws OTRException */
    public void disconnect(OTRCallbacks callback) throws OTRException{
    	if(this.msgState.getCurState() == MsgState.ST_ENCRYPTED && this.their_keyid > 0 &&
    			callback.isLoggedIn(accountName, protocol, recName) == 1){
    		TLV[] tlvs = new TLV[1];
    		tlvs[0] = new TLV(TLV.DISCONNECTED, new byte[0]);
    		DataMessage dm = 
    			Proto.createData(this, new byte[0], Proto.MSGFLAGS_IGNORE_UNREADABLE, tlvs);
    		callback.injectMessage(accountName, protocol, recName, new String(dm.getContent()));
    	}
    	forceFinished();
    	this.msgState.curState = MsgState.ST_UNENCRYPTED;
    	callback.updateContextList();
    }
    
    void forceFinished(){
    	this.msgState.curState = MsgState.ST_FINISHED;
    	this.activeFingerprint = null;
    	this.sessionId = null;
    	this.fragment = null;
    	this.fragment_k=0;
    	this.fragment_n=0;
    	this.numSavedKeys=0;
    	this.savedMacKeys = new byte[0];
    	this.lastMessage = null;
    	this.mayRetransmit=0;
    	this.their_keyid=0;
    	this.their_old_y = null;
    	this.their_y = null;
    	this.our_keyid=0;
    	this.our_dh_key = null;
    	this.our_old_dh_key=null;
    	this.sesskeys = new DHSesskeys[2][2];
    }
}

class FingerPrint {

    byte[] fingerPrint; // The fingerprint
    ConnContext context; // The context to which we belong
    String trust; // The trust level of the fingerprint
}
