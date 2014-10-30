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


package ca.uwaterloo.crysp.otr.iface;

/**
 * Methods that OTR requires that are supplied by the IM client. Example: OTR
 * policies.
 * 
 * @author Can Tang (c24tang@uwaterloo.ca)
 */
public interface OTRCallbacks {

	public static final int OTRL_ERRCODE_NONE = 0;
	public static final int OTRL_ERRCODE_ENCRYPTION_ERROR = 1;
	public static final int OTRL_ERRCODE_MSG_NOT_IN_PRIVATE = 2;
	public static final int OTRL_ERRCODE_MSG_UNREADABLE = 3;
	public static final int OTRL_ERRCODE_MSG_MALFORMED = 4;
	
	
	/* These define the events used to indicate status of SMP to the UI */
	public static final int OTRL_SMPEVENT_NONE= 0;
	public static final int OTRL_SMPEVENT_ERROR= 1;
	public static final int OTRL_SMPEVENT_ABORT= 2;
	public static final int OTRL_SMPEVENT_CHEATED= 3;
	public static final int OTRL_SMPEVENT_ASK_FOR_ANSWER= 4;
	public static final int OTRL_SMPEVENT_ASK_FOR_SECRET= 5;
	public static final int OTRL_SMPEVENT_IN_PROGRESS= 6;
	public static final int OTRL_SMPEVENT_SUCCESS= 7;
	public static final int OTRL_SMPEVENT_FAILURE= 8;


	/* These define the events used to indicate the messages that need
	 * to be sent */
	
	public static final int OTRL_MSGEVENT_NONE= 0;
	public static final int OTRL_MSGEVENT_ENCRYPTION_REQUIRED= 1;
	public static final int OTRL_MSGEVENT_ENCRYPTION_ERROR= 2;
	public static final int OTRL_MSGEVENT_CONNECTION_ENDED= 3;
	public static final int OTRL_MSGEVENT_SETUP_ERROR= 4;
	public static final int OTRL_MSGEVENT_MSG_REFLECTED= 5;
	public static final int OTRL_MSGEVENT_MSG_RESENT= 6;
	public static final int OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE= 7;
	public static final int OTRL_MSGEVENT_RCVDMSG_UNREADABLE= 8;
	public static final int OTRL_MSGEVENT_RCVDMSG_MALFORMED= 9;
	public static final int OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD= 10;
	public static final int OTRL_MSGEVENT_LOG_HEARTBEAT_SENT= 11;
	public static final int OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR= 12;
	public static final int OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED= 13;
	public static final int OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED= 14;
	
	public static final int OTRL_NOTIFY_ERROR = 0;
	public static final int OTRL_NOTIFY_WARNING = 1;
	public static final int OTRL_NOTIFY_INFO = 2;



	/**
	 * Returns the OTR policy for the given context.
	 * 
	 */
	public int getOtrPolicy(OTRContext conn);
    
    /** Report whether you think the given user is online.  Return 1 if
     * you think he is, 0 if you think he isn't, -1 if you're not sure.
     *
     * If you return 1, messages such as heartbeats or other
     * notifications may be sent to the user, which could result in "not
     * logged in" errors if you're wrong. */
    int isLoggedIn(String accountname,
	    String protocol, String recipient);
    
    /** Send the given IM to the given recipient from the given
     * accountname/protocol. */
	public void injectMessage(String accName, String prot, String rec,
			String msg);
	
    /** When the list of ConnContexts changes (including a change in
     * state), this is called so the UI can be updated. */
    void updateContextList();
    
    /** A new fingerprint for the given user has been received. */
    void newFingerprint(OTRInterface us,
	    String accountname, String protocol,
	    String username, byte[] fingerprint);

    /** The list of known fingerprints has changed.  Write them to disk. */
    void writeFingerprints();

    /** A ConnContext has entered a secure state. */
    void goneSecure(OTRContext context);


    /** We have completed an authentication, using the D-H keys we
     * already knew.  is_reply indicates whether we initiated the AKE. */
    void stillSecure(OTRContext context, int is_reply);

    /** Find the maximum message size supported by this protocol. */
    int maxMessageSize(OTRContext context);
    

    /** Return a string according to the error event. This string will then
     * be concatenated to an OTR header to produce an OTR protocol error
     * message. The following are the possible error events:
     * - OTRL_ERRCODE_ENCRYPTION_ERROR
     * 		occured while encrypting a message
     * - OTRL_ERRCODE_MSG_NOT_IN_PRIVATE
     * 		sent encrypted message to somebody who is not in
     * 		a mutual OTR session
     * - OTRL_ERRCODE_MSG_UNREADABLE
     *		sent an unreadable encrypted message
     * - OTRL_ERRCODE_MSG_MALFORMED
     * 		message sent is malformed */
    String errorMessage(OTRContext context,
        int err_code);
    
    /** Update the authentication UI with respect to SMP events
     * These are the possible events:
     * - OTRL_SMPEVENT_ASK_FOR_SECRET
     *      prompt the user to enter a shared secret. The sender application
     *      should call otrl_message_initiate_smp, passing NULL as the question.
     *      When the receiver application resumes the SM protocol by calling
     *      otrl_message_respond_smp with the secret answer.
     * - OTRL_SMPEVENT_ASK_FOR_ANSWER
     *      (same as OTRL_SMPEVENT_ASK_FOR_SECRET but sender calls
     *      otrl_message_initiate_smp_q instead)
     * - OTRL_SMPEVENT_CHEATED
     *      abort the current auth and update the auth progress dialog
     *      with progress_percent. otrl_message_abort_smp should be called to
     *      stop the SM protocol.
     * - OTRL_SMPEVENT_INPROGRESS 	and
     *   OTRL_SMPEVENT_SUCCESS 		and
     *   OTRL_SMPEVENT_FAILURE    	and
     *   OTRL_SMPEVENT_ABORT
     *      update the auth progress dialog with progress_percent
     * - OTRL_SMPEVENT_ERROR
     *      (same as OTRL_SMPEVENT_CHEATED)
     * */
    void handleSmpEvent(int smp_event,
	    OTRContext context, int progress_percent,
	    String question);
    
    /** Handle and send the appropriate message(s) to the sender/recipient
     * depending on the message events. All the events only require an opdata,
     * the event, and the context. The message and err will be NULL except for
     * some events (see below). The possible events are:
     * - OTRL_MSGEVENT_ENCRYPTION_REQUIRED
     *      Our policy requires encryption but we are trying to send
     *      an unencrypted message out.
     * - OTRL_MSGEVENT_ENCRYPTION_ERROR
     *      An error occured while encrypting a message and the message
     *      was not sent.
     * - OTRL_MSGEVENT_CONNECTION_ENDED
     *      Message has not been sent because our buddy has ended the
     *      private conversation. We should either close the connection,
     *      or refresh it.
     * - OTRL_MSGEVENT_SETUP_ERROR
     *      A private conversation could not be set up. A gcry_error_t
     *      will be passed.
     * - OTRL_MSGEVENT_MSG_REFLECTED
     *      Received our own OTR messages.
     * - OTRL_MSGEVENT_MSG_RESENT
     *      The previous message was resent.
     * - OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE
     *      Received an encrypted message but cannot read
     *      it because no private connection is established yet.
     * - OTRL_MSGEVENT_RCVDMSG_UNREADABLE
     *      Cannot read the received message.
     * - OTRL_MSGEVENT_RCVDMSG_MALFORMED
     *      The message received contains malformed data.
     * - OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD
     *      Received a heartbeat.
     * - OTRL_MSGEVENT_LOG_HEARTBEAT_SENT
     *      Sent a heartbeat.
     * - OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR
     *      Received a general OTR error. The argument 'message' will
     *      also be passed and it will contain the OTR error message.
     * - OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED
     *      Received an unencrypted message. The argument 'smessage' will
     *      also be passed and it will contain the plaintext message.
     * - OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED
     *      Cannot recognize the type of OTR message received.
     * */
    void handleMsgEvent(int msg_event,
                OTRContext context, String message);

}
