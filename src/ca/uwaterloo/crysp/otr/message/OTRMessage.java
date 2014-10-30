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

package ca.uwaterloo.crysp.otr.message;

import ca.uwaterloo.crysp.otr.InBuf;
import ca.uwaterloo.crysp.otr.OTRException;
import ca.uwaterloo.crysp.otr.OutBuf;

public abstract class OTRMessage
{
	protected byte messageType;     // the message type
	
	public static final String MSG_TAG_BASE = " \t  \t\t\t\t \t \t \t  ";	// Identifies tagged plaintext messages
	public static final String MSG_TAG_V2 = "  \t\t  \t ";
	public static final String MSG_ENCODED_PREFIX	  = "?OTR:";	   // Prefix of all encoded OTR messages
	public static final String MSG_QUERY_PREFIX       = "?OTRv";	   // Prefix of OTR query messages
	public static final String MSG_ERROR_PREFIX       = "?OTR Error:"; // Prefix of OTR error messages
	public static final String MSG_FRAGMENT_PREFIX	  = "?OTR,";	   // Prefix of OTR fragment messages
	
	/** constant message types */
	public static final byte MSG_TAGGED_WHITESPACE  = (byte)0x01;   // Tagged whitespace message
	public static final byte MSG_QUERY              = (byte)0x07;   // Query message
	public static final byte MSG_DH_COMMIT          = (byte)0x02;   // D-H Commit message
	public static final byte MSG_DH_KEY             = (byte)0x0a;   // D-H Key message
	public static final byte MSG_REVEAL_SIGNATURE   = (byte)0x11;   // Reveal signature message
	public static final byte MSG_SIGNATURE          = (byte)0x12;   // Signature message
	public static final byte MSG_DATA               = (byte)0x03;   // Data message
	public static final byte MSG_ERROR              = (byte)0x0e;   // Error message
	public static final byte MSG_PLAINTEXT				= (byte)0x13;	 // Plaintext message
	public static final byte MSG_NOTOTR					= (byte)0x14;	 // Not OTR message
	public static final byte MSG_FRAGMENT 				= (byte)0x15;	 // Fragment message

    
    public OTRMessage(byte messageType) {
    	this.messageType = messageType;
    }
    
    /**
     * Write the contents of the OTR message to the output buffer.
     * @param stream The output buffer to write to.
     * @throws OTRException
     */
    public abstract void write(OutBuf stream) throws OTRException;
    
    public abstract byte[] getContent() throws OTRException;

    /** Factory method: parses bytes from input stream and returns an appropriate OTRMessage subclass
     * @param stream input buffer stream
     * @return an appropriate OTRMessage object
	 * @throws OTRException
     */
    public static OTRMessage parse(String input) throws OTRException
    {
        OTRMessage otrMsg = null;
        
        // If input doesn't start with "?OTR", see if its a tagged plaintext message
        if (!input.startsWith("?OTR")) {
        	// tagged message prefix was found
        	if (input.indexOf(MSG_TAG_BASE) > -1) {
        		// Tagged plaintext message
        		return new TaggedPlaintextMessage(input);
        	}
        	else {
        		// Not an OTR message
        		return new PlaintextMessage(input);
        	}
        }
        
        if (input.startsWith(MSG_QUERY_PREFIX)) {
        	return new QueryMessage(input);
        }
        
        // If input starts with "OTR?:", decode the base64 contents
        if (input.startsWith(MSG_ENCODED_PREFIX)) {
        	// Decode input to byte array
        	InBuf stream = new InBuf(input);
        	short protocolVersion = (short)stream.readShort();
        	byte messageType = stream.readByte();

	        switch(messageType) {
	            case MSG_DH_COMMIT:
	                otrMsg = DHCommitMessage.readDHCommitMessage(stream, protocolVersion);
	                break;
	            case MSG_DH_KEY:
	                otrMsg = DHKeyMessage.readDHKeyMessage(stream, protocolVersion);
	                break;
	            case MSG_REVEAL_SIGNATURE:
	                otrMsg = RevealSignatureMessage.readRevealSignatureMessage(stream, protocolVersion);
	                break;
	            case MSG_SIGNATURE:
	                otrMsg = SignatureMessage.readSignatureMessage(stream, protocolVersion);
	                break;
	            case MSG_DATA:
	                otrMsg = DataMessage.readDataMessage(stream, protocolVersion);
	                break;
	            default:
	                throw new OTRException("Unknown message type in OTR message");
	        }
        }
        
        if (input.startsWith(MSG_ERROR_PREFIX)) {
        	// Retrieve the error message after the prefix
        	String errorString = input.substring(MSG_ERROR_PREFIX.length());
        	return new ErrorMessage(errorString);
        }
        if (input.startsWith(MSG_FRAGMENT_PREFIX)){
        	return new FragmentMessage(input);
        }

        return otrMsg;
    }
    
    /** Get the type of message
     *  @return byte representing message type
     */     
    public byte getType()
    {
        return this.messageType;
    }
}
