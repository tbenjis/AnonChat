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

import ca.uwaterloo.crysp.otr.CTR;
import ca.uwaterloo.crysp.otr.Data;
import ca.uwaterloo.crysp.otr.InBuf;
import ca.uwaterloo.crysp.otr.MAC;
import ca.uwaterloo.crysp.otr.OTRException;
import ca.uwaterloo.crysp.otr.OutBuf;
import ca.uwaterloo.crysp.otr.crypt.MPI;

public class DataMessage extends OTREncodedMessage
{
	private byte flags;					// the message flags
	private long senderKeyId;			// the sender keyid
	private long recipientKeyId;		// the recipient keyid
	private MPI DHy;					// the next public key for the sender
	private byte[] ctrInit;				// top half of counter init
	private Data encryptedMessage;		// the encrypted message
	private byte[] macAuthenticator;	// the authenticator
	private Data oldMacKeys;			// old MAC keys to be revealed

	/** Constructor
	 * @param protocolVersion the protocol version
	 * @param flags the message flags
	 * @param senderKeyId the sender keyid
	 * @param recipientKeyId the recipient keyid
	 * @param DHy the next public key for the sender
	 * @param ctrInit top half of the counter init
	 * @param encryptedMessage the encrypted message
	 * @param macAuthenticator the authenticator
	 * @param oldMacKeys old MAC keys to be revealed
	 */
	public DataMessage(short protocolVersion, byte flags, long senderKeyId, long recipientKeyId,
		MPI DHy, byte[] ctrInit, Data encryptedMessage, byte[] macAuthenticator, Data oldMacKeys)
	{
		super(protocolVersion, OTRMessage.MSG_DATA);
		this.flags = flags;
		this.senderKeyId = senderKeyId;
		this.recipientKeyId = recipientKeyId;
		this.DHy = DHy;
		this.ctrInit = ctrInit;
		this.encryptedMessage = encryptedMessage;
		this.macAuthenticator = macAuthenticator;
		this.oldMacKeys = oldMacKeys;
	}

	/** Get old MAC keys to be revealed
	 * @return old MAC keys to be revealed
	 */
	public Data getOldKeys()
	{
		return this.oldMacKeys;
	}

	/** Get authenticator
	 * @return authenticator
	 */
	public byte[] getAuthenticator()
	{
		return this.macAuthenticator;
	}

	/** Get encrypted message
	 * @return encrypted message
	 */
	public Data getEncryptedMessage()
	{
		return this.encryptedMessage;
	}

	/** Get half of counter init
	 * @return half of counter init
	 */
	public byte[] getCounterInit()
	{
		return this.ctrInit;
	}

	/** Get next public key for sender 
	 * @return next public key for sender 
	 */
	public MPI getNextSenderKey()
	{
		return this.DHy;
	}

	/** Get recipient key id
	 * @return recipient key id
	 */
	public long getRecipientKeyId()
	{
		return this.recipientKeyId;
	}

	/** Get sender key id
	 * @return sender key id
	 */
	public long getSenderKeyId()
	{
		return this.senderKeyId;
	}

	/** Get message flags
	 * @return message flags
	 */
	public byte getFlags()
	{
		return this.flags;
	}

	/** Read and return a DataMessage object
	 * @param stream input buffer stream to read from
	 * @param protocolVersion the protocol version
	 * @return DataMessage object
	 * @throws OTRException
	 */
	public static DataMessage readDataMessage(InBuf stream, short protocolVersion) throws OTRException
	{
		byte flags = stream.readByte();
		long senderKeyId = stream.readUInt();
		long recipientKeyId = stream.readUInt();
		MPI DHy = MPI.readMPI(stream);
		byte[] ctrInit = CTR.readCTR(stream); 
		Data encryptedMessage = stream.readData();
		byte[] macAuthenticator = MAC.readMAC(stream);
		Data oldMacKeys = stream.readData();
		return new DataMessage(protocolVersion, flags, senderKeyId, recipientKeyId, DHy, 
			ctrInit, encryptedMessage, macAuthenticator, oldMacKeys);
	}

	/** Serialize object and write to output buffer stream
	 * @param stream output buffer stream
	 * @throws OTRException
	 */
	public void write(OutBuf stream) throws OTRException
	{
		// Write protocol version and message type
		super.write(stream);

		// Write message specific content
		stream.writeByte(this.flags);
		stream.writeUInt(this.senderKeyId);
		stream.writeUInt(this.recipientKeyId);
		this.DHy.write(stream);
		stream.writeBytes(this.ctrInit);
		stream.writeData(this.encryptedMessage);
		stream.writeBytes(this.macAuthenticator);
		stream.writeData(this.oldMacKeys);
	}
	
	public int getSize(){
		int maclen=0;
		if(oldMacKeys!=null){
			//maclen=oldMacKeys.getLength();
		}
		
		return (1+2+1+4+4+DHy.getLength()+1+encryptedMessage.getLength()+macAuthenticator.length
				+maclen);
	}

	public byte[] getContent() throws OTRException {
		OutBuf st = new OutBuf(new byte[1024+getSize()]);
		write(st);
		char[] ret = st.encodeBase64();
		byte[] buf = new byte[ret.length];
		for(int i=0; i<ret.length; i++){
			buf[i] = (byte)ret[i];
		}
		return buf;
	}

}
