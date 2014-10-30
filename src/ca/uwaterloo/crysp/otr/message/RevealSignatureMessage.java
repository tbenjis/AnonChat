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

import ca.uwaterloo.crysp.otr.Data;
import ca.uwaterloo.crysp.otr.InBuf;
import ca.uwaterloo.crysp.otr.OTRException;
import ca.uwaterloo.crysp.otr.OutBuf;

public class RevealSignatureMessage extends OTREncodedMessage
{
	private Data revealedKey;			// the revealed key
	private Data encryptedSignature;	// the encrypted signature
	private Data sigMAC;					// the MACed encrypted signature

	/** Constructor
	 * @param protocolVersion the protocol version
	 * @param revealedKey the revealed key
	 * @param encryptedSignature the encrypted signature
	 */
	public RevealSignatureMessage(short protocolVersion, Data revealedKey, Data encryptedSignature, Data sigmac)
	{
		super(protocolVersion, OTRMessage.MSG_REVEAL_SIGNATURE);
		this.revealedKey = revealedKey;
		this.encryptedSignature = encryptedSignature;
		this.sigMAC = sigmac;
	}

	/** Get the revealed key
	 * @return revealed key Data
	 */
	public Data getRevealedKey()
	{
		return this.revealedKey;
	}

	/** Get encrypted signature
	 * @return encrypted signature Data
	 */
	public Data getEncryptedSignature()
	{
		return this.encryptedSignature;
	}
	
	/** Get MAC of encrypted signature
	 * @return MAC of encrypted signature Data
	 */
	public Data getSigMac()
	{
		return this.sigMAC;
	}

	/** Read and return a RevealSignatureMessage object
	 * @param stream input buffer stream to read from
	 * @param protocolVersion the protocol version
	 * @return RevealSignatureMessage object
	 * @throws OTRException
	 */
	public static RevealSignatureMessage readRevealSignatureMessage(InBuf stream, short protocolVersion) throws OTRException
	{
		Data revealedKey = stream.readData();
		Data encryptedSignature = stream.readData();
		Data sigmac = new Data(stream.readBytes(20));
		return new RevealSignatureMessage(protocolVersion, revealedKey, encryptedSignature, sigmac);
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
		stream.writeData(this.revealedKey);
		stream.writeData(this.encryptedSignature);
		stream.writeBytes(this.sigMAC.getValue());
	}

	public byte[] getContent() throws OTRException {
		OutBuf st = new OutBuf(new byte[1024]);
		write(st);
		return st.getBytes();
	}
}
