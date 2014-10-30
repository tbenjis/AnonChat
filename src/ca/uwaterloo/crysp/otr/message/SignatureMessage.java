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
import ca.uwaterloo.crysp.otr.MAC;
import ca.uwaterloo.crysp.otr.OTRException;
import ca.uwaterloo.crysp.otr.OutBuf;

public class SignatureMessage extends OTREncodedMessage
{
	private Data encryptedSignature;	// the encrypted signature
	private byte[] macSignature;		// Message Authentication Coded signature

	/** Constructor
	 * @param protocolVersion the protocol version
	 * @param encryptedSignature the encrypted signature
	 * @param macSig the MAC'd signature
	 */
	public SignatureMessage(short protocolVersion, Data encryptedSignature, byte[] macSig)
	{
		super(protocolVersion, OTRMessage.MSG_SIGNATURE);
		this.encryptedSignature = encryptedSignature;
		this.macSignature = macSig;
	}

	/** Get the encrypted signature message
	 * @return the encrypted signature message
	 */
	public Data getEncryptedSignature()
	{
		return this.encryptedSignature;
	}

	/** Get the MAC signature
	 * @return the MAC signature
	 */
	public byte[] getMacSignature()
	{
		return this.macSignature;
	}

	/** Read and return a SignatureMessage object
	 * @param stream input buffer stream to read from
	 * @param protocolVersion the protocol version
	 * @return SignatureMessage object
	 * @throws OTRException
	 */
	public static SignatureMessage readSignatureMessage(InBuf stream, short protocolVersion) throws OTRException
	{
		Data encryptedSignature = stream.readData();
		byte[] macSignature = MAC.readMAC(stream);
		return new SignatureMessage(protocolVersion, encryptedSignature, macSignature);
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
		stream.writeData(this.encryptedSignature);
		stream.writeBytes(this.macSignature);
	}

	public byte[] getContent() throws OTRException {
		OutBuf st = new OutBuf(new byte[1024]);
		write(st);
		return st.getBytes();
	}
}
