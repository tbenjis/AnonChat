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
import ca.uwaterloo.crysp.otr.crypt.MPI;

public class DHKeyMessage extends OTREncodedMessage
{
	private MPI Gy;	// the encrypted g^y

	/** Constructor
	 * @param protocolVersion the protocol version
	 * @param Gy the g^y MPI 
	 */
	public DHKeyMessage(short protocolVersion, MPI Gy)
	{
		super(protocolVersion, OTRMessage.MSG_DH_KEY);
		this.Gy = Gy;
	}

	/** Get encrypted Gy
	 * @return Gy
	 */
	public MPI getGy()
	{
		return this.Gy;
	}

	/** Read and return a DHKeyMessage object
	 * @param stream input buffer stream to read from
	 * @param protocolVersion the protocol version
	 * @return DHKeyMessage object
	 * @throws OTRException
	 */
	public static DHKeyMessage readDHKeyMessage(InBuf stream, short protocolVersion) throws OTRException
	{
		MPI Gy = MPI.readMPI(stream);
		return new DHKeyMessage(protocolVersion, Gy);
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
		this.Gy.write(stream);
	}

	public byte[] getContent() throws OTRException {
		OutBuf st = new OutBuf(new byte[1024]);
		write(st);
		return st.getBytes();
	}
}
