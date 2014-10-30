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

import ca.uwaterloo.crysp.otr.OTRException;
import ca.uwaterloo.crysp.otr.OutBuf;

/**
 * <p>This class encapsulates the various encoded messages that OTR handles.</p>
 * <p>Each message consists of the 5 bytes "?OTR:", followed by the base 64 encoding of the binary data,
 * ending with the byte ".".</p>
 * <p>The following are considered OTR Encoded Messages:</p>
 * <ul>
 * 	<li>Data Messages</li>
 * 	<li>D-H Commit Message</li>
 * 	<li>D-H Key Message</li>
 * 	<li>Reveal Signature Message</li>
 * 	<li>Signature Message</li>
 * </ul>
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public abstract class OTREncodedMessage extends OTRMessage
{
	/** instance variables */
    protected short protocolVersion;    // the protocol version
    
    /** Constructor
     * @param protocolVersion protocol version
     * @param messageType message type
     */
    public OTREncodedMessage(short protocolVersion, byte messageType)
    {
    	super(messageType);
        this.protocolVersion = protocolVersion;
    }

    /** Get the protocol version
     * @return short representing protocol version
     */
    public short getProtocolVersion()
    {
        return this.protocolVersion;
    }

    /** Set the protocol version
     * @param protocolVersion the protocol version
     */
    public void setProtocolVersion(short protocolVersion)
    {
        this.protocolVersion = protocolVersion;
    }
    
    /** Write to output buffer stream
     * @param stream output buffer stream
	 * @throws OTRException
     */
    public void write(OutBuf stream) throws OTRException
    {
        stream.writeShort(this.protocolVersion);
        stream.writeByte(this.messageType);
    }
}
