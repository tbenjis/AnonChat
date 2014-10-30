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
 * OTR Query message. Used when Alice wishes to communicate to Bob that she
 * would like to use OTR. Only OTR version 2 is supported.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public class QueryMessage extends OTRMessage {
	private String contents;

	/**
	 * Constructs an OTR query message with the given input, indicating which versions Alice is willing to use.
	 * @param input The entire OTR query message.
	 */
	public QueryMessage(String input) {
		super(MSG_QUERY);
		this.contents = input;
	}
	
	/**
	 * Returns the contents of the OTR Query message.
	 * @return the contents of the OTR Query message.
	 */
	public byte[] getContent() throws OTRException {

		return contents.getBytes();
	}

	public void write(OutBuf stream) throws OTRException {
		stream.writeBytes(contents.getBytes());
	}


}
