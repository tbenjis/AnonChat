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

public class CTR
{
    public static final int CTR_SIZE = 8;	// size of CTR

	/** Read CTR value from InBuf and return byte array representation of CTR
	 * @param stream InBuf to read from
	 * @return byte array representing CTR
	 * @throws OTRException
	 */
	public static byte[] readCTR(InBuf stream) throws OTRException
	{
		byte[] ctr = new byte[CTR_SIZE];
		stream.readBytes(ctr, 0, CTR_SIZE);
		return ctr;
	}
}
