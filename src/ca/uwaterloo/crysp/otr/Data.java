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

public class Data
{
	private byte[] value;	// the value of data

	/** Constructor
	 * @param value the value of data
	 */
	public Data(byte[] value)
	{
		this.value = value;
	}

	/** Get the length of data
	 * @return the lengh of data
	 */
	public int getLength()
	{
		return this.value.length;
	}

	/** Get the value of data
	 * @return byte array value of data
	 */
	public byte[] getValue()
	{
		return this.value;
	}

	/** Check if this Data value equals another
	 * @param other the other Data object
	 * @return true if the byte sequence value in this Data equates the other Data
	 */
	public boolean equals(Data other)
	{
		return Util.arrayEquals(this.value, other.value);
	}
}
