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

package ca.uwaterloo.crysp.otr.crypt;

/**
 * Abstract MAC class that provides the generic calls to tag() and
 * verify() when the optional parameters are not specified.
 * 
 * @author Can Tang (c24tang@gmail.com)
 */
public abstract class AbstractMAC implements MAC {
	// Key used by the MAC algorithm
	protected Key key;

	public Key getKey() {
		return key;
	}

	public void setKey(Key k) throws OTRCryptException {
		this.key = k;
	}

	public byte[] tag(byte[] data) throws OTRCryptException {
		// Ensure that Key is set before attempting to tag
		if (key == null) {
			throw new OTRCryptException(
					"Key has not been set yet.");
		}
		return tag(data, 0, data.length);
	}

	public boolean verify(byte[] tag, byte[] data)
			throws OTRCryptException {
		// Ensure that Key is set before attempting to verify
		if (key == null) {
			throw new OTRCryptException(
					"Key has not been set yet.");
		}
		return verify(tag, data, 0, data.length);
	}
}
