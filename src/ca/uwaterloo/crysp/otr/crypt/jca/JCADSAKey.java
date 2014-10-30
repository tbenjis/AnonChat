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

package ca.uwaterloo.crysp.otr.crypt.jca;

import java.math.BigInteger;

/**
 * Abstract class for a DSA signing (private) or verification (public) key using the JCA providers.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public abstract class JCADSAKey extends ca.uwaterloo.crysp.otr.crypt.DSAKey {
	/**
	 * Returns the DSA parameters associated with the DSA key.
	 * 
	 * @return the DSA parameters associated with the DSA key.
	 */
	public abstract java.security.interfaces.DSAParams getDSAParams();
	
	/**
	 * Returns the value of the DSA key.
	 * 
	 * @return the value of the DSA key.
	 */
	public abstract String getValue();

	/* (non-Javadoc)
	 * @see ca.uwaterloo.crysp.otr.crypt.DSAKey#getG()
	 */
	public byte[] getG() {
		BigInteger result = getDSAParams().getG();
		return JCAMPI.toBytes(result);
	}

	/* (non-Javadoc)
	 * @see ca.uwaterloo.crysp.otr.crypt.DSAKey#getP()
	 */
	public byte[] getP() {
		BigInteger result = getDSAParams().getP();
		return JCAMPI.toBytes(result);
	}

	/* (non-Javadoc)
	 * @see ca.uwaterloo.crysp.otr.crypt.DSAKey#getQ()
	 */
	public byte[] getQ() {
		BigInteger result = getDSAParams().getQ();
		return JCAMPI.toBytes(result);
	}
	
	public String toString() {
	    return getValue();
	}
}
