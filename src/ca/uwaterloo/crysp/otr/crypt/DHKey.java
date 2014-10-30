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
 * Abstract class for a Diffie-Hellman Key. Each key stores its value as well as the 
 * Diffie Hellman parameters: p and g.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public abstract class DHKey implements Key {
	public final String getAlgorithm() {
		return "DH";
	}
	
	/**
	 * Returns the prime modulus. The result is in MPI format.
	 * @return the prime modulus.
	 */
	public abstract byte[] getP();
	
	/**
	 * Returns the generator of the multiplicative group modulo p. The result is in MPI format.
	 * @return the generator of the multiplicative group modulo p.
	 */
	public abstract byte[] getG();
}
