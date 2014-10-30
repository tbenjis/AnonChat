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

/** Encapsulates OTR Exception message
 */
public class OTRException extends Exception
{
	/** Constructor
	 */
	public OTRException()
	{
		super("");
	}

	/**
	 * Constructs an OTRException with the given throwable instance.
	 * 
	 * @param t the cause of the exception.
	 */
	public OTRException(Throwable t) {
		super(t.getMessage());
	}
	
	/** Constructor
	 * @param s exception reason
	 */
	public OTRException(String s)
	{
		super(s);
	}


}
