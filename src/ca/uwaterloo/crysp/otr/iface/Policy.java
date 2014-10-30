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

package ca.uwaterloo.crysp.otr.iface;

/**
 * OTR policies are used to define per-correspondent behaviors for each contact Alice wishes to communicate with.
 * The policies are any combination of the flags defined by this class.
 * 
 * @author Can Tang (c24tang@gmail.com)
 */
public class Policy {
	/* Allow version 2 of the OTR protocol to be used. */
	public static final byte ALLOW_V1 				= 1 ;
	
	/* Allow version 2 of the OTR protocol to be used. */
	public static final byte ALLOW_V2 				= 1 << 1;
	
	/* Refuse to send encrypted messages. */
	public static final byte REQUIRE_ENCRYPTION 	= 1 << 2;
	
	/* Advertise your support of OTR using the whitespace tag. */
	public static final byte SEND_WHITESPACE_TAG 	= 1 << 3;
	
	/* Start the OTR AKE when you receive a whitespace tag. */
	public static final byte WHITESPACE_START_AKE 	= 1 << 4;
	
	/* Start the OTR AKE when you receive an OTR Error Message. */
	public static final byte ERROR_START_AKE 		= 1 << 5;
	
	// Predefined combinations of flags
	public static final byte NEVER = 0;
	
	public static final byte MANUAL = ALLOW_V1 | ALLOW_V2;
	
	public static final byte OPPORTUNISTIC = ALLOW_V1 | ALLOW_V2 | SEND_WHITESPACE_TAG 
		| WHITESPACE_START_AKE | ERROR_START_AKE;

	public static final byte DEFAULT = OPPORTUNISTIC;
	
	public static final byte ALWAYS = ALLOW_V1 | ALLOW_V2 | REQUIRE_ENCRYPTION 
		| WHITESPACE_START_AKE | ERROR_START_AKE;
	
	
	public static final byte VERSION_MASK =ALLOW_V1 | ALLOW_V2;
	
	public static final int FRAGMENT_SEND_ALL = 0;
	public static final int FRAGMENT_SEND_ALL_BUT_FIRST = 1;
	public static final int FRAGMENT_SEND_ALL_BUT_LAST = 2;
	public static final int FRAGMENT_SEND_SKIP = 3;
}
