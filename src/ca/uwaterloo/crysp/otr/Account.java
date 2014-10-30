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

/**
 * An Account represents a user's local account (account name and protocol).
 * 
 * @author Ian Goldberg <iang@cs.uwaterloo.ca>
 */
public class Account {
	/** The account name. */
	private String accountname;
	/** The protocol. */
	private String protocol;

	/** Create an Account given the account name and protocol. */
	public Account(String accountname, String protocol) {
		this.accountname = accountname;
		this.protocol = protocol;
	}

	/** Get the account name. */
	public String getAccountName() {
		return accountname;
	}

	/** Get the protocol. */
	public String getProtocol() {
		return protocol;
	}

	/** Compare two Accounts. */
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!(obj instanceof Account))
			return false;
		Account that = (Account) obj;
		return accountname.equals(that.accountname)
				&& protocol.equals(that.protocol);
	}

	/** Hash an Account. */
	public int hashCode() {
		return (accountname == null ? 0 : accountname.hashCode())
				+ (protocol == null ? 0 : protocol.hashCode());
	}
}
