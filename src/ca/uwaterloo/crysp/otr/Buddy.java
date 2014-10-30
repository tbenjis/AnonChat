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
 * A Buddy represents a remote user (local {@link Account} and remote
 * username).
 *
 * @author Ian Goldberg <iang@cs.uwaterloo.ca>
 */
public class Buddy {
    /** The account. */
    private Account account;
    /** The remote username. */
    private String username;

    /** Create a Buddy given the Account and remote username. */
    public Buddy(Account account, String username) {
	this.account = account;
	this.username = username;
    }

    /** Create a Buddy given the local accountname, protocol, and remote
     * username. */
    public Buddy(String accountname, String protocol, String username) {
	this.account = new Account(accountname, protocol);
	this.username = username;
    }

    /** Get the account name. */
    public String getAccountName() { return account.getAccountName(); }

    /** Get the protocol. */
    public String getProtocol() { return account.getProtocol(); }

    /** Get the Account. */
    public Account getAccount() { return account; }

    /** Get the username. */
    public String getUsername() { return username; }

    /** Compare two Buddies. */
    public boolean equals(Object obj) {
	if (this == obj) return true;
	if (!(obj instanceof Buddy)) return false;
	Buddy that = (Buddy)obj;
	return account.equals(that.account) &&
	    username.equals(that.username);
    }

    /** Hash a Buddy. */
    public int hashCode() {
	return (account == null ? 0 : account.hashCode()) * 3 +
	    (username == null ? 0 : username.hashCode());
    }

    /** Unit tests */
    /*public static void main(String[] args) {
	Account a1 = new Account("me1", "XMPP");
	Account a2 = new Account("me1", "XMPP");
	Buddy b1 = new Buddy(a1, "you1");
	Buddy b2 = new Buddy("me1", "XMPP", "you1");
	Buddy b3 = new Buddy(a1, "you2");
	Buddy b4 = new Buddy(a2, "you2");
	System.out.println(a1.equals(a2));
	System.out.println(a1.hashCode() == a2.hashCode());
	System.out.println(! a1.equals(b1));
	System.out.println(b1.equals(b2));
	System.out.println(b1.hashCode() == b2.hashCode());
	System.out.println(! b1.equals(b3));
	System.out.println(b4.equals(b3));
	System.out.println(b4.hashCode() == b3.hashCode());
    }*/
}
