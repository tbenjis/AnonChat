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

import java.util.Hashtable;

import ca.uwaterloo.crysp.otr.crypt.Provider;
import ca.uwaterloo.crysp.otr.iface.*;

/**
 * A UserState encapsulates the list of known fingerprints and the list
 * of known private keys.  Most clients will only need one of these.  If
 * you have separate files for these things for (say) different users,
 * use different UserStates.  If you've got only one user, with multiple
 * accounts all stored together in the same fingerprint store and
 * privkey store files, use just one UserState.
 *
 * @author Ian Goldberg <iang@cs.uwaterloo.ca>
 */

public class UserState implements ca.uwaterloo.crysp.otr.iface.OTRInterface{
    /** The crypto provider. */
    protected Provider crypt;

    /** The set of ConnContexts. Maps Account objects to ConnContext objects. */
    protected Hashtable contexts = new Hashtable();
    /** The set of PrivKeys. */
    protected Hashtable privkeys = new Hashtable();

    /** Create a UserState, using the supplied crypto provider. */
    public UserState(Provider cryptoprovider) {
    	crypt = cryptoprovider;
    }

    /** Look up a privkey, optionally creating one if necessary. 
     * @throws OTRException */
    public PrivKey getPrivKey(Account acc, boolean create) throws OTRException {
        Object v = privkeys.get(acc);
        if (v == null && create == false) {
            return null;
        } else if (v != null) {
            return (PrivKey)v;
        }

        // We need to create a new PrivKey and return it
        PrivKey n = new PrivKey(acc, crypt);
        privkeys.put(acc, n);
        return n;
    }
    
    /** Look up a ConnContext, create one if not exist */
    ConnContext getConnContext(String username, String protocol, String recipient){
        Account acc = new Account(username, protocol);
        Buddy bd = new Buddy(acc, recipient);
        ConnContext conn = (ConnContext)contexts.get(bd);
        if(conn == null){
            ConnContext newConn = new ConnContext(username, recipient, protocol, crypt, this);
            contexts.put(bd, newConn);
            conn = newConn;
        }
        return conn;
    }
    
    /** Look up a ConnContext, create one if not exist */
    public OTRContext getContext(String username, String protocol, String recipient){
        return getConnContext(username, protocol, recipient);
    }
    
    /** Remove a ConnContext from the list */
    public void removeConnContext(String accountName, String protocol, String recipient){
        Account acc = new Account(accountName, protocol);
        Buddy bd = new Buddy(acc, recipient);
        contexts.remove(bd);
    }
    
    public int getConnNum(){
        return contexts.size();
    }

	public StringTLV messageReceiving(String accountname, String protocol, 
			String sender, String message, OTRCallbacks callback) throws Exception {
		ConnContext conn = getConnContext(accountname, protocol, sender);
		return conn.messageReceiving(message, callback);
	}

	public String messageSending(String accountname,String protocol,
			String recipient, String message, OTRTLV[] tlvs,int fragPolicy, 
			OTRCallbacks callback) throws Exception {
		ConnContext conn = getConnContext(accountname, protocol, recipient);
		String str = conn.messageSending(message, tlvs, fragPolicy, callback);
		return str;
	}
    
    /** Unit tests. */
    /*public static void main(String[] args) {
    UserState u = new UserState(new
        ca.uwaterloo.crysp.otr.crypt.jca.Provider());
    Account a = new Account("ian", "XMPP");
    try {
        PrivKey p = u.getPrivKey(a, false);
        System.out.println(p == null);
        p = u.getPrivKey(a, true);
        p.dump();
    } catch (OTRException e) {
        System.out.println("Error: " + e.getMessage());
    }
    }*/
}
