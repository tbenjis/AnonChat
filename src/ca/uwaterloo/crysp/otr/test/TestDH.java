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

package ca.uwaterloo.crysp.otr.test;
import ca.uwaterloo.crysp.otr.OTRException;
import ca.uwaterloo.crysp.otr.crypt.*;

/**
 * Test suite for Diffie Hellman key exchange.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public class TestDH extends TestSuite {
        
        private Provider prov;
        public TestDH(TestHarness h, Provider prov)
        {
                super(h);
                this.prov=prov;
                createSuite();
        }
        protected String getName() {
                return "DH Key Exchange";
        }

        protected void createSuite() {
                this.addTestCase(new TestDHKeyTypes(this.harness));
                this.addTestCase(new TestDHKeyComputation(this.harness));
        }
        
        private class TestDHKeyTypes extends TestCase
        {
                public TestDHKeyTypes(TestHarness h)
                {       
                        super(h);
                }
                
                protected String getDesc() {
                        return "Computing DH public + private values";
                }

                protected void runTest() throws TestException {
                        KeyPairGenerator kg = prov.getDHKeyPairGenerator();
                        try {
                                KeyPair kp = kg.generateKeyPair();
                                // Check types of generated keys
                                PublicKey pub = kp.getPublicKey();
                                if (!(pub instanceof DHPublicKey)) {
                                        throw new RuntimeException("DH public key generated is of wrong type.");
                                }
                                
                                PrivateKey priv = kp.getPrivateKey();
                                if (!(priv instanceof DHPrivateKey)) {
                                        throw new RuntimeException("DH private key generated is of wrong type.");
                                }
                        } catch (OTRException e) {
                                throw new TestException("Exception during key generation."+e.getMessage());
                        }
                }
        }
        
        private class TestDHKeyComputation extends TestCase
        {
                public TestDHKeyComputation(TestHarness h)
                {       
                        super(h);
                }
                
                protected String getDesc() {
                        return "Verifying shared secret";
                }

                protected void runTest() throws TestException {
                        DHKeyAgreement[] ka = new DHKeyAgreement[2];
                        KeyPairGenerator kg = prov.getDHKeyPairGenerator();
                        KeyPair kp[] = new KeyPair[2];
                        DHPublicKey pub[] = new DHPublicKey[2];
                        DHPrivateKey priv[] = new DHPrivateKey[2];
                        byte[][] sharedSecret = new byte[2][];
                        
                        try {
                                // Alice and bob generate keypairs
                                for (int i = 0; i < 2; i++) {
                                        kp[i] = kg.generateKeyPair();
                                        pub[i] = (DHPublicKey)kp[i].getPublicKey();
                                        priv[i] = (DHPrivateKey)kp[i].getPrivateKey();
                                }
                                
                                // Alice computes her shared secret from Bob's public key
                                ka[0] = prov.getDHKeyAgreement();
                                ka[0].init(priv[0]);
                                sharedSecret[0] = ka[0].generateSecret(pub[1]);
                                
                                // Bob computes his shared secret from Alice's public key
                                ka[1] = prov.getDHKeyAgreement();
                                ka[1].init(priv[1]);
                                sharedSecret[1] = ka[1].generateSecret(pub[0]);
                                
                                // Compare their shared secrets
                                if (sharedSecret[0].length != sharedSecret[1].length) {
                                        throw new RuntimeException("Shared secrets are not the same length!");
                                }
                                for (int i = 0; i < sharedSecret[0].length; i++) {
                                        if (sharedSecret[0][i] != sharedSecret[1][i]) {
                                                throw new RuntimeException("Shared secret calculation: Byte mismatch at position " + i);
                                        }
                                }
                                
                                // Retrieve the old shared secrets, ensure that it matches the original one
                                sharedSecret[0] = ka[0].getSharedSecret();
                                for (int i = 0; i < sharedSecret[0].length; i++) {
                                        if (sharedSecret[0][i] != sharedSecret[1][i]) {
                                                throw new RuntimeException("Retrieving previous shared secret: Byte mismatch at position " + i);
                                        }
                                }
                                
                        } catch (OTRException e) {
                                throw new TestException("Exception during key generation."+ e.getMessage());
                        }
                }
        }
}
