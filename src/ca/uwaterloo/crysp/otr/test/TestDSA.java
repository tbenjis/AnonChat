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


public class TestDSA extends TestSuite
{
        private Provider prov;
        public TestDSA(TestHarness h, Provider prov)
        {
                super(h);
                this.prov=prov;
                createSuite();
        }
        
        public String getName()
        {
                return "DSA";
        }

        protected void createSuite()
        {
                this.addTestCase(new TestCaseDSANoOptionalParameters(this.harness));
                this.addTestCase(new TestCaseDSAMultiple(this.harness));
                this.addTestCase(new TestCaseDSAInvalid(this.harness));
        }
        
        private class TestCaseDSANoOptionalParameters extends TestCase
        {
                public TestCaseDSANoOptionalParameters(TestHarness h)
                {       
                        super(h);
                }

                protected void runTest() throws TestException
                {
                        try {
                                DSAKeyPairGenerator gen = prov.getDSAKeyPairGenerator();
                                KeyPair kp = gen.generateKeyPair();
                                
                                RawDSA d = prov.getRawDSA();
                                
                                byte[] s = d.sign(
                                    (DSAPrivateKey)kp.getPrivateKey(),
                                    "hellohellohellohello123456123456".getBytes()
                                );
                                boolean r = d.verify(
                                (DSAPublicKey)kp.getPublicKey(),
                                s, "hellohellohellohello123456123456".getBytes()
                                );
                                
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                        } catch (OTRException e) {
                                throw new TestException(e.getMessage());
                        }
                }

                public String getDesc()
                {
                        return "Signature verification with no optional parameters";
                }
        }
        
        
        private class TestCaseDSAMultiple extends TestCase
        {
                public TestCaseDSAMultiple(TestHarness h)
                {       
                        super(h);
                }

                protected void runTest() throws TestException
                {
                        try {
                                DSAKeyPairGenerator gen = prov.getDSAKeyPairGenerator();
                                KeyPair kp = gen.generateKeyPair();
                                
                                RawDSA d = prov.getRawDSA();
                                
                                byte[] message = "HelloWorldHelloWorld123456123456".getBytes();
                                byte[] message2 = "This is my 2nd msg. 123456123456".getBytes();
                                
                                byte[] s = d.sign((DSAPrivateKey)kp.getPrivateKey(), message);
                                boolean r = d.verify(
                                (DSAPublicKey)kp.getPublicKey(),
                                s, message);
                                
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                                
                                s = d.sign((DSAPrivateKey)kp.getPrivateKey(), message);
                                r = d.verify((DSAPublicKey)kp.getPublicKey(), s, message);
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                                
                                s = d.sign((DSAPrivateKey)kp.getPrivateKey(), message2);
                                r = d.verify((DSAPublicKey)kp.getPublicKey(), s, message2);
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                                
                        } catch (OTRException e) {
                                throw new TestException(e.getMessage());
                        }
                }

                public String getDesc()
                {
                        return "Signing and verifying data multiple times";
                }
        }
        
        private class TestCaseDSAInvalid extends TestCase
        {
                public TestCaseDSAInvalid(TestHarness h)
                {       
                        super(h);
                }

                protected void runTest() throws TestException
                {
                        try {
                                DSAKeyPairGenerator gen = prov.getDSAKeyPairGenerator();
                                KeyPair kp = gen.generateKeyPair();
                                
                                RawDSA d = prov.getRawDSA();
                                
                                byte[] message = "This is my test msg.123456123456".getBytes();
                                
                                byte[] s = d.sign((DSAPrivateKey)kp.getPrivateKey(), message);
                                // Alter the bytes a bit
                                s[0]++;
                                s[1]--;
                                boolean r = d.verify((DSAPublicKey)kp.getPublicKey(), s, message);
                                
                                if(r) {
                                    throw new RuntimeException("Message was erraneously accepted");
                                }
                                
                                // Restore the original signature, signature should be accepted
                                s[0]--;
                                s[1]++;
                                r = d.verify((DSAPublicKey)kp.getPublicKey(), s, message);
                                if (!r) {
                                        throw new RuntimeException("Message was erraneously rejected");
                                }
                                
                        } catch (OTRException e) {
                                throw new TestException(e.getMessage());
                        }
                }

                public String getDesc()
                {
                        return "Invalid signature detection";
                }
        }
}
