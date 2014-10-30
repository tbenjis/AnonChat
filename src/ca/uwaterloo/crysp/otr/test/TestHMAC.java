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

import ca.uwaterloo.crysp.otr.crypt.*;

public class TestHMAC extends TestSuite
{
        private Provider prov;
        public TestHMAC(TestHarness h, Provider prov)
        {
                super(h);
                this.prov=prov;
                createSuite();
        }
        
        public String getName()
        {
                return "HMAC-SHA1 and HMAC-SHA256";
        }

        protected void createSuite()
        {
                this.addTestCase(new TestCaseHMACNoKey(this.harness));
                this.addTestCase(new TestCaseHMACNoOptionalParameters(this.harness));
                this.addTestCase(new TestCaseHMACWithOptionalParameters(this.harness));
                this.addTestCase(new TestCaseHMACMultiple(this.harness));
                this.addTestCase(new TestCaseHMACInvalid(this.harness));
                this.addTestCase(new TestCaseHMACUpdate(this.harness));
        }
        
        private class TestCaseHMACNoKey extends TestCase
        {
                public TestCaseHMACNoKey(TestHarness h)
                {       
                        super(h);
                }

                protected void runTest() throws TestException
                {
                        // Try tagging data before initializing key
                        try {
                                HMAC h = prov.getHMACSHA1();
                                h.tag("hi".getBytes());
                                // Execution should not reach here, exception should have been thrown
                                throw new RuntimeException("Attempt to tagging data before setting key should have failed!");
                        } catch (OTRCryptException e) {
                            // Exception caught, test success
                        }
                        
                        // Try verifying data before initializing keypair
                        try {
                                HMAC h = prov.getHMACSHA1();
                                h.verify("dummy".getBytes(), "hi".getBytes());
                                // Execution should not reach here, exception should have been thrown
                                throw new RuntimeException("Attempt to verify data before setting keypair should have failed!");
                        } catch (OTRCryptException e) {
                            // Exception caught, test success
                        }
                        
                                                // Try tagging data before initializing key
                        try {
                                HMAC h = prov.getHMACSHA256();
                                h.tag("hi".getBytes());
                                // Execution should not reach here, exception should have been thrown
                                throw new RuntimeException("Attempt to tagging data before setting key should have failed!");
                        } catch (OTRCryptException e) {
                            // Exception caught, test success
                        }
                        
                        // Try verifying data before initializing keypair
                        try {
                                HMAC h = prov.getHMACSHA256();
                                h.verify("dummy".getBytes(), "hi".getBytes());
                                // Execution should not reach here, exception should have been thrown
                                throw new RuntimeException("Attempt to verify data before setting keypair should have failed!");
                        } catch (OTRCryptException e) {
                            // Exception caught, test success
                        }
                }

                public String getDesc()
                {
                        return "Tagging + verifying data before setting key";
                }
        }

        private class TestCaseHMACNoOptionalParameters extends TestCase
        {
                public TestCaseHMACNoOptionalParameters(TestHarness h)
                {       
                        super(h);
                }

                protected void runTest() throws TestException
                {
                        try {
                                HMACKeyGenerator gen = prov.getHMACKeyGenerator();
                                Key kp = gen.generateKey();
                                
                                HMAC d = prov.getHMACSHA1();
                                d.setKey(kp);
                                
                                byte[] s = d.tag("hi".getBytes());
                                boolean r = d.verify(s, "hi".getBytes());
                                
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                        } catch (OTRCryptException e) {
                                throw new TestException(e.getMessage());
                        }
                        
                        try {
                                HMACKeyGenerator gen = prov.getHMACKeyGenerator();
                                Key kp = gen.generateKey();
                                
                                HMAC d = prov.getHMACSHA256();
                                d.setKey(kp);
                                
                                byte[] s = d.tag("hi".getBytes());
                                boolean r = d.verify(s, "hi".getBytes());
                                
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                        } catch (OTRCryptException e) {
                                throw new TestException(e.getMessage());
                        }
                }

                public String getDesc()
                {
                        return "Mac verification with no optional parameters";
                }
        }
        
        private class TestCaseHMACWithOptionalParameters extends TestCase
        {
                public TestCaseHMACWithOptionalParameters(TestHarness h)
                {       
                        super(h);
                }

                protected void runTest() throws TestException
                {
                        try {
                                HMACKeyGenerator gen = prov.getHMACKeyGenerator();
                                Key kp = gen.generateKey();
                                
                                HMAC d = prov.getHMACSHA1();
                                d.setKey(kp);
                                
                                byte[] message = "Hello World".getBytes();
                                
                                byte[] s = d.tag(message, 2, 5);
                                boolean r = d.verify(s, message, 2, 5);
                                
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                        } catch (OTRCryptException e) {
                                throw new TestException(e.getMessage());
                        }
                        try {
                                HMACKeyGenerator gen = prov.getHMACKeyGenerator();
                                Key kp = gen.generateKey();
                                
                                HMAC d = prov.getHMACSHA256();
                                d.setKey(kp);
                                
                                byte[] message = "Hello World".getBytes();
                                
                                byte[] s = d.tag(message, 2, 5);
                                boolean r = d.verify(s, message, 2, 5);
                                
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                        } catch (OTRCryptException e) {
                                throw new TestException(e.getMessage());
                        }
                }

                public String getDesc()
                {
                        return "Mac verification with length and offset specified";
                }
        }
        
        private class TestCaseHMACMultiple extends TestCase
        {
                public TestCaseHMACMultiple(TestHarness h)
                {       
                        super(h);
                }

                protected void runTest() throws TestException
                {
                        try {
                                HMACKeyGenerator gen = prov.getHMACKeyGenerator();
                                Key kp = gen.generateKey();
                                
                                HMAC d = prov.getHMACSHA1();
                                d.setKey(kp);
                                
                                byte[] message = "Hello World".getBytes();
                                byte[] message2 = "This is my 2nd message".getBytes();
                                
                                byte[] s = d.tag(message, 2, 5);
                                boolean r = d.verify(s, message, 2, 5);
                                
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                                
                                s = d.tag(message);
                                r = d.verify(s, message);
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                                
                                s = d.tag(message2);
                                r = d.verify(s, message2);
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                                
                                s = d.tag(message2, 3, 7);
                                r = d.verify(s, message2, 3, 7);
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                        } catch (OTRCryptException e) {
                                throw new TestException(e.getMessage());
                        }
                                                try {
                                HMACKeyGenerator gen = prov.getHMACKeyGenerator();
                                Key kp = gen.generateKey();
                                
                                HMAC d = prov.getHMACSHA256();
                                d.setKey(kp);
                                
                                byte[] message = "Hello World".getBytes();
                                byte[] message2 = "This is my 2nd message".getBytes();
                                
                                byte[] s = d.tag(message, 2, 5);
                                boolean r = d.verify(s, message, 2, 5);
                                
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                                
                                s = d.tag(message);
                                r = d.verify(s, message);
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                                
                                s = d.tag(message2);
                                r = d.verify(s, message2);
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                                
                                s = d.tag(message2, 3, 7);
                                r = d.verify(s, message2, 3, 7);
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }
                        } catch (OTRCryptException e) {
                                throw new TestException(e.getMessage());
                        }
                }

                public String getDesc()
                {
                        return "tagging and verifying data multiple times";
                }
        }
        
        private class TestCaseHMACInvalid extends TestCase
        {
                public TestCaseHMACInvalid(TestHarness h)
                {       
                        super(h);
                }

                protected void runTest() throws TestException
                {
                        try {
                                HMACKeyGenerator gen = prov.getHMACKeyGenerator();
                                Key kp = gen.generateKey();
                                
                                HMAC d = prov.getHMACSHA1();
                                d.setKey(kp);
                                
                                byte[] message = "This is my test message".getBytes();
                                
                                byte[] s = d.tag(message);
                                // Alter the bytes a bit
                                s[0]++;
                                s[1]--;
                                boolean r = d.verify(s, message);
                                
                                if(r) {
                                    throw new RuntimeException("Message was erraneously accepted");
                                }
                                
                                // Restore the original tagature, tagature should be accepted
                                s[0]--;
                                s[1]++;
                                r = d.verify(s, message);
                                if (!r) {
                                        throw new RuntimeException("Message was erraneously rejected");
                                }
                                
                        } catch (OTRCryptException e) {
                                throw new TestException(e.getMessage());
                        }
                        
                       try {
                                HMACKeyGenerator gen = prov.getHMACKeyGenerator();
                                Key kp = gen.generateKey();
                                
                                HMAC d = prov.getHMACSHA256();
                                d.setKey(kp);
                                
                                byte[] message = "This is my test message".getBytes();
                                
                                byte[] s = d.tag(message);
                                // Alter the bytes a bit
                                s[0]++;
                                s[1]--;
                                boolean r = d.verify(s, message);
                                
                                if(r) {
                                    throw new RuntimeException("Message was erraneously accepted");
                                }
                                
                                // Restore the original tagature, tagature should be accepted
                                s[0]--;
                                s[1]++;
                                r = d.verify(s, message);
                                if (!r) {
                                        throw new RuntimeException("Message was erraneously rejected");
                                }
                                
                        } catch (OTRCryptException e) {
                                throw new TestException(e.getMessage());
                        }
                }

                public String getDesc()
                {
                        return "Invalid tag detection";
                }
        }
        
        private class TestCaseHMACUpdate extends TestCase{
                
                public TestCaseHMACUpdate(TestHarness h)
                {       
                        super(h);
                }

                protected void runTest() throws TestException
                {
                        try {
                                HMACKeyGenerator gen = prov.getHMACKeyGenerator();
                                Key kp = gen.generateKey();
                                
                                HMAC d = prov.getHMACSHA1();
                                d.setKey(kp);
                                
                                byte[] message = "Hello ".getBytes();
                                byte[] message2 = "world".getBytes();
                                
                                d.update(message);
                                d.update(message2);
                                byte[] s = d.doFinal();
                                boolean r = d.verify(s, "Hello world".getBytes());
                                
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }

                        } catch (OTRCryptException e) {
                                throw new TestException(e.getMessage());
                        }
                        
                        try {
                                HMACKeyGenerator gen = prov.getHMACKeyGenerator();
                                Key kp = gen.generateKey();
                                
                                HMAC d = prov.getHMACSHA256();
                                d.setKey(kp);
                                
                                byte[] message = "Hello ".getBytes();
                                byte[] message2 = "world".getBytes();
                                
                                d.update(message);
                                d.update(message2);
                                byte[] s = d.doFinal();
                                boolean r = d.verify(s, "Hello world".getBytes());
                                
                                if(!r) {
                                        throw new RuntimeException("Message could not be verified");
                                }

                        } catch (OTRCryptException e) {
                                throw new TestException(e.getMessage());
                        }
                }

                public String getDesc()
                {
                        return "Tagging and verifying data using update";
                }
        }
        
}
