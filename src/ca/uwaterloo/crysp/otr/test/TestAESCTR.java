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


/**
 * Test suites to test AES encryption + decryption.
 * 
 * @author Andrew Chung (kachung@uwaterloo.ca)
 */
public class TestAESCTR extends TestSuite
{
        private Provider prov;
        public TestAESCTR(TestHarness h, Provider prov)
        {
                super(h);
                this.prov=prov;
                createSuite();
        }
        
        public String getName()
        {
                return "AES CTR Mode";
        }

        protected void createSuite()
        {
                this.addTestCase(new AESTestVector1(this.harness, prov));
                this.addTestCase(new AESTestVector2(this.harness, prov));
                this.addTestCase(new AESTestVector3(this.harness, prov));
                this.addTestCase(new AESTestVector4(this.harness, prov));
                this.addTestCase(new AESTestVector5(this.harness, prov));
                this.addTestCase(new AESTestVector6(this.harness, prov));
                this.addTestCase(new AESTestVector7(this.harness, prov));
                this.addTestCase(new AESTestVector8(this.harness, prov));
        }
        
        private static abstract class AESTestVector extends TestCase
        {
                byte[] aesKey;
                byte[] high;
                byte[] plaintext;
                byte[] expectedCiphertext;
                Provider prov;
                
                public AESTestVector(TestHarness h, byte[] aesKey, byte[] highBits, 
                                byte[] plaintext, byte[] expectedCiphertext, Provider prov) {
                        super(h);
                        
                        this.aesKey = new byte[aesKey.length];
                        System.arraycopy(aesKey, 0, this.aesKey, 0, aesKey.length);
                        
                        this.high = new byte[highBits.length];
                        System.arraycopy(highBits, 0, this.high, 0, highBits.length);
                        
                        this.plaintext = new byte[plaintext.length];
                        System.arraycopy(plaintext, 0, this.plaintext, 0, plaintext.length);
                        
                        this.expectedCiphertext = new byte[expectedCiphertext.length];
                        System.arraycopy(expectedCiphertext, 0, this.expectedCiphertext, 0, expectedCiphertext.length);
                
                        this.prov=prov;
                }

                protected void runTest() throws TestException {
                        SecretKey secKey = prov.getAESKey(aesKey);
                        //System.out.println("Here");
                        AESCTR aes;
                        try {
                                aes = prov.getAESCounterMode(secKey, high);
                                
                                // Verify ciphertext
                                byte[] cipherText = aes.doFinal(plaintext);
                                if (cipherText.length != expectedCiphertext.length) {
                                        throw new RuntimeException("Ciphertext output of incorrect length");
                                }
                                for (int i = 0; i < expectedCiphertext.length; i++) {
                                        if (cipherText[i] != expectedCiphertext[i]) {
                                                throw new RuntimeException("Ciphertext byte mismatch at position " + i);
                                        }
                                }
                                
                                // Try to decrypt
                                byte[] originalText = aes.doFinal(cipherText);
                                if (originalText.length != plaintext.length) {
                                        throw new RuntimeException("Plaintext output of incorrect length");
                                }
                                for (int i = 0; i < originalText.length; i++) {
                                        if (plaintext[i] != originalText[i]) {
                                                throw new RuntimeException("Plaintext byte mismatch at position " + i);
                                        }
                                }
                        } catch (OTRCryptException e) {
                                throw new TestException(e.getMessage());
                        }
                }
        }
        
        // 16 byte plaintext (taken from RFC, except counter behaves differently)
        private static class AESTestVector1 extends AESTestVector {
                static byte[] testAESKey = {
                        (byte)0xAE, (byte)0x68, (byte)0x52, (byte)0xF8, (byte)0x12, (byte)0x10, (byte)0x67, (byte)0xCC, 
                        (byte)0x4B, (byte)0xF7, (byte)0xA5, (byte)0x76, (byte)0x55, (byte)0x77, (byte)0xF3, (byte)0x9E,
                };
                static byte[] testHighBits = {
                        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                };
                static byte[] testPlainText = {
                        (byte)0x53, (byte)0x69, (byte)0x6E, (byte)0x67, (byte)0x6C, (byte)0x65, (byte)0x20, (byte)0x62,
                        (byte)0x6C, (byte)0x6F, (byte)0x63, (byte)0x6B, (byte)0x20, (byte)0x6D, (byte)0x73, (byte)0x67,
                };
                static byte[] testExpectedCiphertext = {
                        (byte)0x9b, (byte)0x88, (byte)0x8e, (byte)0x93, (byte)0xa7, (byte)0x1a, (byte)0x97, (byte)0xaf,
                        (byte)0x56, (byte)0x00, (byte)0xc9, (byte)0xbe, (byte)0x26, (byte)0x8b, (byte)0xd2, (byte)0xcd,
                };
                public AESTestVector1(TestHarness h, Provider prov) {
                        super(h, testAESKey, testHighBits, testPlainText, testExpectedCiphertext, prov);
                }
                protected String getDesc() {
                        return "AES Test Vector #1 (16 byte plaintext)";
                }
        }
        
        // 16 byte plaintext
        /*
        Key: e0 a5 7b 32 6d 28 53 74 93 e5 70 ab 0a 10 f4 0b
        CTR: 56 27 ff 60 d1 00 45 b1
        Plaintext : 88 25 83 a1 a9 e9 2d 30 81 69 0c 8a c8 90 68 c7
        Ciphertext: 69 45 70 51 a0 b5 35 11 00 81 be fc 38 24 4e 4a
         */
        private static class AESTestVector2 extends AESTestVector {
                static byte[] testAESKey = {
                        (byte)0xe0, (byte)0xa5, (byte)0x7b, (byte)0x32, (byte)0x6d, (byte)0x28, (byte)0x53, (byte)0x74,
                        (byte)0x93, (byte)0xe5, (byte)0x70, (byte)0xab, (byte)0x0a, (byte)0x10, (byte)0xf4, (byte)0x0b,
                };
                static byte[] testHighBits = {
                        (byte)0x56, (byte)0x27, (byte)0xff, (byte)0x60, (byte)0xd1, (byte)0x00, (byte)0x45, (byte)0xb1,
                };
                static byte[] testPlainText = {
                        (byte)0x88, (byte)0x25, (byte)0x83, (byte)0xa1, (byte)0xa9, (byte)0xe9, (byte)0x2d, (byte)0x30,
                        (byte)0x81, (byte)0x69, (byte)0x0c, (byte)0x8a, (byte)0xc8, (byte)0x90, (byte)0x68, (byte)0xc7,
                };
                static byte[] testExpectedCiphertext = {
                        (byte)0x69, (byte)0x45, (byte)0x70, (byte)0x51, (byte)0xa0, (byte)0xb5, (byte)0x35, (byte)0x11,
                        (byte)0x00, (byte)0x81, (byte)0xbe, (byte)0xfc, (byte)0x38, (byte)0x24, (byte)0x4e, (byte)0x4a,
                };
                public AESTestVector2(TestHarness h, Provider prov) {
                        super(h, testAESKey, testHighBits, testPlainText, testExpectedCiphertext, prov);
                }
                protected String getDesc() {
                        return "AES Test Vector #2 (16 byte plaintext)";
                }
        }
        
        // 32 byte plaintext
        /*
        Key: 64 9b 56 ce e7 56 78 6f ff 74 26 ec fa c6 60 21
        CTR: 40 d8 8a 0a 17 52 e3 6a
        Plaintext : c9 6f 48 68 91 eb 00 4e 20 aa ad 04 fb b4 62 73 a2 55 e2 d8 48 ad 82 bb 83 31 d0 f1 14 b8 8a 16
        Ciphertext: 41 09 81 bf 9c 73 9f 38 e9 b6 2b 8e 83 b6 43 e6 91 eb a3 6c 60 d2 a5 02 2c e1 a2 d9 4a 3c 2c bf
         */
        private static class AESTestVector3 extends AESTestVector {
                static byte[] testAESKey = {
                        (byte)0x64, (byte)0x9b, (byte)0x56, (byte)0xce, (byte)0xe7, (byte)0x56, (byte)0x78, (byte)0x6f,
                        (byte)0xff, (byte)0x74, (byte)0x26, (byte)0xec, (byte)0xfa, (byte)0xc6, (byte)0x60, (byte)0x21,
                };
                static byte[] testHighBits = {
                        (byte)0x40, (byte)0xd8, (byte)0x8a, (byte)0x0a, (byte)0x17, (byte)0x52, (byte)0xe3, (byte)0x6a,
                };
                static byte[] testPlainText = {
                        (byte)0xc9, (byte)0x6f, (byte)0x48, (byte)0x68, (byte)0x91, (byte)0xeb, (byte)0x00, (byte)0x4e,
                        (byte)0x20, (byte)0xaa, (byte)0xad, (byte)0x04, (byte)0xfb, (byte)0xb4, (byte)0x62, (byte)0x73,
                        (byte)0xa2, (byte)0x55, (byte)0xe2, (byte)0xd8, (byte)0x48, (byte)0xad, (byte)0x82, (byte)0xbb,
                        (byte)0x83, (byte)0x31, (byte)0xd0, (byte)0xf1, (byte)0x14, (byte)0xb8, (byte)0x8a, (byte)0x16,
                };
                static byte[] testExpectedCiphertext = {
                        (byte)0x41, (byte)0x09, (byte)0x81, (byte)0xbf, (byte)0x9c, (byte)0x73, (byte)0x9f, (byte)0x38,
                        (byte)0xe9, (byte)0xb6, (byte)0x2b, (byte)0x8e, (byte)0x83, (byte)0xb6, (byte)0x43, (byte)0xe6,
                        (byte)0x91, (byte)0xeb, (byte)0xa3, (byte)0x6c, (byte)0x60, (byte)0xd2, (byte)0xa5, (byte)0x02,
                        (byte)0x2c, (byte)0xe1, (byte)0xa2, (byte)0xd9, (byte)0x4a, (byte)0x3c, (byte)0x2c, (byte)0xbf,
                };
                public AESTestVector3(TestHarness h, Provider prov) {
                        super(h, testAESKey, testHighBits, testPlainText, testExpectedCiphertext, prov);
                }
                protected String getDesc() {
                        return "AES Test Vector #3 (32 byte plaintext)";
                }
        }
        
        // 15 byte plaintext
        /*
        Key: 0f c2 4c 9d 29 95 a5 c5 d8 7d e0 04 f3 03 b1 ac
        CTR: 62 c7 6f 69 7f 02 30 93
        Plaintext : ee e6 d0 99 8b a2 b9 51 70 0c e7 52 dd 2a 0f
        Ciphertext: 62 7b a6 5a 75 88 c5 a3 ec f0 fc a2 80 1e 0a
         */
        private static class AESTestVector4 extends AESTestVector {
                static byte[] testAESKey = {
                        (byte)0x0f, (byte)0xc2, (byte)0x4c, (byte)0x9d, (byte)0x29, (byte)0x95, (byte)0xa5, (byte)0xc5,
                        (byte)0xd8, (byte)0x7d, (byte)0xe0, (byte)0x04, (byte)0xf3, (byte)0x03, (byte)0xb1, (byte)0xac,
                };
                static byte[] testHighBits = {
                        (byte)0x62, (byte)0xc7, (byte)0x6f, (byte)0x69, (byte)0x7f, (byte)0x02, (byte)0x30, (byte)0x93,
                };
                static byte[] testPlainText = {
                        (byte)0xee, (byte)0xe6, (byte)0xd0, (byte)0x99, (byte)0x8b, (byte)0xa2, (byte)0xb9, (byte)0x51,
                        (byte)0x70, (byte)0x0c, (byte)0xe7, (byte)0x52, (byte)0xdd, (byte)0x2a, (byte)0x0f,
                };
                static byte[] testExpectedCiphertext = {
                        (byte)0x62, (byte)0x7b, (byte)0xa6, (byte)0x5a, (byte)0x75, (byte)0x88, (byte)0xc5, (byte)0xa3,
                        (byte)0xec, (byte)0xf0, (byte)0xfc, (byte)0xa2, (byte)0x80, (byte)0x1e, (byte)0x0a,
                };
                public AESTestVector4(TestHarness h, Provider prov) {
                        super(h, testAESKey, testHighBits, testPlainText, testExpectedCiphertext, prov);
                }
                protected String getDesc() {
                        return "AES Test Vector #4 (15 byte plaintext)";
                }
        }
        
        // 45 byte plaintext
        /*
        Key: 87 d5 c4 eb 75 8d e8 32 c5 25 6e 55 7b 24 24 fd
        CTR: c1 3a 26 ef 12 a7 80 44
        Plaintext :
        30 1a 49 c5 e5 9c 84 20 78 0e 90 83 1b 1a c7 f4 0a 74 1c 35 05 e0 28 57
        0d fe 5c 43 17 21 b9 20 3a b6 75 67 c0 a0 c3 d6 d4 2f 69 b6 97
        Ciphertext:
        fa b7 ca d5 49 e8 fa ce dc db 5a ae 1d fb 3b 7c 2e 04 50 b7 93 97 bf e8
        c5 7b ad 3b 50 a9 86 d5 f4 cb 49 be c3 f1 35 3b 25 f3 39 4e f3
         */
        private static class AESTestVector5 extends AESTestVector {
                static byte[] testAESKey = {
                        (byte)0x87, (byte)0xd5, (byte)0xc4, (byte)0xeb, (byte)0x75, (byte)0x8d, (byte)0xe8, (byte)0x32,
                        (byte)0xc5, (byte)0x25, (byte)0x6e, (byte)0x55, (byte)0x7b, (byte)0x24, (byte)0x24, (byte)0xfd,
                };
                static byte[] testHighBits = {
                        (byte)0xc1, (byte)0x3a, (byte)0x26, (byte)0xef, (byte)0x12, (byte)0xa7, (byte)0x80, (byte)0x44,
                };
                static byte[] testPlainText = {
                        (byte)0x30, (byte)0x1a, (byte)0x49, (byte)0xc5, (byte)0xe5, (byte)0x9c, (byte)0x84, (byte)0x20,
                        (byte)0x78, (byte)0x0e, (byte)0x90, (byte)0x83, (byte)0x1b, (byte)0x1a, (byte)0xc7, (byte)0xf4,
                        (byte)0x0a, (byte)0x74, (byte)0x1c, (byte)0x35, (byte)0x05, (byte)0xe0, (byte)0x28, (byte)0x57,
                        (byte)0x0d, (byte)0xfe, (byte)0x5c, (byte)0x43, (byte)0x17, (byte)0x21, (byte)0xb9, (byte)0x20,
                        (byte)0x3a, (byte)0xb6, (byte)0x75, (byte)0x67, (byte)0xc0, (byte)0xa0, (byte)0xc3, (byte)0xd6,
                        (byte)0xd4, (byte)0x2f, (byte)0x69, (byte)0xb6, (byte)0x97,
                };
                static byte[] testExpectedCiphertext = {
                        (byte)0xfa, (byte)0xb7, (byte)0xca, (byte)0xd5, (byte)0x49, (byte)0xe8, (byte)0xfa, (byte)0xce,
                        (byte)0xdc, (byte)0xdb, (byte)0x5a, (byte)0xae, (byte)0x1d, (byte)0xfb, (byte)0x3b, (byte)0x7c,
                        (byte)0x2e, (byte)0x04, (byte)0x50, (byte)0xb7, (byte)0x93, (byte)0x97, (byte)0xbf, (byte)0xe8,
                        (byte)0xc5, (byte)0x7b, (byte)0xad, (byte)0x3b, (byte)0x50, (byte)0xa9, (byte)0x86, (byte)0xd5,
                        (byte)0xf4, (byte)0xcb, (byte)0x49, (byte)0xbe, (byte)0xc3, (byte)0xf1, (byte)0x35, (byte)0x3b,
                        (byte)0x25, (byte)0xf3, (byte)0x39, (byte)0x4e, (byte)0xf3,
                };
                public AESTestVector5(TestHarness h, Provider prov) {
                        super(h, testAESKey, testHighBits, testPlainText, testExpectedCiphertext, prov);
                }
                protected String getDesc() {
                        return "AES Test Vector #5 (45 byte plaintext)";
                }
        }
        
        // 256 byte plaintext
        /*
        Key: ee f2 72 d8 89 37 41 97 b4 b1 6b 4b 31 19 39 e4
        CTR: 6f 25 cc f6 a5 3e 39 b3 
        Plaintext :
        76 9e 4a 23 99 20 d8 4b 3c 68 e3 25 3b 8e aa 94 9b a4 9b b2 02 da 39 08 b1 f6 a0 3a b9 f9 0b 80 64 9c 16 ef 37 23 13 ee
        6b 73 3d e5 51 ba fd 69 5b 13 50 e2 db 16 7c 40 6b b7 4a 0a 18 11 b0 f3 7d 51 bd 1b c5 ad fb 8d 47 56 b0 1e 5e c1 df 91
        cb 2e c9 7a 06 bd 31 ff 8f b6 18 b4 92 5f bd 29 79 49 79 82 a7 3b a3 c7 25 b7 da 68 dd fd cd 74 fd 53 0c 8e ce b3 d0 bc
        82 74 4d 8a 57 10 94 e4 fe 5e 4f 66 34 17 6b 17 81 5e 0a 69 cb 5a 9b 6d c8 0a 3a c0 a3 5f 8e 39 f3 53 22 5d b3 14 51 6f
        8e aa 5c d9 fd 95 b1 5b 70 50 76 fd 23 25 70 a0 bb 29 74 d1 17 47 ec c7 b3 02 d9 ac ac f1 fc 6d b4 50 b4 d2 a3 8b 51 be
        b1 4c b2 db df b7 24 89 e1 40 64 02 a4 a0 38 87 90 05 25 74 f1 7c 81 f7 71 ed 9f c0 12 a1 53 a7 e6 66 db 81 68 10 0f 9b
        ab 7d b4 f8 6e e9 46 59 a0 3b e6 de 4c b7 0f 19
        Ciphertext:
        35 f6 e1 d7 81 8d a6 17 e3 eb cb 5b 54 87 fe 87 8e 90 0f c3 16 34 64 09 1d 21 d0 0e 74 0b ca c5 ac 94 97 4e 2a f7 12 97
        6f 58 27 18 f4 6d 3e 33 1d b2 7e 59 2f a3 43 ec 90 69 56 ba f4 6f d9 ed d0 5c 37 41 f2 5f 60 44 a2 ae 76 13 41 9d 9a 21
        81 e3 a3 90 9d 6d 36 be 2b 2b 74 71 8d 90 d0 9d ae dc a6 ea 40 b3 db e0 1d 8a e2 19 61 db 21 aa 48 af e3 98 b6 3f 90 1c
        13 23 da 3b 2b 88 70 cf e6 50 c5 c7 a8 2a 16 62 9b 65 d2 44 7d 87 e2 c5 fe 78 bf 37 34 02 2d bb 94 be 47 4a fc 25 2e 3f
        bd 34 90 bf fb 86 14 bd ce 97 31 09 89 45 41 83 79 6a 67 5b a3 90 a9 5b 58 a4 ce 81 53 c5 3b 8a b2 56 2d 5c 39 b5 42 46
        cf 6a ab 15 b5 40 ed 77 bc d7 2d da c4 fb a6 0d 3d 94 2b ab 1c 1a 84 cb 05 d0 ee 1c f0 68 94 8c cd 42 2f 4c 20 62 59 76
        87 bc 7a 23 c5 15 05 be 7a c2 70 67 f9 9b c1 b4
         */
        private static class AESTestVector6 extends AESTestVector {
                static byte[] testAESKey = {
                        (byte)0xee, (byte)0xf2, (byte)0x72, (byte)0xd8, (byte)0x89, (byte)0x37, (byte)0x41, (byte)0x97,
                        (byte)0xb4, (byte)0xb1, (byte)0x6b, (byte)0x4b, (byte)0x31, (byte)0x19, (byte)0x39, (byte)0xe4,
                };
                static byte[] testHighBits = {
                        (byte)0x6f, (byte)0x25, (byte)0xcc, (byte)0xf6, (byte)0xa5, (byte)0x3e, (byte)0x39, (byte)0xb3,
                };
                static byte[] testPlainText = {
                        (byte)0x76, (byte)0x9e, (byte)0x4a, (byte)0x23, (byte)0x99, (byte)0x20, (byte)0xd8, (byte)0x4b,
                        (byte)0x3c, (byte)0x68, (byte)0xe3, (byte)0x25, (byte)0x3b, (byte)0x8e, (byte)0xaa, (byte)0x94,
                        (byte)0x9b, (byte)0xa4, (byte)0x9b, (byte)0xb2, (byte)0x02, (byte)0xda, (byte)0x39, (byte)0x08,
                        (byte)0xb1, (byte)0xf6, (byte)0xa0, (byte)0x3a, (byte)0xb9, (byte)0xf9, (byte)0x0b, (byte)0x80,
                        (byte)0x64, (byte)0x9c, (byte)0x16, (byte)0xef, (byte)0x37, (byte)0x23, (byte)0x13, (byte)0xee,
                        (byte)0x6b, (byte)0x73, (byte)0x3d, (byte)0xe5, (byte)0x51, (byte)0xba, (byte)0xfd, (byte)0x69,
                        (byte)0x5b, (byte)0x13, (byte)0x50, (byte)0xe2, (byte)0xdb, (byte)0x16, (byte)0x7c, (byte)0x40,
                        (byte)0x6b, (byte)0xb7, (byte)0x4a, (byte)0x0a, (byte)0x18, (byte)0x11, (byte)0xb0, (byte)0xf3,
                        (byte)0x7d, (byte)0x51, (byte)0xbd, (byte)0x1b, (byte)0xc5, (byte)0xad, (byte)0xfb, (byte)0x8d,
                        (byte)0x47, (byte)0x56, (byte)0xb0, (byte)0x1e, (byte)0x5e, (byte)0xc1, (byte)0xdf, (byte)0x91,
                        (byte)0xcb, (byte)0x2e, (byte)0xc9, (byte)0x7a, (byte)0x06, (byte)0xbd, (byte)0x31, (byte)0xff,
                        (byte)0x8f, (byte)0xb6, (byte)0x18, (byte)0xb4, (byte)0x92, (byte)0x5f, (byte)0xbd, (byte)0x29,
                        (byte)0x79, (byte)0x49, (byte)0x79, (byte)0x82, (byte)0xa7, (byte)0x3b, (byte)0xa3, (byte)0xc7,
                        (byte)0x25, (byte)0xb7, (byte)0xda, (byte)0x68, (byte)0xdd, (byte)0xfd, (byte)0xcd, (byte)0x74,
                        (byte)0xfd, (byte)0x53, (byte)0x0c, (byte)0x8e, (byte)0xce, (byte)0xb3, (byte)0xd0, (byte)0xbc,
                        (byte)0x82, (byte)0x74, (byte)0x4d, (byte)0x8a, (byte)0x57, (byte)0x10, (byte)0x94, (byte)0xe4,
                        (byte)0xfe, (byte)0x5e, (byte)0x4f, (byte)0x66, (byte)0x34, (byte)0x17, (byte)0x6b, (byte)0x17,
                        (byte)0x81, (byte)0x5e, (byte)0x0a, (byte)0x69, (byte)0xcb, (byte)0x5a, (byte)0x9b, (byte)0x6d,
                        (byte)0xc8, (byte)0x0a, (byte)0x3a, (byte)0xc0, (byte)0xa3, (byte)0x5f, (byte)0x8e, (byte)0x39,
                        (byte)0xf3, (byte)0x53, (byte)0x22, (byte)0x5d, (byte)0xb3, (byte)0x14, (byte)0x51, (byte)0x6f,
                        (byte)0x8e, (byte)0xaa, (byte)0x5c, (byte)0xd9, (byte)0xfd, (byte)0x95, (byte)0xb1, (byte)0x5b,
                        (byte)0x70, (byte)0x50, (byte)0x76, (byte)0xfd, (byte)0x23, (byte)0x25, (byte)0x70, (byte)0xa0,
                        (byte)0xbb, (byte)0x29, (byte)0x74, (byte)0xd1, (byte)0x17, (byte)0x47, (byte)0xec, (byte)0xc7,
                        (byte)0xb3, (byte)0x02, (byte)0xd9, (byte)0xac, (byte)0xac, (byte)0xf1, (byte)0xfc, (byte)0x6d,
                        (byte)0xb4, (byte)0x50, (byte)0xb4, (byte)0xd2, (byte)0xa3, (byte)0x8b, (byte)0x51, (byte)0xbe,
                        (byte)0xb1, (byte)0x4c, (byte)0xb2, (byte)0xdb, (byte)0xdf, (byte)0xb7, (byte)0x24, (byte)0x89,
                        (byte)0xe1, (byte)0x40, (byte)0x64, (byte)0x02, (byte)0xa4, (byte)0xa0, (byte)0x38, (byte)0x87,
                        (byte)0x90, (byte)0x05, (byte)0x25, (byte)0x74, (byte)0xf1, (byte)0x7c, (byte)0x81, (byte)0xf7,
                        (byte)0x71, (byte)0xed, (byte)0x9f, (byte)0xc0, (byte)0x12, (byte)0xa1, (byte)0x53, (byte)0xa7,
                        (byte)0xe6, (byte)0x66, (byte)0xdb, (byte)0x81, (byte)0x68, (byte)0x10, (byte)0x0f, (byte)0x9b,
                        (byte)0xab, (byte)0x7d, (byte)0xb4, (byte)0xf8, (byte)0x6e, (byte)0xe9, (byte)0x46, (byte)0x59,
                        (byte)0xa0, (byte)0x3b, (byte)0xe6, (byte)0xde, (byte)0x4c, (byte)0xb7, (byte)0x0f, (byte)0x19,
                };
                static byte[] testExpectedCiphertext = {
                        (byte)0x35, (byte)0xf6, (byte)0xe1, (byte)0xd7, (byte)0x81, (byte)0x8d, (byte)0xa6, (byte)0x17,
                        (byte)0xe3, (byte)0xeb, (byte)0xcb, (byte)0x5b, (byte)0x54, (byte)0x87, (byte)0xfe, (byte)0x87,
                        (byte)0x8e, (byte)0x90, (byte)0x0f, (byte)0xc3, (byte)0x16, (byte)0x34, (byte)0x64, (byte)0x09,
                        (byte)0x1d, (byte)0x21, (byte)0xd0, (byte)0x0e, (byte)0x74, (byte)0x0b, (byte)0xca, (byte)0xc5,
                        (byte)0xac, (byte)0x94, (byte)0x97, (byte)0x4e, (byte)0x2a, (byte)0xf7, (byte)0x12, (byte)0x97,
                        (byte)0x6f, (byte)0x58, (byte)0x27, (byte)0x18, (byte)0xf4, (byte)0x6d, (byte)0x3e, (byte)0x33,
                        (byte)0x1d, (byte)0xb2, (byte)0x7e, (byte)0x59, (byte)0x2f, (byte)0xa3, (byte)0x43, (byte)0xec,
                        (byte)0x90, (byte)0x69, (byte)0x56, (byte)0xba, (byte)0xf4, (byte)0x6f, (byte)0xd9, (byte)0xed,
                        (byte)0xd0, (byte)0x5c, (byte)0x37, (byte)0x41, (byte)0xf2, (byte)0x5f, (byte)0x60, (byte)0x44,
                        (byte)0xa2, (byte)0xae, (byte)0x76, (byte)0x13, (byte)0x41, (byte)0x9d, (byte)0x9a, (byte)0x21,
                        (byte)0x81, (byte)0xe3, (byte)0xa3, (byte)0x90, (byte)0x9d, (byte)0x6d, (byte)0x36, (byte)0xbe,
                        (byte)0x2b, (byte)0x2b, (byte)0x74, (byte)0x71, (byte)0x8d, (byte)0x90, (byte)0xd0, (byte)0x9d,
                        (byte)0xae, (byte)0xdc, (byte)0xa6, (byte)0xea, (byte)0x40, (byte)0xb3, (byte)0xdb, (byte)0xe0,
                        (byte)0x1d, (byte)0x8a, (byte)0xe2, (byte)0x19, (byte)0x61, (byte)0xdb, (byte)0x21, (byte)0xaa,
                        (byte)0x48, (byte)0xaf, (byte)0xe3, (byte)0x98, (byte)0xb6, (byte)0x3f, (byte)0x90, (byte)0x1c,
                        (byte)0x13, (byte)0x23, (byte)0xda, (byte)0x3b, (byte)0x2b, (byte)0x88, (byte)0x70, (byte)0xcf,
                        (byte)0xe6, (byte)0x50, (byte)0xc5, (byte)0xc7, (byte)0xa8, (byte)0x2a, (byte)0x16, (byte)0x62,
                        (byte)0x9b, (byte)0x65, (byte)0xd2, (byte)0x44, (byte)0x7d, (byte)0x87, (byte)0xe2, (byte)0xc5,
                        (byte)0xfe, (byte)0x78, (byte)0xbf, (byte)0x37, (byte)0x34, (byte)0x02, (byte)0x2d, (byte)0xbb,
                        (byte)0x94, (byte)0xbe, (byte)0x47, (byte)0x4a, (byte)0xfc, (byte)0x25, (byte)0x2e, (byte)0x3f,
                        (byte)0xbd, (byte)0x34, (byte)0x90, (byte)0xbf, (byte)0xfb, (byte)0x86, (byte)0x14, (byte)0xbd,
                        (byte)0xce, (byte)0x97, (byte)0x31, (byte)0x09, (byte)0x89, (byte)0x45, (byte)0x41, (byte)0x83,
                        (byte)0x79, (byte)0x6a, (byte)0x67, (byte)0x5b, (byte)0xa3, (byte)0x90, (byte)0xa9, (byte)0x5b,
                        (byte)0x58, (byte)0xa4, (byte)0xce, (byte)0x81, (byte)0x53, (byte)0xc5, (byte)0x3b, (byte)0x8a,
                        (byte)0xb2, (byte)0x56, (byte)0x2d, (byte)0x5c, (byte)0x39, (byte)0xb5, (byte)0x42, (byte)0x46,
                        (byte)0xcf, (byte)0x6a, (byte)0xab, (byte)0x15, (byte)0xb5, (byte)0x40, (byte)0xed, (byte)0x77,
                        (byte)0xbc, (byte)0xd7, (byte)0x2d, (byte)0xda, (byte)0xc4, (byte)0xfb, (byte)0xa6, (byte)0x0d,
                        (byte)0x3d, (byte)0x94, (byte)0x2b, (byte)0xab, (byte)0x1c, (byte)0x1a, (byte)0x84, (byte)0xcb,
                        (byte)0x05, (byte)0xd0, (byte)0xee, (byte)0x1c, (byte)0xf0, (byte)0x68, (byte)0x94, (byte)0x8c,
                        (byte)0xcd, (byte)0x42, (byte)0x2f, (byte)0x4c, (byte)0x20, (byte)0x62, (byte)0x59, (byte)0x76,
                        (byte)0x87, (byte)0xbc, (byte)0x7a, (byte)0x23, (byte)0xc5, (byte)0x15, (byte)0x05, (byte)0xbe,
                        (byte)0x7a, (byte)0xc2, (byte)0x70, (byte)0x67, (byte)0xf9, (byte)0x9b, (byte)0xc1, (byte)0xb4,
                };
                public AESTestVector6(TestHarness h, Provider prov) {
                        super(h, testAESKey, testHighBits, testPlainText, testExpectedCiphertext, prov);
                }
                protected String getDesc() {
                        return "AES Test Vector #6 (256 byte plaintext)";
                }
        }
        
        // 1024 byte plaintext
        /*
        Key: 23 1b a1 8a dc cb df 4d d6 ff 81 43 3a d1 c8 3a
        CTR: 8d e2 b9 e0 5b d6 f0 92
        Plaintext :
        8f 45 59 49 a3 21 1d 74 19 52 19 90 b4 91 a9 61 f0 ee 14 b6 09 9d 9b 80 ed 71 b6 31 9c 96 3d e0 3b 6c 67 2c 3b 81 0f c9
        f4 25 78 24 7d e7 1e a9 46 e5 a5 8c 6a fd 24 5d 95 05 89 2b 91 be e4 bb 0f ac 30 6c 91 89 cd 0d 1d c2 ce b6 24 64 6d 60
        ca 79 99 4d bc 20 d6 ae b1 18 1a e7 e7 54 56 06 7d 71 91 39 92 e1 d6 b0 91 fe f3 4b 6e e3 2f fa ed c9 0b 93 39 94 1a c6
        95 77 c9 23 75 81 6b ac ea 82 1c 5d 9c 4f 6c 57 ba a1 c0 68 5b fe 17 63 55 d5 7f e0 d2 82 af dd eb c9 a4 a6 69 d2 ca 0e
        cd f1 1e 37 ee 24 a2 cf c0 12 b5 a1 19 24 86 27 3b 7d a5 fc 97 29 44 43 b6 d7 df cf 56 6e 7e d1 84 0a 1b 31 6f 9b b9 0f
        5c 32 ed 2e 6d 6a 52 86 0a cf 36 da 38 94 1e e3 3a e4 fa bf a4 0c 43 bf 48 40 9e 11 11 e9 38 cf 24 47 cc f6 7b 42 d8 98
        9e 27 1f 32 07 ef 77 54 58 76 8a 83 df 2f 05 10 c7 60 4d 42 23 39 15 da 34 73 91 f9 90 4c fe 20 31 a4 ab f7 d1 d2 af 92
        32 71 05 1a 2d ca ab bd c6 0d 4c 1d 67 24 0e 89 c4 6f e7 d3 70 aa c7 33 f9 ab f0 bd fa 2f 57 85 d7 95 87 dc e4 cb 4d 65
        42 d0 14 7e 70 1b c4 58 69 60 af 76 0f a5 b2 71 72 d2 b2 33 c9 05 bc 6a 92 35 78 84 75 f8 f8 81 b5 d4 b8 a9 b6 c7 60 4c
        a9 e0 05 ed 46 4b 2b da 64 11 5a d7 42 09 be 8c 15 61 40 e9 f3 06 0e 15 ca 8b fc 50 cd 8f 36 19 a9 69 4b f5 1a 09 0d cc
        7b 15 bb dd 15 ec 7c 1b 81 fc 91 63 f2 16 18 5d 64 13 09 13 ae 55 a5 6c 25 82 56 71 6f 77 fa aa 7c 14 07 f3 3a 1c c1 35
        fb fd cf 0a 68 88 24 e5 d1 d1 50 ec 51 6a ea 47 5b bc b9 a9 80 0c bf bb ca 62 a1 e5 dc f1 a6 be 8a 97 89 a5 d8 59 a4 3c
        26 f1 7d 86 44 aa 97 d5 b7 e5 0b ed 3e 92 34 91 36 54 f5 0f c8 0a 91 61 ed 49 a6 b9 10 c9 ed 37 01 20 f1 4b 56 56 35 ce
        13 ea 34 0b e7 23 1a 5c 57 44 38 af 77 5a 06 46 1d 9f ae 5a 4a 44 1f 98 43 85 cc db de dd 79 e6 18 15 cd 07 d1 dc 3d 02
        23 c3 66 5a a2 9d 48 ad fc fd 84 ac 55 73 9e e5 2d eb 7b d3 8e 54 c1 c6 2a e2 74 21 03 36 d0 c7 72 51 ca 0f c7 d7 be 95
        78 b8 3a 2b 08 f8 35 ac 83 71 f1 ff 2a 10 83 df 99 a7 90 9d e1 b0 cf cc 80 1a 9b 47 a2 70 19 05 d8 71 e2 cb 8c 47 e6 78
        cc f6 89 d8 36 28 81 eb 68 41 ca b9 39 9a 90 46 93 a3 44 cc 1e 7d 01 8f 6f 81 5f 95 5b 78 89 41 d5 1d a9 9b 14 9b 5d 21
        ca 11 b6 b5 e0 fd 0c 6a 5f 95 e3 ab fd f0 5d 00 06 4c 25 1a 14 ea 59 38 c6 0f 63 00 42 ae 68 39 2d 7b 55 8c 9d 51 f9 db
        fe a6 f8 03 9d 64 98 0b b2 22 73 18 6c 4f 0e fb a0 5a e9 7e 2e f0 67 80 a2 28 53 be 0f b7 6b 6c 98 2f e2 b4 2d 32 c2 68
        f9 0b 40 c4 75 88 48 10 b0 fe c1 c6 82 82 16 c5 62 97 f2 59 6b 90 d4 36 b8 db 58 6c 46 4d 4d 4c eb 97 0c 8c cb 83 db 76
        88 ce dd e6 60 63 44 62 7e 69 f4 bd d2 13 99 43 b3 93 e4 95 47 3d 04 2f e3 ba b1 0b df 09 70 cf d9 b7 af 3d e0 aa c5 ef
        b9 fd d3 74 f1 89 47 4a 71 d6 be 30 de 8f ad 9f fa 32 c6 15 a3 fb 52 1a 46 38 91 04 70 4d bd e8 f4 0b 50 49 74 d9 9a c3
        34 6f d6 1b eb 94 f2 42 c7 be 37 be 07 53 1c 8d 83 65 39 b0 c5 18 b4 be 3e 11 4b cd 79 8b c1 c7 77 3e 83 68 60 94 04 92
        8d 4f 28 ee 1a ca a7 59 a5 b8 5d ba 8d 18 1c 87 84 64 7e 1e 59 fc 96 6c ab 84 eb 3a 9d 30 28 fa 03 0a 2c 60 d2 bf 81 21
        51 38 26 8d ac f0 70 b4 3a 3e c8 0a 2e 82 89 16 d4 bc 59 81 71 44 8b 14 ac 25 ac 18 26 9c f4 39 9c a8 b1 68 0c 0e 0e 35
        b1 45 e0 9b fc 86 94 39 3c d2 03 77 bc 98 37 75 09 be 73 40 4e 54 a5 0d
        Ciphertext:
        39 65 e4 02 78 3d 12 87 08 7d c3 4d c2 c2 28 8b 57 b6 29 9b 0a 07 9f 5a 8a 87 02 3f 50 e6 89 0e f3 3d 29 ed aa 2d cf 7c
        a3 af 36 3f 32 33 25 b5 2f 3f 57 c2 f0 48 c2 db 37 28 8e 7e ec 64 a3 52 05 e3 29 18 4b fc 77 84 03 e7 bf 0b 06 b7 81 3e
        b5 b3 28 c1 97 4a ec 00 02 82 d6 cc ab dd 18 a3 1e 24 b3 3e f1 f4 3a d8 6a ad 30 6f 3e f6 8c d0 f2 2b d7 61 fc 86 67 24
        e5 34 d2 ea fa 77 95 c1 c2 37 09 59 44 ae 8d 54 c7 ee 3c 17 26 19 07 f1 cd f3 8e cd 6b 4b 58 2d c1 95 7a a8 89 f3 97 1b
        9f 08 07 17 27 1d fe f8 f0 5c 20 86 55 7f 0d 81 03 3d 94 3a 2b 4b f4 d8 34 fe 2b 42 a6 3f ee 2c ba 14 a5 43 f6 80 a9 eb
        6b 1c d8 6e 88 82 6d 1a 0e 10 d6 3c 89 58 99 a8 47 62 a8 37 2b 9e df 2f 11 6d 01 6a 21 8e 2c c1 ac bd 58 3d 3c 8c b1 25
        4c ea ed 77 47 5b 46 34 ba c7 9f 89 15 67 ee d0 7f b1 29 79 88 d2 bb 55 66 4e ea c7 5b 66 14 39 5d 68 6c 42 6a 8c 15 f8
        8b e4 31 95 08 f2 6d 3e ba 83 07 a7 73 ff 2d aa d5 2a 10 1a 51 23 8f 32 19 34 cc ec 47 a6 3a f9 79 28 ff a7 c8 a2 ec 2a
        4d e1 d1 ae 4f e2 16 4c 33 15 25 13 0b 88 b3 c3 f9 b8 66 65 53 f1 10 d4 d7 40 6e 70 fe 9f 85 df a6 c0 c2 bc 8f 9a 53 0f
        8b fb 69 07 d2 79 2f 81 04 dc e5 89 15 d8 3e 6a 13 5b 3f 20 4e 4a 3e af cd bf bb 14 db 57 3a 72 c1 19 f2 e4 3c ef 59 33
        0a 60 b5 3e be e8 99 07 d6 1a 4f d7 f7 81 12 ff a2 86 f4 cd 45 3a 77 6e dc fd aa c6 ca e9 a0 bc b5 70 cf a4 39 c8 c1 e0
        d1 43 58 8d 09 2d 93 97 cf d6 3f a2 43 2e f0 24 ab 8c 1d 54 d5 ab ee 45 82 d9 b6 f3 78 8b bf b5 fe 7c 52 48 82 b2 40 ac
        55 35 59 79 89 33 89 6b 3f 10 a7 5e 8a 5d e2 51 7b 62 2a 71 59 2c 06 fd 7b 74 f8 ca f7 20 3e 69 97 cd f8 6d cb 30 17 31
        fc 24 7c be a3 35 87 7b d3 a9 2b 58 18 60 ef dc a8 51 f4 58 48 de ef c2 88 1a cb 49 3c de 58 88 a3 2f 2e 14 f3 a7 1b f1
        f5 0a e9 58 a7 ab 65 03 17 09 ed aa 5a 59 81 06 04 ec 22 80 53 ec 88 14 30 c5 40 bc c1 bc d6 4c 5d 29 de 50 9d a9 52 bf
        67 0b df 4c 8a fe 1f f2 03 a6 90 d9 34 6d 1a 31 b6 01 f5 51 58 5d 59 25 52 e2 20 d9 5d 9b 23 90 91 6a 3a 14 93 66 06 c9
        15 f7 a0 49 a3 ca d0 21 80 e8 e1 3b 31 ad 65 4f 68 db 3d a3 f5 9c 94 ed 97 15 d3 67 f8 27 1f c5 bf db 6a 7d bc 04 05 8a
        ee 90 b1 ae d1 88 12 04 f4 15 2b e6 04 5b 96 9f 89 a2 5a 1a c5 5f a6 1b 06 d4 5d 0a d5 82 90 4b a1 e9 4a fb 6c 78 8b 66
        6a 13 da fd 23 80 49 4d 4f 74 72 64 6a c8 3a 19 fe 6d 14 11 6f bf bf db 3d 4f dc 35 c5 64 2e be 39 af de 59 aa 82 56 88
        13 43 d9 10 56 33 d9 a4 c0 51 c4 85 f2 96 68 b3 4e 59 79 ce 3c 97 49 5b 1e 12 fc d1 2c 11 a7 79 b1 4a df cd e3 c1 a4 1f
        82 de 92 c0 b2 d5 87 04 01 cf ab 09 31 fe fc e9 b8 69 c5 b1 ab 73 1a 70 c1 94 92 6a bb 4c 12 ad 8a 7a 2b 63 51 43 15 c3
        c7 d9 1f 06 27 19 38 5e e3 14 12 23 0e 21 2f 68 33 4d e8 0f 57 d9 c1 6e 1e 27 20 0b cc 72 d2 1a a6 bb b4 e8 03 30 90 cf
        f5 2d 26 f9 c5 e1 7f 08 e9 36 ce 87 56 71 53 5c e1 bd a5 11 78 01 97 42 0b 78 27 db f7 14 2d 5b 58 4c 9a d4 28 1a df 59
        bb 6f 72 fb e9 cc 6a d2 e8 b9 e0 bd 90 fd 7c 6c bc c8 bd a9 37 4d 7c 82 19 5a 1a 24 3d 47 01 73 83 12 a3 b4 b7 de 14 e0
        54 1b d3 19 86 9a 90 de 05 fb 20 d8 b3 14 96 32 a9 27 5b 7a 2f bc 23 7f 7d 42 a6 ca a2 88 0b bb 74 2f b5 d4 2d 56 00 09
        67 6a e4 4f e9 12 ca 13 24 a0 05 fc f1 0c d0 9e c9 72 4f ab 1f 59 e6 03
         */
        private static class AESTestVector7 extends AESTestVector {
                static byte[] testAESKey = {
                        (byte)0x23, (byte)0x1b, (byte)0xa1, (byte)0x8a, (byte)0xdc, (byte)0xcb, (byte)0xdf, (byte)0x4d, 
                        (byte)0xd6, (byte)0xff, (byte)0x81, (byte)0x43, (byte)0x3a, (byte)0xd1, (byte)0xc8, (byte)0x3a, 
                };
                static byte[] testHighBits = {
                        (byte)0x8d, (byte)0xe2, (byte)0xb9, (byte)0xe0, (byte)0x5b, (byte)0xd6, (byte)0xf0, (byte)0x92,
                };
                static byte[] testPlainText = {
                        (byte)0x8f, (byte)0x45, (byte)0x59, (byte)0x49, (byte)0xa3, (byte)0x21, (byte)0x1d, (byte)0x74, 
                        (byte)0x19, (byte)0x52, (byte)0x19, (byte)0x90, (byte)0xb4, (byte)0x91, (byte)0xa9, (byte)0x61, 
                        (byte)0xf0, (byte)0xee, (byte)0x14, (byte)0xb6, (byte)0x09, (byte)0x9d, (byte)0x9b, (byte)0x80, 
                        (byte)0xed, (byte)0x71, (byte)0xb6, (byte)0x31, (byte)0x9c, (byte)0x96, (byte)0x3d, (byte)0xe0, 
                        (byte)0x3b, (byte)0x6c, (byte)0x67, (byte)0x2c, (byte)0x3b, (byte)0x81, (byte)0x0f, (byte)0xc9, 
                        (byte)0xf4, (byte)0x25, (byte)0x78, (byte)0x24, (byte)0x7d, (byte)0xe7, (byte)0x1e, (byte)0xa9, 
                        (byte)0x46, (byte)0xe5, (byte)0xa5, (byte)0x8c, (byte)0x6a, (byte)0xfd, (byte)0x24, (byte)0x5d, 
                        (byte)0x95, (byte)0x05, (byte)0x89, (byte)0x2b, (byte)0x91, (byte)0xbe, (byte)0xe4, (byte)0xbb, 
                        (byte)0x0f, (byte)0xac, (byte)0x30, (byte)0x6c, (byte)0x91, (byte)0x89, (byte)0xcd, (byte)0x0d, 
                        (byte)0x1d, (byte)0xc2, (byte)0xce, (byte)0xb6, (byte)0x24, (byte)0x64, (byte)0x6d, (byte)0x60, 
                        (byte)0xca, (byte)0x79, (byte)0x99, (byte)0x4d, (byte)0xbc, (byte)0x20, (byte)0xd6, (byte)0xae, 
                        (byte)0xb1, (byte)0x18, (byte)0x1a, (byte)0xe7, (byte)0xe7, (byte)0x54, (byte)0x56, (byte)0x06, 
                        (byte)0x7d, (byte)0x71, (byte)0x91, (byte)0x39, (byte)0x92, (byte)0xe1, (byte)0xd6, (byte)0xb0, 
                        (byte)0x91, (byte)0xfe, (byte)0xf3, (byte)0x4b, (byte)0x6e, (byte)0xe3, (byte)0x2f, (byte)0xfa, 
                        (byte)0xed, (byte)0xc9, (byte)0x0b, (byte)0x93, (byte)0x39, (byte)0x94, (byte)0x1a, (byte)0xc6, 
                        (byte)0x95, (byte)0x77, (byte)0xc9, (byte)0x23, (byte)0x75, (byte)0x81, (byte)0x6b, (byte)0xac, 
                        (byte)0xea, (byte)0x82, (byte)0x1c, (byte)0x5d, (byte)0x9c, (byte)0x4f, (byte)0x6c, (byte)0x57, 
                        (byte)0xba, (byte)0xa1, (byte)0xc0, (byte)0x68, (byte)0x5b, (byte)0xfe, (byte)0x17, (byte)0x63, 
                        (byte)0x55, (byte)0xd5, (byte)0x7f, (byte)0xe0, (byte)0xd2, (byte)0x82, (byte)0xaf, (byte)0xdd, 
                        (byte)0xeb, (byte)0xc9, (byte)0xa4, (byte)0xa6, (byte)0x69, (byte)0xd2, (byte)0xca, (byte)0x0e, 
                        (byte)0xcd, (byte)0xf1, (byte)0x1e, (byte)0x37, (byte)0xee, (byte)0x24, (byte)0xa2, (byte)0xcf, 
                        (byte)0xc0, (byte)0x12, (byte)0xb5, (byte)0xa1, (byte)0x19, (byte)0x24, (byte)0x86, (byte)0x27, 
                        (byte)0x3b, (byte)0x7d, (byte)0xa5, (byte)0xfc, (byte)0x97, (byte)0x29, (byte)0x44, (byte)0x43, 
                        (byte)0xb6, (byte)0xd7, (byte)0xdf, (byte)0xcf, (byte)0x56, (byte)0x6e, (byte)0x7e, (byte)0xd1, 
                        (byte)0x84, (byte)0x0a, (byte)0x1b, (byte)0x31, (byte)0x6f, (byte)0x9b, (byte)0xb9, (byte)0x0f, 
                        (byte)0x5c, (byte)0x32, (byte)0xed, (byte)0x2e, (byte)0x6d, (byte)0x6a, (byte)0x52, (byte)0x86, 
                        (byte)0x0a, (byte)0xcf, (byte)0x36, (byte)0xda, (byte)0x38, (byte)0x94, (byte)0x1e, (byte)0xe3, 
                        (byte)0x3a, (byte)0xe4, (byte)0xfa, (byte)0xbf, (byte)0xa4, (byte)0x0c, (byte)0x43, (byte)0xbf, 
                        (byte)0x48, (byte)0x40, (byte)0x9e, (byte)0x11, (byte)0x11, (byte)0xe9, (byte)0x38, (byte)0xcf, 
                        (byte)0x24, (byte)0x47, (byte)0xcc, (byte)0xf6, (byte)0x7b, (byte)0x42, (byte)0xd8, (byte)0x98, 
                        (byte)0x9e, (byte)0x27, (byte)0x1f, (byte)0x32, (byte)0x07, (byte)0xef, (byte)0x77, (byte)0x54, 
                        (byte)0x58, (byte)0x76, (byte)0x8a, (byte)0x83, (byte)0xdf, (byte)0x2f, (byte)0x05, (byte)0x10, 
                        (byte)0xc7, (byte)0x60, (byte)0x4d, (byte)0x42, (byte)0x23, (byte)0x39, (byte)0x15, (byte)0xda, 
                        (byte)0x34, (byte)0x73, (byte)0x91, (byte)0xf9, (byte)0x90, (byte)0x4c, (byte)0xfe, (byte)0x20, 
                        (byte)0x31, (byte)0xa4, (byte)0xab, (byte)0xf7, (byte)0xd1, (byte)0xd2, (byte)0xaf, (byte)0x92, 
                        (byte)0x32, (byte)0x71, (byte)0x05, (byte)0x1a, (byte)0x2d, (byte)0xca, (byte)0xab, (byte)0xbd, 
                        (byte)0xc6, (byte)0x0d, (byte)0x4c, (byte)0x1d, (byte)0x67, (byte)0x24, (byte)0x0e, (byte)0x89, 
                        (byte)0xc4, (byte)0x6f, (byte)0xe7, (byte)0xd3, (byte)0x70, (byte)0xaa, (byte)0xc7, (byte)0x33, 
                        (byte)0xf9, (byte)0xab, (byte)0xf0, (byte)0xbd, (byte)0xfa, (byte)0x2f, (byte)0x57, (byte)0x85, 
                        (byte)0xd7, (byte)0x95, (byte)0x87, (byte)0xdc, (byte)0xe4, (byte)0xcb, (byte)0x4d, (byte)0x65, 
                        (byte)0x42, (byte)0xd0, (byte)0x14, (byte)0x7e, (byte)0x70, (byte)0x1b, (byte)0xc4, (byte)0x58, 
                        (byte)0x69, (byte)0x60, (byte)0xaf, (byte)0x76, (byte)0x0f, (byte)0xa5, (byte)0xb2, (byte)0x71, 
                        (byte)0x72, (byte)0xd2, (byte)0xb2, (byte)0x33, (byte)0xc9, (byte)0x05, (byte)0xbc, (byte)0x6a, 
                        (byte)0x92, (byte)0x35, (byte)0x78, (byte)0x84, (byte)0x75, (byte)0xf8, (byte)0xf8, (byte)0x81, 
                        (byte)0xb5, (byte)0xd4, (byte)0xb8, (byte)0xa9, (byte)0xb6, (byte)0xc7, (byte)0x60, (byte)0x4c, 
                        (byte)0xa9, (byte)0xe0, (byte)0x05, (byte)0xed, (byte)0x46, (byte)0x4b, (byte)0x2b, (byte)0xda, 
                        (byte)0x64, (byte)0x11, (byte)0x5a, (byte)0xd7, (byte)0x42, (byte)0x09, (byte)0xbe, (byte)0x8c, 
                        (byte)0x15, (byte)0x61, (byte)0x40, (byte)0xe9, (byte)0xf3, (byte)0x06, (byte)0x0e, (byte)0x15, 
                        (byte)0xca, (byte)0x8b, (byte)0xfc, (byte)0x50, (byte)0xcd, (byte)0x8f, (byte)0x36, (byte)0x19, 
                        (byte)0xa9, (byte)0x69, (byte)0x4b, (byte)0xf5, (byte)0x1a, (byte)0x09, (byte)0x0d, (byte)0xcc, 
                        (byte)0x7b, (byte)0x15, (byte)0xbb, (byte)0xdd, (byte)0x15, (byte)0xec, (byte)0x7c, (byte)0x1b, 
                        (byte)0x81, (byte)0xfc, (byte)0x91, (byte)0x63, (byte)0xf2, (byte)0x16, (byte)0x18, (byte)0x5d, 
                        (byte)0x64, (byte)0x13, (byte)0x09, (byte)0x13, (byte)0xae, (byte)0x55, (byte)0xa5, (byte)0x6c, 
                        (byte)0x25, (byte)0x82, (byte)0x56, (byte)0x71, (byte)0x6f, (byte)0x77, (byte)0xfa, (byte)0xaa, 
                        (byte)0x7c, (byte)0x14, (byte)0x07, (byte)0xf3, (byte)0x3a, (byte)0x1c, (byte)0xc1, (byte)0x35, 
                        (byte)0xfb, (byte)0xfd, (byte)0xcf, (byte)0x0a, (byte)0x68, (byte)0x88, (byte)0x24, (byte)0xe5, 
                        (byte)0xd1, (byte)0xd1, (byte)0x50, (byte)0xec, (byte)0x51, (byte)0x6a, (byte)0xea, (byte)0x47, 
                        (byte)0x5b, (byte)0xbc, (byte)0xb9, (byte)0xa9, (byte)0x80, (byte)0x0c, (byte)0xbf, (byte)0xbb, 
                        (byte)0xca, (byte)0x62, (byte)0xa1, (byte)0xe5, (byte)0xdc, (byte)0xf1, (byte)0xa6, (byte)0xbe, 
                        (byte)0x8a, (byte)0x97, (byte)0x89, (byte)0xa5, (byte)0xd8, (byte)0x59, (byte)0xa4, (byte)0x3c, 
                        (byte)0x26, (byte)0xf1, (byte)0x7d, (byte)0x86, (byte)0x44, (byte)0xaa, (byte)0x97, (byte)0xd5, 
                        (byte)0xb7, (byte)0xe5, (byte)0x0b, (byte)0xed, (byte)0x3e, (byte)0x92, (byte)0x34, (byte)0x91, 
                        (byte)0x36, (byte)0x54, (byte)0xf5, (byte)0x0f, (byte)0xc8, (byte)0x0a, (byte)0x91, (byte)0x61, 
                        (byte)0xed, (byte)0x49, (byte)0xa6, (byte)0xb9, (byte)0x10, (byte)0xc9, (byte)0xed, (byte)0x37, 
                        (byte)0x01, (byte)0x20, (byte)0xf1, (byte)0x4b, (byte)0x56, (byte)0x56, (byte)0x35, (byte)0xce, 
                        (byte)0x13, (byte)0xea, (byte)0x34, (byte)0x0b, (byte)0xe7, (byte)0x23, (byte)0x1a, (byte)0x5c, 
                        (byte)0x57, (byte)0x44, (byte)0x38, (byte)0xaf, (byte)0x77, (byte)0x5a, (byte)0x06, (byte)0x46, 
                        (byte)0x1d, (byte)0x9f, (byte)0xae, (byte)0x5a, (byte)0x4a, (byte)0x44, (byte)0x1f, (byte)0x98, 
                        (byte)0x43, (byte)0x85, (byte)0xcc, (byte)0xdb, (byte)0xde, (byte)0xdd, (byte)0x79, (byte)0xe6, 
                        (byte)0x18, (byte)0x15, (byte)0xcd, (byte)0x07, (byte)0xd1, (byte)0xdc, (byte)0x3d, (byte)0x02, 
                        (byte)0x23, (byte)0xc3, (byte)0x66, (byte)0x5a, (byte)0xa2, (byte)0x9d, (byte)0x48, (byte)0xad, 
                        (byte)0xfc, (byte)0xfd, (byte)0x84, (byte)0xac, (byte)0x55, (byte)0x73, (byte)0x9e, (byte)0xe5, 
                        (byte)0x2d, (byte)0xeb, (byte)0x7b, (byte)0xd3, (byte)0x8e, (byte)0x54, (byte)0xc1, (byte)0xc6, 
                        (byte)0x2a, (byte)0xe2, (byte)0x74, (byte)0x21, (byte)0x03, (byte)0x36, (byte)0xd0, (byte)0xc7, 
                        (byte)0x72, (byte)0x51, (byte)0xca, (byte)0x0f, (byte)0xc7, (byte)0xd7, (byte)0xbe, (byte)0x95, 
                        (byte)0x78, (byte)0xb8, (byte)0x3a, (byte)0x2b, (byte)0x08, (byte)0xf8, (byte)0x35, (byte)0xac, 
                        (byte)0x83, (byte)0x71, (byte)0xf1, (byte)0xff, (byte)0x2a, (byte)0x10, (byte)0x83, (byte)0xdf, 
                        (byte)0x99, (byte)0xa7, (byte)0x90, (byte)0x9d, (byte)0xe1, (byte)0xb0, (byte)0xcf, (byte)0xcc, 
                        (byte)0x80, (byte)0x1a, (byte)0x9b, (byte)0x47, (byte)0xa2, (byte)0x70, (byte)0x19, (byte)0x05, 
                        (byte)0xd8, (byte)0x71, (byte)0xe2, (byte)0xcb, (byte)0x8c, (byte)0x47, (byte)0xe6, (byte)0x78, 
                        (byte)0xcc, (byte)0xf6, (byte)0x89, (byte)0xd8, (byte)0x36, (byte)0x28, (byte)0x81, (byte)0xeb, 
                        (byte)0x68, (byte)0x41, (byte)0xca, (byte)0xb9, (byte)0x39, (byte)0x9a, (byte)0x90, (byte)0x46, 
                        (byte)0x93, (byte)0xa3, (byte)0x44, (byte)0xcc, (byte)0x1e, (byte)0x7d, (byte)0x01, (byte)0x8f, 
                        (byte)0x6f, (byte)0x81, (byte)0x5f, (byte)0x95, (byte)0x5b, (byte)0x78, (byte)0x89, (byte)0x41, 
                        (byte)0xd5, (byte)0x1d, (byte)0xa9, (byte)0x9b, (byte)0x14, (byte)0x9b, (byte)0x5d, (byte)0x21, 
                        (byte)0xca, (byte)0x11, (byte)0xb6, (byte)0xb5, (byte)0xe0, (byte)0xfd, (byte)0x0c, (byte)0x6a, 
                        (byte)0x5f, (byte)0x95, (byte)0xe3, (byte)0xab, (byte)0xfd, (byte)0xf0, (byte)0x5d, (byte)0x00, 
                        (byte)0x06, (byte)0x4c, (byte)0x25, (byte)0x1a, (byte)0x14, (byte)0xea, (byte)0x59, (byte)0x38, 
                        (byte)0xc6, (byte)0x0f, (byte)0x63, (byte)0x00, (byte)0x42, (byte)0xae, (byte)0x68, (byte)0x39, 
                        (byte)0x2d, (byte)0x7b, (byte)0x55, (byte)0x8c, (byte)0x9d, (byte)0x51, (byte)0xf9, (byte)0xdb, 
                        (byte)0xfe, (byte)0xa6, (byte)0xf8, (byte)0x03, (byte)0x9d, (byte)0x64, (byte)0x98, (byte)0x0b, 
                        (byte)0xb2, (byte)0x22, (byte)0x73, (byte)0x18, (byte)0x6c, (byte)0x4f, (byte)0x0e, (byte)0xfb, 
                        (byte)0xa0, (byte)0x5a, (byte)0xe9, (byte)0x7e, (byte)0x2e, (byte)0xf0, (byte)0x67, (byte)0x80, 
                        (byte)0xa2, (byte)0x28, (byte)0x53, (byte)0xbe, (byte)0x0f, (byte)0xb7, (byte)0x6b, (byte)0x6c, 
                        (byte)0x98, (byte)0x2f, (byte)0xe2, (byte)0xb4, (byte)0x2d, (byte)0x32, (byte)0xc2, (byte)0x68, 
                        (byte)0xf9, (byte)0x0b, (byte)0x40, (byte)0xc4, (byte)0x75, (byte)0x88, (byte)0x48, (byte)0x10, 
                        (byte)0xb0, (byte)0xfe, (byte)0xc1, (byte)0xc6, (byte)0x82, (byte)0x82, (byte)0x16, (byte)0xc5, 
                        (byte)0x62, (byte)0x97, (byte)0xf2, (byte)0x59, (byte)0x6b, (byte)0x90, (byte)0xd4, (byte)0x36, 
                        (byte)0xb8, (byte)0xdb, (byte)0x58, (byte)0x6c, (byte)0x46, (byte)0x4d, (byte)0x4d, (byte)0x4c, 
                        (byte)0xeb, (byte)0x97, (byte)0x0c, (byte)0x8c, (byte)0xcb, (byte)0x83, (byte)0xdb, (byte)0x76, 
                        (byte)0x88, (byte)0xce, (byte)0xdd, (byte)0xe6, (byte)0x60, (byte)0x63, (byte)0x44, (byte)0x62, 
                        (byte)0x7e, (byte)0x69, (byte)0xf4, (byte)0xbd, (byte)0xd2, (byte)0x13, (byte)0x99, (byte)0x43, 
                        (byte)0xb3, (byte)0x93, (byte)0xe4, (byte)0x95, (byte)0x47, (byte)0x3d, (byte)0x04, (byte)0x2f, 
                        (byte)0xe3, (byte)0xba, (byte)0xb1, (byte)0x0b, (byte)0xdf, (byte)0x09, (byte)0x70, (byte)0xcf, 
                        (byte)0xd9, (byte)0xb7, (byte)0xaf, (byte)0x3d, (byte)0xe0, (byte)0xaa, (byte)0xc5, (byte)0xef, 
                        (byte)0xb9, (byte)0xfd, (byte)0xd3, (byte)0x74, (byte)0xf1, (byte)0x89, (byte)0x47, (byte)0x4a, 
                        (byte)0x71, (byte)0xd6, (byte)0xbe, (byte)0x30, (byte)0xde, (byte)0x8f, (byte)0xad, (byte)0x9f, 
                        (byte)0xfa, (byte)0x32, (byte)0xc6, (byte)0x15, (byte)0xa3, (byte)0xfb, (byte)0x52, (byte)0x1a, 
                        (byte)0x46, (byte)0x38, (byte)0x91, (byte)0x04, (byte)0x70, (byte)0x4d, (byte)0xbd, (byte)0xe8, 
                        (byte)0xf4, (byte)0x0b, (byte)0x50, (byte)0x49, (byte)0x74, (byte)0xd9, (byte)0x9a, (byte)0xc3, 
                        (byte)0x34, (byte)0x6f, (byte)0xd6, (byte)0x1b, (byte)0xeb, (byte)0x94, (byte)0xf2, (byte)0x42, 
                        (byte)0xc7, (byte)0xbe, (byte)0x37, (byte)0xbe, (byte)0x07, (byte)0x53, (byte)0x1c, (byte)0x8d, 
                        (byte)0x83, (byte)0x65, (byte)0x39, (byte)0xb0, (byte)0xc5, (byte)0x18, (byte)0xb4, (byte)0xbe, 
                        (byte)0x3e, (byte)0x11, (byte)0x4b, (byte)0xcd, (byte)0x79, (byte)0x8b, (byte)0xc1, (byte)0xc7, 
                        (byte)0x77, (byte)0x3e, (byte)0x83, (byte)0x68, (byte)0x60, (byte)0x94, (byte)0x04, (byte)0x92, 
                        (byte)0x8d, (byte)0x4f, (byte)0x28, (byte)0xee, (byte)0x1a, (byte)0xca, (byte)0xa7, (byte)0x59, 
                        (byte)0xa5, (byte)0xb8, (byte)0x5d, (byte)0xba, (byte)0x8d, (byte)0x18, (byte)0x1c, (byte)0x87, 
                        (byte)0x84, (byte)0x64, (byte)0x7e, (byte)0x1e, (byte)0x59, (byte)0xfc, (byte)0x96, (byte)0x6c, 
                        (byte)0xab, (byte)0x84, (byte)0xeb, (byte)0x3a, (byte)0x9d, (byte)0x30, (byte)0x28, (byte)0xfa, 
                        (byte)0x03, (byte)0x0a, (byte)0x2c, (byte)0x60, (byte)0xd2, (byte)0xbf, (byte)0x81, (byte)0x21, 
                        (byte)0x51, (byte)0x38, (byte)0x26, (byte)0x8d, (byte)0xac, (byte)0xf0, (byte)0x70, (byte)0xb4, 
                        (byte)0x3a, (byte)0x3e, (byte)0xc8, (byte)0x0a, (byte)0x2e, (byte)0x82, (byte)0x89, (byte)0x16, 
                        (byte)0xd4, (byte)0xbc, (byte)0x59, (byte)0x81, (byte)0x71, (byte)0x44, (byte)0x8b, (byte)0x14, 
                        (byte)0xac, (byte)0x25, (byte)0xac, (byte)0x18, (byte)0x26, (byte)0x9c, (byte)0xf4, (byte)0x39, 
                        (byte)0x9c, (byte)0xa8, (byte)0xb1, (byte)0x68, (byte)0x0c, (byte)0x0e, (byte)0x0e, (byte)0x35, 
                        (byte)0xb1, (byte)0x45, (byte)0xe0, (byte)0x9b, (byte)0xfc, (byte)0x86, (byte)0x94, (byte)0x39, 
                        (byte)0x3c, (byte)0xd2, (byte)0x03, (byte)0x77, (byte)0xbc, (byte)0x98, (byte)0x37, (byte)0x75, 
                        (byte)0x09, (byte)0xbe, (byte)0x73, (byte)0x40, (byte)0x4e, (byte)0x54, (byte)0xa5, (byte)0x0d,
                };
                static byte[] testExpectedCiphertext = {
                        (byte)0x39, (byte)0x65, (byte)0xe4, (byte)0x02, (byte)0x78, (byte)0x3d, (byte)0x12, (byte)0x87, 
                        (byte)0x08, (byte)0x7d, (byte)0xc3, (byte)0x4d, (byte)0xc2, (byte)0xc2, (byte)0x28, (byte)0x8b, 
                        (byte)0x57, (byte)0xb6, (byte)0x29, (byte)0x9b, (byte)0x0a, (byte)0x07, (byte)0x9f, (byte)0x5a, 
                        (byte)0x8a, (byte)0x87, (byte)0x02, (byte)0x3f, (byte)0x50, (byte)0xe6, (byte)0x89, (byte)0x0e, 
                        (byte)0xf3, (byte)0x3d, (byte)0x29, (byte)0xed, (byte)0xaa, (byte)0x2d, (byte)0xcf, (byte)0x7c, 
                        (byte)0xa3, (byte)0xaf, (byte)0x36, (byte)0x3f, (byte)0x32, (byte)0x33, (byte)0x25, (byte)0xb5, 
                        (byte)0x2f, (byte)0x3f, (byte)0x57, (byte)0xc2, (byte)0xf0, (byte)0x48, (byte)0xc2, (byte)0xdb, 
                        (byte)0x37, (byte)0x28, (byte)0x8e, (byte)0x7e, (byte)0xec, (byte)0x64, (byte)0xa3, (byte)0x52, 
                        (byte)0x05, (byte)0xe3, (byte)0x29, (byte)0x18, (byte)0x4b, (byte)0xfc, (byte)0x77, (byte)0x84, 
                        (byte)0x03, (byte)0xe7, (byte)0xbf, (byte)0x0b, (byte)0x06, (byte)0xb7, (byte)0x81, (byte)0x3e, 
                        (byte)0xb5, (byte)0xb3, (byte)0x28, (byte)0xc1, (byte)0x97, (byte)0x4a, (byte)0xec, (byte)0x00, 
                        (byte)0x02, (byte)0x82, (byte)0xd6, (byte)0xcc, (byte)0xab, (byte)0xdd, (byte)0x18, (byte)0xa3, 
                        (byte)0x1e, (byte)0x24, (byte)0xb3, (byte)0x3e, (byte)0xf1, (byte)0xf4, (byte)0x3a, (byte)0xd8, 
                        (byte)0x6a, (byte)0xad, (byte)0x30, (byte)0x6f, (byte)0x3e, (byte)0xf6, (byte)0x8c, (byte)0xd0, 
                        (byte)0xf2, (byte)0x2b, (byte)0xd7, (byte)0x61, (byte)0xfc, (byte)0x86, (byte)0x67, (byte)0x24, 
                        (byte)0xe5, (byte)0x34, (byte)0xd2, (byte)0xea, (byte)0xfa, (byte)0x77, (byte)0x95, (byte)0xc1, 
                        (byte)0xc2, (byte)0x37, (byte)0x09, (byte)0x59, (byte)0x44, (byte)0xae, (byte)0x8d, (byte)0x54, 
                        (byte)0xc7, (byte)0xee, (byte)0x3c, (byte)0x17, (byte)0x26, (byte)0x19, (byte)0x07, (byte)0xf1, 
                        (byte)0xcd, (byte)0xf3, (byte)0x8e, (byte)0xcd, (byte)0x6b, (byte)0x4b, (byte)0x58, (byte)0x2d, 
                        (byte)0xc1, (byte)0x95, (byte)0x7a, (byte)0xa8, (byte)0x89, (byte)0xf3, (byte)0x97, (byte)0x1b, 
                        (byte)0x9f, (byte)0x08, (byte)0x07, (byte)0x17, (byte)0x27, (byte)0x1d, (byte)0xfe, (byte)0xf8, 
                        (byte)0xf0, (byte)0x5c, (byte)0x20, (byte)0x86, (byte)0x55, (byte)0x7f, (byte)0x0d, (byte)0x81, 
                        (byte)0x03, (byte)0x3d, (byte)0x94, (byte)0x3a, (byte)0x2b, (byte)0x4b, (byte)0xf4, (byte)0xd8, 
                        (byte)0x34, (byte)0xfe, (byte)0x2b, (byte)0x42, (byte)0xa6, (byte)0x3f, (byte)0xee, (byte)0x2c, 
                        (byte)0xba, (byte)0x14, (byte)0xa5, (byte)0x43, (byte)0xf6, (byte)0x80, (byte)0xa9, (byte)0xeb, 
                        (byte)0x6b, (byte)0x1c, (byte)0xd8, (byte)0x6e, (byte)0x88, (byte)0x82, (byte)0x6d, (byte)0x1a, 
                        (byte)0x0e, (byte)0x10, (byte)0xd6, (byte)0x3c, (byte)0x89, (byte)0x58, (byte)0x99, (byte)0xa8, 
                        (byte)0x47, (byte)0x62, (byte)0xa8, (byte)0x37, (byte)0x2b, (byte)0x9e, (byte)0xdf, (byte)0x2f, 
                        (byte)0x11, (byte)0x6d, (byte)0x01, (byte)0x6a, (byte)0x21, (byte)0x8e, (byte)0x2c, (byte)0xc1, 
                        (byte)0xac, (byte)0xbd, (byte)0x58, (byte)0x3d, (byte)0x3c, (byte)0x8c, (byte)0xb1, (byte)0x25, 
                        (byte)0x4c, (byte)0xea, (byte)0xed, (byte)0x77, (byte)0x47, (byte)0x5b, (byte)0x46, (byte)0x34, 
                        (byte)0xba, (byte)0xc7, (byte)0x9f, (byte)0x89, (byte)0x15, (byte)0x67, (byte)0xee, (byte)0xd0, 
                        (byte)0x7f, (byte)0xb1, (byte)0x29, (byte)0x79, (byte)0x88, (byte)0xd2, (byte)0xbb, (byte)0x55, 
                        (byte)0x66, (byte)0x4e, (byte)0xea, (byte)0xc7, (byte)0x5b, (byte)0x66, (byte)0x14, (byte)0x39, 
                        (byte)0x5d, (byte)0x68, (byte)0x6c, (byte)0x42, (byte)0x6a, (byte)0x8c, (byte)0x15, (byte)0xf8, 
                        (byte)0x8b, (byte)0xe4, (byte)0x31, (byte)0x95, (byte)0x08, (byte)0xf2, (byte)0x6d, (byte)0x3e, 
                        (byte)0xba, (byte)0x83, (byte)0x07, (byte)0xa7, (byte)0x73, (byte)0xff, (byte)0x2d, (byte)0xaa, 
                        (byte)0xd5, (byte)0x2a, (byte)0x10, (byte)0x1a, (byte)0x51, (byte)0x23, (byte)0x8f, (byte)0x32, 
                        (byte)0x19, (byte)0x34, (byte)0xcc, (byte)0xec, (byte)0x47, (byte)0xa6, (byte)0x3a, (byte)0xf9, 
                        (byte)0x79, (byte)0x28, (byte)0xff, (byte)0xa7, (byte)0xc8, (byte)0xa2, (byte)0xec, (byte)0x2a, 
                        (byte)0x4d, (byte)0xe1, (byte)0xd1, (byte)0xae, (byte)0x4f, (byte)0xe2, (byte)0x16, (byte)0x4c, 
                        (byte)0x33, (byte)0x15, (byte)0x25, (byte)0x13, (byte)0x0b, (byte)0x88, (byte)0xb3, (byte)0xc3, 
                        (byte)0xf9, (byte)0xb8, (byte)0x66, (byte)0x65, (byte)0x53, (byte)0xf1, (byte)0x10, (byte)0xd4, 
                        (byte)0xd7, (byte)0x40, (byte)0x6e, (byte)0x70, (byte)0xfe, (byte)0x9f, (byte)0x85, (byte)0xdf, 
                        (byte)0xa6, (byte)0xc0, (byte)0xc2, (byte)0xbc, (byte)0x8f, (byte)0x9a, (byte)0x53, (byte)0x0f, 
                        (byte)0x8b, (byte)0xfb, (byte)0x69, (byte)0x07, (byte)0xd2, (byte)0x79, (byte)0x2f, (byte)0x81, 
                        (byte)0x04, (byte)0xdc, (byte)0xe5, (byte)0x89, (byte)0x15, (byte)0xd8, (byte)0x3e, (byte)0x6a, 
                        (byte)0x13, (byte)0x5b, (byte)0x3f, (byte)0x20, (byte)0x4e, (byte)0x4a, (byte)0x3e, (byte)0xaf, 
                        (byte)0xcd, (byte)0xbf, (byte)0xbb, (byte)0x14, (byte)0xdb, (byte)0x57, (byte)0x3a, (byte)0x72, 
                        (byte)0xc1, (byte)0x19, (byte)0xf2, (byte)0xe4, (byte)0x3c, (byte)0xef, (byte)0x59, (byte)0x33, 
                        (byte)0x0a, (byte)0x60, (byte)0xb5, (byte)0x3e, (byte)0xbe, (byte)0xe8, (byte)0x99, (byte)0x07, 
                        (byte)0xd6, (byte)0x1a, (byte)0x4f, (byte)0xd7, (byte)0xf7, (byte)0x81, (byte)0x12, (byte)0xff, 
                        (byte)0xa2, (byte)0x86, (byte)0xf4, (byte)0xcd, (byte)0x45, (byte)0x3a, (byte)0x77, (byte)0x6e, 
                        (byte)0xdc, (byte)0xfd, (byte)0xaa, (byte)0xc6, (byte)0xca, (byte)0xe9, (byte)0xa0, (byte)0xbc, 
                        (byte)0xb5, (byte)0x70, (byte)0xcf, (byte)0xa4, (byte)0x39, (byte)0xc8, (byte)0xc1, (byte)0xe0, 
                        (byte)0xd1, (byte)0x43, (byte)0x58, (byte)0x8d, (byte)0x09, (byte)0x2d, (byte)0x93, (byte)0x97, 
                        (byte)0xcf, (byte)0xd6, (byte)0x3f, (byte)0xa2, (byte)0x43, (byte)0x2e, (byte)0xf0, (byte)0x24, 
                        (byte)0xab, (byte)0x8c, (byte)0x1d, (byte)0x54, (byte)0xd5, (byte)0xab, (byte)0xee, (byte)0x45, 
                        (byte)0x82, (byte)0xd9, (byte)0xb6, (byte)0xf3, (byte)0x78, (byte)0x8b, (byte)0xbf, (byte)0xb5, 
                        (byte)0xfe, (byte)0x7c, (byte)0x52, (byte)0x48, (byte)0x82, (byte)0xb2, (byte)0x40, (byte)0xac, 
                        (byte)0x55, (byte)0x35, (byte)0x59, (byte)0x79, (byte)0x89, (byte)0x33, (byte)0x89, (byte)0x6b, 
                        (byte)0x3f, (byte)0x10, (byte)0xa7, (byte)0x5e, (byte)0x8a, (byte)0x5d, (byte)0xe2, (byte)0x51, 
                        (byte)0x7b, (byte)0x62, (byte)0x2a, (byte)0x71, (byte)0x59, (byte)0x2c, (byte)0x06, (byte)0xfd, 
                        (byte)0x7b, (byte)0x74, (byte)0xf8, (byte)0xca, (byte)0xf7, (byte)0x20, (byte)0x3e, (byte)0x69, 
                        (byte)0x97, (byte)0xcd, (byte)0xf8, (byte)0x6d, (byte)0xcb, (byte)0x30, (byte)0x17, (byte)0x31, 
                        (byte)0xfc, (byte)0x24, (byte)0x7c, (byte)0xbe, (byte)0xa3, (byte)0x35, (byte)0x87, (byte)0x7b, 
                        (byte)0xd3, (byte)0xa9, (byte)0x2b, (byte)0x58, (byte)0x18, (byte)0x60, (byte)0xef, (byte)0xdc, 
                        (byte)0xa8, (byte)0x51, (byte)0xf4, (byte)0x58, (byte)0x48, (byte)0xde, (byte)0xef, (byte)0xc2, 
                        (byte)0x88, (byte)0x1a, (byte)0xcb, (byte)0x49, (byte)0x3c, (byte)0xde, (byte)0x58, (byte)0x88, 
                        (byte)0xa3, (byte)0x2f, (byte)0x2e, (byte)0x14, (byte)0xf3, (byte)0xa7, (byte)0x1b, (byte)0xf1, 
                        (byte)0xf5, (byte)0x0a, (byte)0xe9, (byte)0x58, (byte)0xa7, (byte)0xab, (byte)0x65, (byte)0x03, 
                        (byte)0x17, (byte)0x09, (byte)0xed, (byte)0xaa, (byte)0x5a, (byte)0x59, (byte)0x81, (byte)0x06, 
                        (byte)0x04, (byte)0xec, (byte)0x22, (byte)0x80, (byte)0x53, (byte)0xec, (byte)0x88, (byte)0x14, 
                        (byte)0x30, (byte)0xc5, (byte)0x40, (byte)0xbc, (byte)0xc1, (byte)0xbc, (byte)0xd6, (byte)0x4c, 
                        (byte)0x5d, (byte)0x29, (byte)0xde, (byte)0x50, (byte)0x9d, (byte)0xa9, (byte)0x52, (byte)0xbf, 
                        (byte)0x67, (byte)0x0b, (byte)0xdf, (byte)0x4c, (byte)0x8a, (byte)0xfe, (byte)0x1f, (byte)0xf2, 
                        (byte)0x03, (byte)0xa6, (byte)0x90, (byte)0xd9, (byte)0x34, (byte)0x6d, (byte)0x1a, (byte)0x31, 
                        (byte)0xb6, (byte)0x01, (byte)0xf5, (byte)0x51, (byte)0x58, (byte)0x5d, (byte)0x59, (byte)0x25, 
                        (byte)0x52, (byte)0xe2, (byte)0x20, (byte)0xd9, (byte)0x5d, (byte)0x9b, (byte)0x23, (byte)0x90, 
                        (byte)0x91, (byte)0x6a, (byte)0x3a, (byte)0x14, (byte)0x93, (byte)0x66, (byte)0x06, (byte)0xc9, 
                        (byte)0x15, (byte)0xf7, (byte)0xa0, (byte)0x49, (byte)0xa3, (byte)0xca, (byte)0xd0, (byte)0x21, 
                        (byte)0x80, (byte)0xe8, (byte)0xe1, (byte)0x3b, (byte)0x31, (byte)0xad, (byte)0x65, (byte)0x4f, 
                        (byte)0x68, (byte)0xdb, (byte)0x3d, (byte)0xa3, (byte)0xf5, (byte)0x9c, (byte)0x94, (byte)0xed, 
                        (byte)0x97, (byte)0x15, (byte)0xd3, (byte)0x67, (byte)0xf8, (byte)0x27, (byte)0x1f, (byte)0xc5, 
                        (byte)0xbf, (byte)0xdb, (byte)0x6a, (byte)0x7d, (byte)0xbc, (byte)0x04, (byte)0x05, (byte)0x8a, 
                        (byte)0xee, (byte)0x90, (byte)0xb1, (byte)0xae, (byte)0xd1, (byte)0x88, (byte)0x12, (byte)0x04, 
                        (byte)0xf4, (byte)0x15, (byte)0x2b, (byte)0xe6, (byte)0x04, (byte)0x5b, (byte)0x96, (byte)0x9f, 
                        (byte)0x89, (byte)0xa2, (byte)0x5a, (byte)0x1a, (byte)0xc5, (byte)0x5f, (byte)0xa6, (byte)0x1b, 
                        (byte)0x06, (byte)0xd4, (byte)0x5d, (byte)0x0a, (byte)0xd5, (byte)0x82, (byte)0x90, (byte)0x4b, 
                        (byte)0xa1, (byte)0xe9, (byte)0x4a, (byte)0xfb, (byte)0x6c, (byte)0x78, (byte)0x8b, (byte)0x66, 
                        (byte)0x6a, (byte)0x13, (byte)0xda, (byte)0xfd, (byte)0x23, (byte)0x80, (byte)0x49, (byte)0x4d, 
                        (byte)0x4f, (byte)0x74, (byte)0x72, (byte)0x64, (byte)0x6a, (byte)0xc8, (byte)0x3a, (byte)0x19, 
                        (byte)0xfe, (byte)0x6d, (byte)0x14, (byte)0x11, (byte)0x6f, (byte)0xbf, (byte)0xbf, (byte)0xdb, 
                        (byte)0x3d, (byte)0x4f, (byte)0xdc, (byte)0x35, (byte)0xc5, (byte)0x64, (byte)0x2e, (byte)0xbe, 
                        (byte)0x39, (byte)0xaf, (byte)0xde, (byte)0x59, (byte)0xaa, (byte)0x82, (byte)0x56, (byte)0x88, 
                        (byte)0x13, (byte)0x43, (byte)0xd9, (byte)0x10, (byte)0x56, (byte)0x33, (byte)0xd9, (byte)0xa4, 
                        (byte)0xc0, (byte)0x51, (byte)0xc4, (byte)0x85, (byte)0xf2, (byte)0x96, (byte)0x68, (byte)0xb3, 
                        (byte)0x4e, (byte)0x59, (byte)0x79, (byte)0xce, (byte)0x3c, (byte)0x97, (byte)0x49, (byte)0x5b, 
                        (byte)0x1e, (byte)0x12, (byte)0xfc, (byte)0xd1, (byte)0x2c, (byte)0x11, (byte)0xa7, (byte)0x79, 
                        (byte)0xb1, (byte)0x4a, (byte)0xdf, (byte)0xcd, (byte)0xe3, (byte)0xc1, (byte)0xa4, (byte)0x1f, 
                        (byte)0x82, (byte)0xde, (byte)0x92, (byte)0xc0, (byte)0xb2, (byte)0xd5, (byte)0x87, (byte)0x04, 
                        (byte)0x01, (byte)0xcf, (byte)0xab, (byte)0x09, (byte)0x31, (byte)0xfe, (byte)0xfc, (byte)0xe9, 
                        (byte)0xb8, (byte)0x69, (byte)0xc5, (byte)0xb1, (byte)0xab, (byte)0x73, (byte)0x1a, (byte)0x70, 
                        (byte)0xc1, (byte)0x94, (byte)0x92, (byte)0x6a, (byte)0xbb, (byte)0x4c, (byte)0x12, (byte)0xad, 
                        (byte)0x8a, (byte)0x7a, (byte)0x2b, (byte)0x63, (byte)0x51, (byte)0x43, (byte)0x15, (byte)0xc3, 
                        (byte)0xc7, (byte)0xd9, (byte)0x1f, (byte)0x06, (byte)0x27, (byte)0x19, (byte)0x38, (byte)0x5e, 
                        (byte)0xe3, (byte)0x14, (byte)0x12, (byte)0x23, (byte)0x0e, (byte)0x21, (byte)0x2f, (byte)0x68, 
                        (byte)0x33, (byte)0x4d, (byte)0xe8, (byte)0x0f, (byte)0x57, (byte)0xd9, (byte)0xc1, (byte)0x6e, 
                        (byte)0x1e, (byte)0x27, (byte)0x20, (byte)0x0b, (byte)0xcc, (byte)0x72, (byte)0xd2, (byte)0x1a, 
                        (byte)0xa6, (byte)0xbb, (byte)0xb4, (byte)0xe8, (byte)0x03, (byte)0x30, (byte)0x90, (byte)0xcf, 
                        (byte)0xf5, (byte)0x2d, (byte)0x26, (byte)0xf9, (byte)0xc5, (byte)0xe1, (byte)0x7f, (byte)0x08, 
                        (byte)0xe9, (byte)0x36, (byte)0xce, (byte)0x87, (byte)0x56, (byte)0x71, (byte)0x53, (byte)0x5c, 
                        (byte)0xe1, (byte)0xbd, (byte)0xa5, (byte)0x11, (byte)0x78, (byte)0x01, (byte)0x97, (byte)0x42, 
                        (byte)0x0b, (byte)0x78, (byte)0x27, (byte)0xdb, (byte)0xf7, (byte)0x14, (byte)0x2d, (byte)0x5b, 
                        (byte)0x58, (byte)0x4c, (byte)0x9a, (byte)0xd4, (byte)0x28, (byte)0x1a, (byte)0xdf, (byte)0x59, 
                        (byte)0xbb, (byte)0x6f, (byte)0x72, (byte)0xfb, (byte)0xe9, (byte)0xcc, (byte)0x6a, (byte)0xd2, 
                        (byte)0xe8, (byte)0xb9, (byte)0xe0, (byte)0xbd, (byte)0x90, (byte)0xfd, (byte)0x7c, (byte)0x6c, 
                        (byte)0xbc, (byte)0xc8, (byte)0xbd, (byte)0xa9, (byte)0x37, (byte)0x4d, (byte)0x7c, (byte)0x82, 
                        (byte)0x19, (byte)0x5a, (byte)0x1a, (byte)0x24, (byte)0x3d, (byte)0x47, (byte)0x01, (byte)0x73, 
                        (byte)0x83, (byte)0x12, (byte)0xa3, (byte)0xb4, (byte)0xb7, (byte)0xde, (byte)0x14, (byte)0xe0, 
                        (byte)0x54, (byte)0x1b, (byte)0xd3, (byte)0x19, (byte)0x86, (byte)0x9a, (byte)0x90, (byte)0xde, 
                        (byte)0x05, (byte)0xfb, (byte)0x20, (byte)0xd8, (byte)0xb3, (byte)0x14, (byte)0x96, (byte)0x32, 
                        (byte)0xa9, (byte)0x27, (byte)0x5b, (byte)0x7a, (byte)0x2f, (byte)0xbc, (byte)0x23, (byte)0x7f, 
                        (byte)0x7d, (byte)0x42, (byte)0xa6, (byte)0xca, (byte)0xa2, (byte)0x88, (byte)0x0b, (byte)0xbb, 
                        (byte)0x74, (byte)0x2f, (byte)0xb5, (byte)0xd4, (byte)0x2d, (byte)0x56, (byte)0x00, (byte)0x09, 
                        (byte)0x67, (byte)0x6a, (byte)0xe4, (byte)0x4f, (byte)0xe9, (byte)0x12, (byte)0xca, (byte)0x13, 
                        (byte)0x24, (byte)0xa0, (byte)0x05, (byte)0xfc, (byte)0xf1, (byte)0x0c, (byte)0xd0, (byte)0x9e, 
                        (byte)0xc9, (byte)0x72, (byte)0x4f, (byte)0xab, (byte)0x1f, (byte)0x59, (byte)0xe6, (byte)0x03,
                };
                public AESTestVector7(TestHarness h, Provider prov) {
                        super(h, testAESKey, testHighBits, testPlainText, testExpectedCiphertext, prov);
                }
                protected String getDesc() {
                        return "AES Test Vector #7 (1024 byte plaintext)";
                }
        }
        
        // 1031-byte plaintext
        /*
        Key: 18 36 02 78 d6 15 be 45 15 65 9f d8 6c ab fb ba
        CTR: 1a 97 c2 c4 23 9f 73 4f
        Plaintext :
        a8 fc b4 fd cf 40 f4 a9 8b a7 64 32 19 ef df eb 99 36 fc 00 49 2b c3 e1 bb 6a 0b 74 a1 3f eb cc 
        f9 7b 4c b5 cd 5a 7f 36 be 0b 74 63 7e 26 37 ad 2d 18 90 83 e2 25 9a e6 dd d1 93 41 47 14 45 2c 
        f0 24 6e 5d a7 8a 03 37 1f d5 f4 a5 0a 5b 8b 6c d4 ac 15 d3 be f7 75 34 7b 41 1a a2 7d e1 8b 32 
        83 42 bd 15 44 1b a0 15 32 d8 45 a5 f8 e7 7e a6 da bc 7b cb d7 1e 58 92 3d 88 39 52 59 f7 15 fe 
        ea d8 41 e6 43 d6 37 71 44 99 b2 16 ae 67 8a ff 43 5b 9b a7 8d 42 32 40 57 9a 0f 0a ce d8 dd 4d 
        ce aa 1d b9 11 5a e0 3c d7 5a 85 06 29 9e 5a 94 e6 b8 b7 89 1f cd cf 3b bb c5 68 d8 0f 0a 22 2d 
        e6 c4 ef 6b 90 3e 8a 1f 89 de 49 b9 eb 95 e1 64 6e 59 5e a4 61 83 83 86 b9 06 d5 dc f0 c2 a3 d5 
        db 98 63 21 53 4a 80 91 a0 12 c7 ee f5 39 85 40 3e 08 d0 04 2c be 4a 55 f4 a9 17 0e 79 9f 21 64 
        37 6d 23 f3 13 4c c0 ca a4 d1 f7 f9 5c be 87 8f 72 34 20 cd 4d e5 76 39 6c 61 15 6e 97 61 42 88 
        ae 74 30 b2 fb d9 b5 aa cc 28 9d d3 e2 ef 01 cc 2a 51 06 95 4f cb 91 95 6d a7 9f fd 00 7e 19 b0 
        39 81 f1 b5 19 7d 3d cb 02 1b d8 5f e9 7f c8 5e 65 5f 5c a8 49 d7 c0 9b b9 e4 7d 6c dd 0e 54 c9 
        41 4d 0d 89 61 64 bc 6b aa 1d 08 f0 bd 68 c5 f1 8b 51 4e 40 16 60 e4 66 5a 25 3b 80 90 86 86 1d 
        9a 44 71 f8 58 80 16 12 26 64 24 a8 50 85 23 d3 64 78 78 43 ef a5 13 b2 6d b8 9c 67 ee 15 e4 71 
        25 d5 a9 79 02 8b 8a ff a7 4c 2d 1d a2 8a 7d e6 98 a1 ef 8f c6 ee 67 df 6e 97 51 8f da d5 b2 1e 
        04 a7 ce 78 e6 c8 93 3a 0e 33 a2 fc 8a 5a 55 70 b9 8e 3b 54 ff 23 e9 7f de 6d 74 e5 8f 2b f3 f0 
        9c 69 10 4b ac 5e e0 b2 60 fa 12 39 9b ff e4 d7 a5 ce 0d 59 92 b0 ec 47 f7 40 eb d3 22 c4 99 28 
        ed 08 ce 25 b5 b9 21 37 60 a7 d4 8c ad c0 b2 9a e8 4e ad da 71 ab 30 a7 e3 75 52 ed 0e 11 c1 18 
        f5 14 96 74 2f 40 50 28 35 13 29 2a 64 a5 d4 b4 10 3a 9e 10 81 e8 c0 73 8a ac da 44 cb e5 91 01 
        86 9b ee 9b 11 74 29 8e 0e db 91 41 0a e8 af c7 ca 81 16 1d ca d8 1c 82 d8 18 7c 60 07 54 f1 24 
        ef d6 fe 6e 44 7d 00 39 ea af a0 99 cc 84 3b 45 1e a4 13 cc fc a7 53 9b 77 cb ff 01 13 b2 79 62 
        51 15 0e 90 fc 00 17 57 b7 41 2a 16 a8 26 a1 aa 52 74 58 d5 03 8d 23 9a c8 6e 78 b2 39 34 1a 0d 
        fa 3c 65 d7 da 93 2b 67 89 5b 39 2f 5b ed bc 60 0e 2a f2 6a ab d2 40 de 09 b7 f8 14 71 de 8f 67 
        99 5e 75 4e a8 66 06 be 88 08 6d 21 b2 61 75 26 66 c3 39 95 1d 24 36 39 48 4a 45 7d b4 98 97 8b 
        85 dc a2 7e 88 a9 93 1d a8 00 4e 41 9c 55 ac 55 3c e8 ec b5 f8 f1 ea 03 32 ac ed 73 29 ce 56 95 
        3b 60 b8 a0 81 c9 5b e9 8a 41 29 93 9e 88 19 21 98 f1 76 67 2e 64 77 15 db 01 c0 13 da bb 09 6e 
        aa 3f 4b 9f c0 0f c2 70 df ad d3 b3 0f e9 a3 11 a0 6a c5 09 89 d6 ce d4 30 03 06 92 6c f8 7b ad 
        fa 5c 09 bf 4f 45 6c 30 6b b1 f7 31 69 91 a4 d2 4f 4a 2b 71 81 4f 63 28 3d 49 94 cb 1b 01 df 6a 
        a8 b8 54 8d b5 f2 42 98 1b aa 90 82 ff 0f fe 0e 00 61 9c 44 0a bd e5 83 2d 65 ad 67 26 85 1c 68 
        8d 2f 6c f8 d0 33 f9 54 f6 f3 a0 9c e4 5c 4d 1f f4 5e b3 f7 53 c1 4c a1 05 f6 27 a7 70 77 72 2c 
        81 6e 8d 13 68 3d 1d c6 ba b9 32 22 f8 7c 5a ca a4 0f 25 16 b6 a8 73 e1 b2 61 d6 d1 3f c3 0d 28 
        da f2 d7 e3 ba fe 12 9b ff 42 35 99 5e 9f d9 f1 6e fe ec 0b 3d 7e 02 d5 4f 6a cb c2 d6 47 11 8d 
        0f 4b 16 75 1c 66 c2 0f 41 d1 59 7c 10 ae 6b 5c e8 a5 7d 58 99 28 99 91 3a 44 20 1f f1 02 06 95 
        38 e1 a2 5b 1a 50 30
        Ciphertext:
        fe 8c 1f 41 19 b2 7b 95 79 54 cf 97 e1 e3 1d b4 29 1e e6 02 cb 08 2e 52 1c b8 78 0e cb a0 83 2c 
        a3 d9 55 eb 1d dc eb 0e 1b 1d b2 a5 2c 44 c2 bf 55 33 52 f7 5c 28 47 7e d5 c2 e2 87 05 c1 4c 5b 
        81 25 3c 23 63 08 58 79 27 e1 1e 45 fa e8 48 fb 73 95 bc 10 f7 c6 70 d0 78 d6 47 ea 81 d3 46 d6 
        bd 3f 72 eb 38 03 ea 58 e7 15 40 ca 3a de 77 d7 33 0e e1 fc 35 44 eb 6b e3 f4 47 f1 5a bb 79 62 
        ce 49 13 75 c6 82 b4 88 6d 7f 0e 8d f8 6d d6 74 89 5d 46 00 f9 50 98 96 1d a1 28 62 bb cd 92 63 
        7f c7 b4 78 ce 13 14 86 e3 f6 a1 b0 8c 22 80 ba 11 93 2e 83 17 af 9d 64 68 6e 79 92 8b 2e 15 b9 
        72 49 10 c3 3d b0 88 e7 25 28 9b 28 eb 61 94 35 36 84 da 81 9f a9 45 4d eb 7e b0 cf 47 5f 6a 76 
        f9 0a f4 91 ca b7 18 7e 51 6b e4 03 38 83 66 c4 af 58 89 35 92 a3 33 2b 69 e8 8e a7 46 34 53 6d 
        1e ac 56 fa 3a ae e8 cf f9 85 b9 46 d9 0b 17 71 21 e6 96 80 bc 5c 4d 0d 45 99 bc 92 81 a2 ea 7c 
        08 93 a4 8e 30 01 f9 01 28 81 d3 62 78 d1 2c 8d dd da ae 40 4f a4 52 88 f9 c0 64 9c 0c dd a7 ec 
        eb 32 16 86 09 9e ea fc 8d a7 df 41 7c f6 61 60 d0 40 50 ac 1e 24 30 16 dc 23 30 93 bd bb 8d ca 
        4f 94 fc 5e 68 37 b3 0e 34 df 94 cf 42 72 c7 ef 35 91 4d 69 78 3b 95 9a 9b 8f f9 8f f9 8b 24 e2 
        ef 75 c8 72 72 47 aa 28 d0 2f 96 18 a6 4d c6 e7 d5 f7 14 50 e1 2c 0d 21 7c 89 66 f3 d5 68 bc f4 
        d3 9a 56 23 95 3c a7 f5 20 46 ba a9 c9 98 c7 82 48 79 b9 9a 5d 85 3c 75 9f bd d3 95 19 2c 6a 2c 
        d2 ae b4 2b ce 80 ff ad 79 0d 5f 0e 57 c2 95 39 68 b8 ff 06 82 8a 8b 83 57 85 00 8f c9 c3 17 94 
        38 a2 92 b1 a3 b8 5e 63 bf d0 79 9c 0d bd 40 2f f0 f4 72 f3 c1 9c a2 5b 05 c9 ff b5 14 68 02 01 
        ef 35 38 bb 68 8b a0 2a ec 60 45 c0 c5 c0 6c b0 ca ef 25 51 90 b5 b6 3b 76 de 75 59 e9 2f 4c 6d 
        14 e0 8d 6e 81 40 d5 49 17 4f 12 e8 62 31 b6 f2 41 8a cd 69 b1 0c 79 7d 5e 2a d2 a9 24 8e 76 14 
        00 cd ac aa 14 81 f6 94 e4 03 f3 f3 e4 64 d7 06 75 d3 68 3c e8 2f ae 04 73 61 51 24 62 e6 4b c9 
        d2 27 de f0 66 5f 9b 22 d7 8c c2 97 bd 69 22 c9 d3 c1 72 5a dc 38 e7 39 48 bb eb 6f 08 e7 d9 66 
        c1 db d7 23 bf ed 66 9f ee 49 04 df b1 e1 8d b3 68 61 52 13 48 1c be c8 8f 5b b5 81 23 e8 f6 b2 
        39 14 2d 31 22 d4 82 f7 1f 81 12 88 fc 24 71 f0 db a8 35 51 d5 b0 37 c9 3f 4e 87 e5 f0 c6 0e 34 
        b5 ab bd ad 93 62 8a dd 32 59 02 84 df df 3e 7b 05 85 89 c1 51 9b 68 39 74 d0 59 0f 7c 59 0f 7d 
        b8 49 dc c0 41 fe ad d1 61 02 52 4a 5a c4 c3 7c a4 6d 7c b7 c6 02 20 a2 d8 55 21 94 22 bd 02 b5 
        7c d4 e3 b8 28 40 39 61 f1 17 6d f3 8f e0 92 91 2a c8 90 52 53 81 88 d9 35 56 fe 8d e0 9c 54 7f 
        79 a5 83 fc 35 9b a2 54 30 3b 01 c3 f9 f2 e6 ed 17 fb 15 76 50 5e 13 dc af 22 62 a2 b1 ee 0e 67 
        e3 40 f3 59 24 94 11 f9 b5 c2 15 5a e6 cd b5 92 0e 3e 0b 62 46 d2 1e be 9e 05 67 1d c5 3f 12 29 
        57 b9 67 c6 b2 4b cb 17 b6 f9 08 5e 0d 76 cd 75 57 d5 4d 3d b6 74 cd 85 2c 2d e4 08 24 14 48 b0 
        50 c1 76 0e b5 5b 84 20 99 3c 39 b8 40 d9 2c 3c b4 0d 4b 64 55 f9 4f 03 72 af 9c 69 35 e4 c5 09 
        02 f5 ec e9 4c 07 3b b2 a5 02 54 92 f8 ae 56 37 30 2f df 4e 56 b5 24 97 09 75 f9 2f 70 09 d0 ba 
        1a bc c8 5b a0 67 23 53 d7 9a 7c 2a 07 9d e0 a2 1c 51 8e 22 69 e6 0b 30 3d 39 9e 9a 5d 0e 7d ef 
        a2 fc 47 09 db 37 76 dc 0c a3 6f b5 04 98 07 50 73 4e 15 6e b7 e2 6f ec ae 2e ef 48 b4 8a af 71 
        3d 21 8c 20 7c 32 47
         */
        private static class AESTestVector8 extends AESTestVector {
                static byte[] testAESKey = {
                        (byte)0x18, (byte)0x36, (byte)0x02, (byte)0x78, (byte)0xd6, (byte)0x15, (byte)0xbe, (byte)0x45, 
                        (byte)0x15, (byte)0x65, (byte)0x9f, (byte)0xd8, (byte)0x6c, (byte)0xab, (byte)0xfb, (byte)0xba,
                };
                static byte[] testHighBits = {
                        (byte)0x1a, (byte)0x97, (byte)0xc2, (byte)0xc4, (byte)0x23, (byte)0x9f, (byte)0x73, (byte)0x4f,
                };
                static byte[] testPlainText = {
                        (byte)0xa8, (byte)0xfc, (byte)0xb4, (byte)0xfd, (byte)0xcf, (byte)0x40, (byte)0xf4, (byte)0xa9, 
                        (byte)0x8b, (byte)0xa7, (byte)0x64, (byte)0x32, (byte)0x19, (byte)0xef, (byte)0xdf, (byte)0xeb, 
                        (byte)0x99, (byte)0x36, (byte)0xfc, (byte)0x00, (byte)0x49, (byte)0x2b, (byte)0xc3, (byte)0xe1, 
                        (byte)0xbb, (byte)0x6a, (byte)0x0b, (byte)0x74, (byte)0xa1, (byte)0x3f, (byte)0xeb, (byte)0xcc, 
                        (byte)0xf9, (byte)0x7b, (byte)0x4c, (byte)0xb5, (byte)0xcd, (byte)0x5a, (byte)0x7f, (byte)0x36, 
                        (byte)0xbe, (byte)0x0b, (byte)0x74, (byte)0x63, (byte)0x7e, (byte)0x26, (byte)0x37, (byte)0xad, 
                        (byte)0x2d, (byte)0x18, (byte)0x90, (byte)0x83, (byte)0xe2, (byte)0x25, (byte)0x9a, (byte)0xe6, 
                        (byte)0xdd, (byte)0xd1, (byte)0x93, (byte)0x41, (byte)0x47, (byte)0x14, (byte)0x45, (byte)0x2c, 
                        (byte)0xf0, (byte)0x24, (byte)0x6e, (byte)0x5d, (byte)0xa7, (byte)0x8a, (byte)0x03, (byte)0x37, 
                        (byte)0x1f, (byte)0xd5, (byte)0xf4, (byte)0xa5, (byte)0x0a, (byte)0x5b, (byte)0x8b, (byte)0x6c, 
                        (byte)0xd4, (byte)0xac, (byte)0x15, (byte)0xd3, (byte)0xbe, (byte)0xf7, (byte)0x75, (byte)0x34, 
                        (byte)0x7b, (byte)0x41, (byte)0x1a, (byte)0xa2, (byte)0x7d, (byte)0xe1, (byte)0x8b, (byte)0x32, 
                        (byte)0x83, (byte)0x42, (byte)0xbd, (byte)0x15, (byte)0x44, (byte)0x1b, (byte)0xa0, (byte)0x15, 
                        (byte)0x32, (byte)0xd8, (byte)0x45, (byte)0xa5, (byte)0xf8, (byte)0xe7, (byte)0x7e, (byte)0xa6, 
                        (byte)0xda, (byte)0xbc, (byte)0x7b, (byte)0xcb, (byte)0xd7, (byte)0x1e, (byte)0x58, (byte)0x92, 
                        (byte)0x3d, (byte)0x88, (byte)0x39, (byte)0x52, (byte)0x59, (byte)0xf7, (byte)0x15, (byte)0xfe, 
                        (byte)0xea, (byte)0xd8, (byte)0x41, (byte)0xe6, (byte)0x43, (byte)0xd6, (byte)0x37, (byte)0x71, 
                        (byte)0x44, (byte)0x99, (byte)0xb2, (byte)0x16, (byte)0xae, (byte)0x67, (byte)0x8a, (byte)0xff, 
                        (byte)0x43, (byte)0x5b, (byte)0x9b, (byte)0xa7, (byte)0x8d, (byte)0x42, (byte)0x32, (byte)0x40, 
                        (byte)0x57, (byte)0x9a, (byte)0x0f, (byte)0x0a, (byte)0xce, (byte)0xd8, (byte)0xdd, (byte)0x4d, 
                        (byte)0xce, (byte)0xaa, (byte)0x1d, (byte)0xb9, (byte)0x11, (byte)0x5a, (byte)0xe0, (byte)0x3c, 
                        (byte)0xd7, (byte)0x5a, (byte)0x85, (byte)0x06, (byte)0x29, (byte)0x9e, (byte)0x5a, (byte)0x94, 
                        (byte)0xe6, (byte)0xb8, (byte)0xb7, (byte)0x89, (byte)0x1f, (byte)0xcd, (byte)0xcf, (byte)0x3b, 
                        (byte)0xbb, (byte)0xc5, (byte)0x68, (byte)0xd8, (byte)0x0f, (byte)0x0a, (byte)0x22, (byte)0x2d, 
                        (byte)0xe6, (byte)0xc4, (byte)0xef, (byte)0x6b, (byte)0x90, (byte)0x3e, (byte)0x8a, (byte)0x1f, 
                        (byte)0x89, (byte)0xde, (byte)0x49, (byte)0xb9, (byte)0xeb, (byte)0x95, (byte)0xe1, (byte)0x64, 
                        (byte)0x6e, (byte)0x59, (byte)0x5e, (byte)0xa4, (byte)0x61, (byte)0x83, (byte)0x83, (byte)0x86, 
                        (byte)0xb9, (byte)0x06, (byte)0xd5, (byte)0xdc, (byte)0xf0, (byte)0xc2, (byte)0xa3, (byte)0xd5, 
                        (byte)0xdb, (byte)0x98, (byte)0x63, (byte)0x21, (byte)0x53, (byte)0x4a, (byte)0x80, (byte)0x91, 
                        (byte)0xa0, (byte)0x12, (byte)0xc7, (byte)0xee, (byte)0xf5, (byte)0x39, (byte)0x85, (byte)0x40, 
                        (byte)0x3e, (byte)0x08, (byte)0xd0, (byte)0x04, (byte)0x2c, (byte)0xbe, (byte)0x4a, (byte)0x55, 
                        (byte)0xf4, (byte)0xa9, (byte)0x17, (byte)0x0e, (byte)0x79, (byte)0x9f, (byte)0x21, (byte)0x64, 
                        (byte)0x37, (byte)0x6d, (byte)0x23, (byte)0xf3, (byte)0x13, (byte)0x4c, (byte)0xc0, (byte)0xca, 
                        (byte)0xa4, (byte)0xd1, (byte)0xf7, (byte)0xf9, (byte)0x5c, (byte)0xbe, (byte)0x87, (byte)0x8f, 
                        (byte)0x72, (byte)0x34, (byte)0x20, (byte)0xcd, (byte)0x4d, (byte)0xe5, (byte)0x76, (byte)0x39, 
                        (byte)0x6c, (byte)0x61, (byte)0x15, (byte)0x6e, (byte)0x97, (byte)0x61, (byte)0x42, (byte)0x88, 
                        (byte)0xae, (byte)0x74, (byte)0x30, (byte)0xb2, (byte)0xfb, (byte)0xd9, (byte)0xb5, (byte)0xaa, 
                        (byte)0xcc, (byte)0x28, (byte)0x9d, (byte)0xd3, (byte)0xe2, (byte)0xef, (byte)0x01, (byte)0xcc, 
                        (byte)0x2a, (byte)0x51, (byte)0x06, (byte)0x95, (byte)0x4f, (byte)0xcb, (byte)0x91, (byte)0x95, 
                        (byte)0x6d, (byte)0xa7, (byte)0x9f, (byte)0xfd, (byte)0x00, (byte)0x7e, (byte)0x19, (byte)0xb0, 
                        (byte)0x39, (byte)0x81, (byte)0xf1, (byte)0xb5, (byte)0x19, (byte)0x7d, (byte)0x3d, (byte)0xcb, 
                        (byte)0x02, (byte)0x1b, (byte)0xd8, (byte)0x5f, (byte)0xe9, (byte)0x7f, (byte)0xc8, (byte)0x5e, 
                        (byte)0x65, (byte)0x5f, (byte)0x5c, (byte)0xa8, (byte)0x49, (byte)0xd7, (byte)0xc0, (byte)0x9b, 
                        (byte)0xb9, (byte)0xe4, (byte)0x7d, (byte)0x6c, (byte)0xdd, (byte)0x0e, (byte)0x54, (byte)0xc9, 
                        (byte)0x41, (byte)0x4d, (byte)0x0d, (byte)0x89, (byte)0x61, (byte)0x64, (byte)0xbc, (byte)0x6b, 
                        (byte)0xaa, (byte)0x1d, (byte)0x08, (byte)0xf0, (byte)0xbd, (byte)0x68, (byte)0xc5, (byte)0xf1, 
                        (byte)0x8b, (byte)0x51, (byte)0x4e, (byte)0x40, (byte)0x16, (byte)0x60, (byte)0xe4, (byte)0x66, 
                        (byte)0x5a, (byte)0x25, (byte)0x3b, (byte)0x80, (byte)0x90, (byte)0x86, (byte)0x86, (byte)0x1d, 
                        (byte)0x9a, (byte)0x44, (byte)0x71, (byte)0xf8, (byte)0x58, (byte)0x80, (byte)0x16, (byte)0x12, 
                        (byte)0x26, (byte)0x64, (byte)0x24, (byte)0xa8, (byte)0x50, (byte)0x85, (byte)0x23, (byte)0xd3, 
                        (byte)0x64, (byte)0x78, (byte)0x78, (byte)0x43, (byte)0xef, (byte)0xa5, (byte)0x13, (byte)0xb2, 
                        (byte)0x6d, (byte)0xb8, (byte)0x9c, (byte)0x67, (byte)0xee, (byte)0x15, (byte)0xe4, (byte)0x71, 
                        (byte)0x25, (byte)0xd5, (byte)0xa9, (byte)0x79, (byte)0x02, (byte)0x8b, (byte)0x8a, (byte)0xff, 
                        (byte)0xa7, (byte)0x4c, (byte)0x2d, (byte)0x1d, (byte)0xa2, (byte)0x8a, (byte)0x7d, (byte)0xe6, 
                        (byte)0x98, (byte)0xa1, (byte)0xef, (byte)0x8f, (byte)0xc6, (byte)0xee, (byte)0x67, (byte)0xdf, 
                        (byte)0x6e, (byte)0x97, (byte)0x51, (byte)0x8f, (byte)0xda, (byte)0xd5, (byte)0xb2, (byte)0x1e, 
                        (byte)0x04, (byte)0xa7, (byte)0xce, (byte)0x78, (byte)0xe6, (byte)0xc8, (byte)0x93, (byte)0x3a, 
                        (byte)0x0e, (byte)0x33, (byte)0xa2, (byte)0xfc, (byte)0x8a, (byte)0x5a, (byte)0x55, (byte)0x70, 
                        (byte)0xb9, (byte)0x8e, (byte)0x3b, (byte)0x54, (byte)0xff, (byte)0x23, (byte)0xe9, (byte)0x7f, 
                        (byte)0xde, (byte)0x6d, (byte)0x74, (byte)0xe5, (byte)0x8f, (byte)0x2b, (byte)0xf3, (byte)0xf0, 
                        (byte)0x9c, (byte)0x69, (byte)0x10, (byte)0x4b, (byte)0xac, (byte)0x5e, (byte)0xe0, (byte)0xb2, 
                        (byte)0x60, (byte)0xfa, (byte)0x12, (byte)0x39, (byte)0x9b, (byte)0xff, (byte)0xe4, (byte)0xd7, 
                        (byte)0xa5, (byte)0xce, (byte)0x0d, (byte)0x59, (byte)0x92, (byte)0xb0, (byte)0xec, (byte)0x47, 
                        (byte)0xf7, (byte)0x40, (byte)0xeb, (byte)0xd3, (byte)0x22, (byte)0xc4, (byte)0x99, (byte)0x28, 
                        (byte)0xed, (byte)0x08, (byte)0xce, (byte)0x25, (byte)0xb5, (byte)0xb9, (byte)0x21, (byte)0x37, 
                        (byte)0x60, (byte)0xa7, (byte)0xd4, (byte)0x8c, (byte)0xad, (byte)0xc0, (byte)0xb2, (byte)0x9a, 
                        (byte)0xe8, (byte)0x4e, (byte)0xad, (byte)0xda, (byte)0x71, (byte)0xab, (byte)0x30, (byte)0xa7, 
                        (byte)0xe3, (byte)0x75, (byte)0x52, (byte)0xed, (byte)0x0e, (byte)0x11, (byte)0xc1, (byte)0x18, 
                        (byte)0xf5, (byte)0x14, (byte)0x96, (byte)0x74, (byte)0x2f, (byte)0x40, (byte)0x50, (byte)0x28, 
                        (byte)0x35, (byte)0x13, (byte)0x29, (byte)0x2a, (byte)0x64, (byte)0xa5, (byte)0xd4, (byte)0xb4, 
                        (byte)0x10, (byte)0x3a, (byte)0x9e, (byte)0x10, (byte)0x81, (byte)0xe8, (byte)0xc0, (byte)0x73, 
                        (byte)0x8a, (byte)0xac, (byte)0xda, (byte)0x44, (byte)0xcb, (byte)0xe5, (byte)0x91, (byte)0x01, 
                        (byte)0x86, (byte)0x9b, (byte)0xee, (byte)0x9b, (byte)0x11, (byte)0x74, (byte)0x29, (byte)0x8e, 
                        (byte)0x0e, (byte)0xdb, (byte)0x91, (byte)0x41, (byte)0x0a, (byte)0xe8, (byte)0xaf, (byte)0xc7, 
                        (byte)0xca, (byte)0x81, (byte)0x16, (byte)0x1d, (byte)0xca, (byte)0xd8, (byte)0x1c, (byte)0x82, 
                        (byte)0xd8, (byte)0x18, (byte)0x7c, (byte)0x60, (byte)0x07, (byte)0x54, (byte)0xf1, (byte)0x24, 
                        (byte)0xef, (byte)0xd6, (byte)0xfe, (byte)0x6e, (byte)0x44, (byte)0x7d, (byte)0x00, (byte)0x39, 
                        (byte)0xea, (byte)0xaf, (byte)0xa0, (byte)0x99, (byte)0xcc, (byte)0x84, (byte)0x3b, (byte)0x45, 
                        (byte)0x1e, (byte)0xa4, (byte)0x13, (byte)0xcc, (byte)0xfc, (byte)0xa7, (byte)0x53, (byte)0x9b, 
                        (byte)0x77, (byte)0xcb, (byte)0xff, (byte)0x01, (byte)0x13, (byte)0xb2, (byte)0x79, (byte)0x62, 
                        (byte)0x51, (byte)0x15, (byte)0x0e, (byte)0x90, (byte)0xfc, (byte)0x00, (byte)0x17, (byte)0x57, 
                        (byte)0xb7, (byte)0x41, (byte)0x2a, (byte)0x16, (byte)0xa8, (byte)0x26, (byte)0xa1, (byte)0xaa, 
                        (byte)0x52, (byte)0x74, (byte)0x58, (byte)0xd5, (byte)0x03, (byte)0x8d, (byte)0x23, (byte)0x9a, 
                        (byte)0xc8, (byte)0x6e, (byte)0x78, (byte)0xb2, (byte)0x39, (byte)0x34, (byte)0x1a, (byte)0x0d, 
                        (byte)0xfa, (byte)0x3c, (byte)0x65, (byte)0xd7, (byte)0xda, (byte)0x93, (byte)0x2b, (byte)0x67, 
                        (byte)0x89, (byte)0x5b, (byte)0x39, (byte)0x2f, (byte)0x5b, (byte)0xed, (byte)0xbc, (byte)0x60, 
                        (byte)0x0e, (byte)0x2a, (byte)0xf2, (byte)0x6a, (byte)0xab, (byte)0xd2, (byte)0x40, (byte)0xde, 
                        (byte)0x09, (byte)0xb7, (byte)0xf8, (byte)0x14, (byte)0x71, (byte)0xde, (byte)0x8f, (byte)0x67, 
                        (byte)0x99, (byte)0x5e, (byte)0x75, (byte)0x4e, (byte)0xa8, (byte)0x66, (byte)0x06, (byte)0xbe, 
                        (byte)0x88, (byte)0x08, (byte)0x6d, (byte)0x21, (byte)0xb2, (byte)0x61, (byte)0x75, (byte)0x26, 
                        (byte)0x66, (byte)0xc3, (byte)0x39, (byte)0x95, (byte)0x1d, (byte)0x24, (byte)0x36, (byte)0x39, 
                        (byte)0x48, (byte)0x4a, (byte)0x45, (byte)0x7d, (byte)0xb4, (byte)0x98, (byte)0x97, (byte)0x8b, 
                        (byte)0x85, (byte)0xdc, (byte)0xa2, (byte)0x7e, (byte)0x88, (byte)0xa9, (byte)0x93, (byte)0x1d, 
                        (byte)0xa8, (byte)0x00, (byte)0x4e, (byte)0x41, (byte)0x9c, (byte)0x55, (byte)0xac, (byte)0x55, 
                        (byte)0x3c, (byte)0xe8, (byte)0xec, (byte)0xb5, (byte)0xf8, (byte)0xf1, (byte)0xea, (byte)0x03, 
                        (byte)0x32, (byte)0xac, (byte)0xed, (byte)0x73, (byte)0x29, (byte)0xce, (byte)0x56, (byte)0x95, 
                        (byte)0x3b, (byte)0x60, (byte)0xb8, (byte)0xa0, (byte)0x81, (byte)0xc9, (byte)0x5b, (byte)0xe9, 
                        (byte)0x8a, (byte)0x41, (byte)0x29, (byte)0x93, (byte)0x9e, (byte)0x88, (byte)0x19, (byte)0x21, 
                        (byte)0x98, (byte)0xf1, (byte)0x76, (byte)0x67, (byte)0x2e, (byte)0x64, (byte)0x77, (byte)0x15, 
                        (byte)0xdb, (byte)0x01, (byte)0xc0, (byte)0x13, (byte)0xda, (byte)0xbb, (byte)0x09, (byte)0x6e, 
                        (byte)0xaa, (byte)0x3f, (byte)0x4b, (byte)0x9f, (byte)0xc0, (byte)0x0f, (byte)0xc2, (byte)0x70, 
                        (byte)0xdf, (byte)0xad, (byte)0xd3, (byte)0xb3, (byte)0x0f, (byte)0xe9, (byte)0xa3, (byte)0x11, 
                        (byte)0xa0, (byte)0x6a, (byte)0xc5, (byte)0x09, (byte)0x89, (byte)0xd6, (byte)0xce, (byte)0xd4, 
                        (byte)0x30, (byte)0x03, (byte)0x06, (byte)0x92, (byte)0x6c, (byte)0xf8, (byte)0x7b, (byte)0xad, 
                        (byte)0xfa, (byte)0x5c, (byte)0x09, (byte)0xbf, (byte)0x4f, (byte)0x45, (byte)0x6c, (byte)0x30, 
                        (byte)0x6b, (byte)0xb1, (byte)0xf7, (byte)0x31, (byte)0x69, (byte)0x91, (byte)0xa4, (byte)0xd2, 
                        (byte)0x4f, (byte)0x4a, (byte)0x2b, (byte)0x71, (byte)0x81, (byte)0x4f, (byte)0x63, (byte)0x28, 
                        (byte)0x3d, (byte)0x49, (byte)0x94, (byte)0xcb, (byte)0x1b, (byte)0x01, (byte)0xdf, (byte)0x6a, 
                        (byte)0xa8, (byte)0xb8, (byte)0x54, (byte)0x8d, (byte)0xb5, (byte)0xf2, (byte)0x42, (byte)0x98, 
                        (byte)0x1b, (byte)0xaa, (byte)0x90, (byte)0x82, (byte)0xff, (byte)0x0f, (byte)0xfe, (byte)0x0e, 
                        (byte)0x00, (byte)0x61, (byte)0x9c, (byte)0x44, (byte)0x0a, (byte)0xbd, (byte)0xe5, (byte)0x83, 
                        (byte)0x2d, (byte)0x65, (byte)0xad, (byte)0x67, (byte)0x26, (byte)0x85, (byte)0x1c, (byte)0x68, 
                        (byte)0x8d, (byte)0x2f, (byte)0x6c, (byte)0xf8, (byte)0xd0, (byte)0x33, (byte)0xf9, (byte)0x54, 
                        (byte)0xf6, (byte)0xf3, (byte)0xa0, (byte)0x9c, (byte)0xe4, (byte)0x5c, (byte)0x4d, (byte)0x1f, 
                        (byte)0xf4, (byte)0x5e, (byte)0xb3, (byte)0xf7, (byte)0x53, (byte)0xc1, (byte)0x4c, (byte)0xa1, 
                        (byte)0x05, (byte)0xf6, (byte)0x27, (byte)0xa7, (byte)0x70, (byte)0x77, (byte)0x72, (byte)0x2c, 
                        (byte)0x81, (byte)0x6e, (byte)0x8d, (byte)0x13, (byte)0x68, (byte)0x3d, (byte)0x1d, (byte)0xc6, 
                        (byte)0xba, (byte)0xb9, (byte)0x32, (byte)0x22, (byte)0xf8, (byte)0x7c, (byte)0x5a, (byte)0xca, 
                        (byte)0xa4, (byte)0x0f, (byte)0x25, (byte)0x16, (byte)0xb6, (byte)0xa8, (byte)0x73, (byte)0xe1, 
                        (byte)0xb2, (byte)0x61, (byte)0xd6, (byte)0xd1, (byte)0x3f, (byte)0xc3, (byte)0x0d, (byte)0x28, 
                        (byte)0xda, (byte)0xf2, (byte)0xd7, (byte)0xe3, (byte)0xba, (byte)0xfe, (byte)0x12, (byte)0x9b, 
                        (byte)0xff, (byte)0x42, (byte)0x35, (byte)0x99, (byte)0x5e, (byte)0x9f, (byte)0xd9, (byte)0xf1, 
                        (byte)0x6e, (byte)0xfe, (byte)0xec, (byte)0x0b, (byte)0x3d, (byte)0x7e, (byte)0x02, (byte)0xd5, 
                        (byte)0x4f, (byte)0x6a, (byte)0xcb, (byte)0xc2, (byte)0xd6, (byte)0x47, (byte)0x11, (byte)0x8d, 
                        (byte)0x0f, (byte)0x4b, (byte)0x16, (byte)0x75, (byte)0x1c, (byte)0x66, (byte)0xc2, (byte)0x0f, 
                        (byte)0x41, (byte)0xd1, (byte)0x59, (byte)0x7c, (byte)0x10, (byte)0xae, (byte)0x6b, (byte)0x5c, 
                        (byte)0xe8, (byte)0xa5, (byte)0x7d, (byte)0x58, (byte)0x99, (byte)0x28, (byte)0x99, (byte)0x91, 
                        (byte)0x3a, (byte)0x44, (byte)0x20, (byte)0x1f, (byte)0xf1, (byte)0x02, (byte)0x06, (byte)0x95, 
                        (byte)0x38, (byte)0xe1, (byte)0xa2, (byte)0x5b, (byte)0x1a, (byte)0x50, (byte)0x30,
                };
                static byte[] testExpectedCiphertext = {
                        (byte)0xfe, (byte)0x8c, (byte)0x1f, (byte)0x41, (byte)0x19, (byte)0xb2, (byte)0x7b, (byte)0x95, 
                        (byte)0x79, (byte)0x54, (byte)0xcf, (byte)0x97, (byte)0xe1, (byte)0xe3, (byte)0x1d, (byte)0xb4, 
                        (byte)0x29, (byte)0x1e, (byte)0xe6, (byte)0x02, (byte)0xcb, (byte)0x08, (byte)0x2e, (byte)0x52, 
                        (byte)0x1c, (byte)0xb8, (byte)0x78, (byte)0x0e, (byte)0xcb, (byte)0xa0, (byte)0x83, (byte)0x2c, 
                        (byte)0xa3, (byte)0xd9, (byte)0x55, (byte)0xeb, (byte)0x1d, (byte)0xdc, (byte)0xeb, (byte)0x0e, 
                        (byte)0x1b, (byte)0x1d, (byte)0xb2, (byte)0xa5, (byte)0x2c, (byte)0x44, (byte)0xc2, (byte)0xbf, 
                        (byte)0x55, (byte)0x33, (byte)0x52, (byte)0xf7, (byte)0x5c, (byte)0x28, (byte)0x47, (byte)0x7e, 
                        (byte)0xd5, (byte)0xc2, (byte)0xe2, (byte)0x87, (byte)0x05, (byte)0xc1, (byte)0x4c, (byte)0x5b, 
                        (byte)0x81, (byte)0x25, (byte)0x3c, (byte)0x23, (byte)0x63, (byte)0x08, (byte)0x58, (byte)0x79, 
                        (byte)0x27, (byte)0xe1, (byte)0x1e, (byte)0x45, (byte)0xfa, (byte)0xe8, (byte)0x48, (byte)0xfb, 
                        (byte)0x73, (byte)0x95, (byte)0xbc, (byte)0x10, (byte)0xf7, (byte)0xc6, (byte)0x70, (byte)0xd0, 
                        (byte)0x78, (byte)0xd6, (byte)0x47, (byte)0xea, (byte)0x81, (byte)0xd3, (byte)0x46, (byte)0xd6, 
                        (byte)0xbd, (byte)0x3f, (byte)0x72, (byte)0xeb, (byte)0x38, (byte)0x03, (byte)0xea, (byte)0x58, 
                        (byte)0xe7, (byte)0x15, (byte)0x40, (byte)0xca, (byte)0x3a, (byte)0xde, (byte)0x77, (byte)0xd7, 
                        (byte)0x33, (byte)0x0e, (byte)0xe1, (byte)0xfc, (byte)0x35, (byte)0x44, (byte)0xeb, (byte)0x6b, 
                        (byte)0xe3, (byte)0xf4, (byte)0x47, (byte)0xf1, (byte)0x5a, (byte)0xbb, (byte)0x79, (byte)0x62, 
                        (byte)0xce, (byte)0x49, (byte)0x13, (byte)0x75, (byte)0xc6, (byte)0x82, (byte)0xb4, (byte)0x88, 
                        (byte)0x6d, (byte)0x7f, (byte)0x0e, (byte)0x8d, (byte)0xf8, (byte)0x6d, (byte)0xd6, (byte)0x74, 
                        (byte)0x89, (byte)0x5d, (byte)0x46, (byte)0x00, (byte)0xf9, (byte)0x50, (byte)0x98, (byte)0x96, 
                        (byte)0x1d, (byte)0xa1, (byte)0x28, (byte)0x62, (byte)0xbb, (byte)0xcd, (byte)0x92, (byte)0x63, 
                        (byte)0x7f, (byte)0xc7, (byte)0xb4, (byte)0x78, (byte)0xce, (byte)0x13, (byte)0x14, (byte)0x86, 
                        (byte)0xe3, (byte)0xf6, (byte)0xa1, (byte)0xb0, (byte)0x8c, (byte)0x22, (byte)0x80, (byte)0xba, 
                        (byte)0x11, (byte)0x93, (byte)0x2e, (byte)0x83, (byte)0x17, (byte)0xaf, (byte)0x9d, (byte)0x64, 
                        (byte)0x68, (byte)0x6e, (byte)0x79, (byte)0x92, (byte)0x8b, (byte)0x2e, (byte)0x15, (byte)0xb9, 
                        (byte)0x72, (byte)0x49, (byte)0x10, (byte)0xc3, (byte)0x3d, (byte)0xb0, (byte)0x88, (byte)0xe7, 
                        (byte)0x25, (byte)0x28, (byte)0x9b, (byte)0x28, (byte)0xeb, (byte)0x61, (byte)0x94, (byte)0x35, 
                        (byte)0x36, (byte)0x84, (byte)0xda, (byte)0x81, (byte)0x9f, (byte)0xa9, (byte)0x45, (byte)0x4d, 
                        (byte)0xeb, (byte)0x7e, (byte)0xb0, (byte)0xcf, (byte)0x47, (byte)0x5f, (byte)0x6a, (byte)0x76, 
                        (byte)0xf9, (byte)0x0a, (byte)0xf4, (byte)0x91, (byte)0xca, (byte)0xb7, (byte)0x18, (byte)0x7e, 
                        (byte)0x51, (byte)0x6b, (byte)0xe4, (byte)0x03, (byte)0x38, (byte)0x83, (byte)0x66, (byte)0xc4, 
                        (byte)0xaf, (byte)0x58, (byte)0x89, (byte)0x35, (byte)0x92, (byte)0xa3, (byte)0x33, (byte)0x2b, 
                        (byte)0x69, (byte)0xe8, (byte)0x8e, (byte)0xa7, (byte)0x46, (byte)0x34, (byte)0x53, (byte)0x6d, 
                        (byte)0x1e, (byte)0xac, (byte)0x56, (byte)0xfa, (byte)0x3a, (byte)0xae, (byte)0xe8, (byte)0xcf, 
                        (byte)0xf9, (byte)0x85, (byte)0xb9, (byte)0x46, (byte)0xd9, (byte)0x0b, (byte)0x17, (byte)0x71, 
                        (byte)0x21, (byte)0xe6, (byte)0x96, (byte)0x80, (byte)0xbc, (byte)0x5c, (byte)0x4d, (byte)0x0d, 
                        (byte)0x45, (byte)0x99, (byte)0xbc, (byte)0x92, (byte)0x81, (byte)0xa2, (byte)0xea, (byte)0x7c, 
                        (byte)0x08, (byte)0x93, (byte)0xa4, (byte)0x8e, (byte)0x30, (byte)0x01, (byte)0xf9, (byte)0x01, 
                        (byte)0x28, (byte)0x81, (byte)0xd3, (byte)0x62, (byte)0x78, (byte)0xd1, (byte)0x2c, (byte)0x8d, 
                        (byte)0xdd, (byte)0xda, (byte)0xae, (byte)0x40, (byte)0x4f, (byte)0xa4, (byte)0x52, (byte)0x88, 
                        (byte)0xf9, (byte)0xc0, (byte)0x64, (byte)0x9c, (byte)0x0c, (byte)0xdd, (byte)0xa7, (byte)0xec, 
                        (byte)0xeb, (byte)0x32, (byte)0x16, (byte)0x86, (byte)0x09, (byte)0x9e, (byte)0xea, (byte)0xfc, 
                        (byte)0x8d, (byte)0xa7, (byte)0xdf, (byte)0x41, (byte)0x7c, (byte)0xf6, (byte)0x61, (byte)0x60, 
                        (byte)0xd0, (byte)0x40, (byte)0x50, (byte)0xac, (byte)0x1e, (byte)0x24, (byte)0x30, (byte)0x16, 
                        (byte)0xdc, (byte)0x23, (byte)0x30, (byte)0x93, (byte)0xbd, (byte)0xbb, (byte)0x8d, (byte)0xca, 
                        (byte)0x4f, (byte)0x94, (byte)0xfc, (byte)0x5e, (byte)0x68, (byte)0x37, (byte)0xb3, (byte)0x0e, 
                        (byte)0x34, (byte)0xdf, (byte)0x94, (byte)0xcf, (byte)0x42, (byte)0x72, (byte)0xc7, (byte)0xef, 
                        (byte)0x35, (byte)0x91, (byte)0x4d, (byte)0x69, (byte)0x78, (byte)0x3b, (byte)0x95, (byte)0x9a, 
                        (byte)0x9b, (byte)0x8f, (byte)0xf9, (byte)0x8f, (byte)0xf9, (byte)0x8b, (byte)0x24, (byte)0xe2, 
                        (byte)0xef, (byte)0x75, (byte)0xc8, (byte)0x72, (byte)0x72, (byte)0x47, (byte)0xaa, (byte)0x28, 
                        (byte)0xd0, (byte)0x2f, (byte)0x96, (byte)0x18, (byte)0xa6, (byte)0x4d, (byte)0xc6, (byte)0xe7, 
                        (byte)0xd5, (byte)0xf7, (byte)0x14, (byte)0x50, (byte)0xe1, (byte)0x2c, (byte)0x0d, (byte)0x21, 
                        (byte)0x7c, (byte)0x89, (byte)0x66, (byte)0xf3, (byte)0xd5, (byte)0x68, (byte)0xbc, (byte)0xf4, 
                        (byte)0xd3, (byte)0x9a, (byte)0x56, (byte)0x23, (byte)0x95, (byte)0x3c, (byte)0xa7, (byte)0xf5, 
                        (byte)0x20, (byte)0x46, (byte)0xba, (byte)0xa9, (byte)0xc9, (byte)0x98, (byte)0xc7, (byte)0x82, 
                        (byte)0x48, (byte)0x79, (byte)0xb9, (byte)0x9a, (byte)0x5d, (byte)0x85, (byte)0x3c, (byte)0x75, 
                        (byte)0x9f, (byte)0xbd, (byte)0xd3, (byte)0x95, (byte)0x19, (byte)0x2c, (byte)0x6a, (byte)0x2c, 
                        (byte)0xd2, (byte)0xae, (byte)0xb4, (byte)0x2b, (byte)0xce, (byte)0x80, (byte)0xff, (byte)0xad, 
                        (byte)0x79, (byte)0x0d, (byte)0x5f, (byte)0x0e, (byte)0x57, (byte)0xc2, (byte)0x95, (byte)0x39, 
                        (byte)0x68, (byte)0xb8, (byte)0xff, (byte)0x06, (byte)0x82, (byte)0x8a, (byte)0x8b, (byte)0x83, 
                        (byte)0x57, (byte)0x85, (byte)0x00, (byte)0x8f, (byte)0xc9, (byte)0xc3, (byte)0x17, (byte)0x94, 
                        (byte)0x38, (byte)0xa2, (byte)0x92, (byte)0xb1, (byte)0xa3, (byte)0xb8, (byte)0x5e, (byte)0x63, 
                        (byte)0xbf, (byte)0xd0, (byte)0x79, (byte)0x9c, (byte)0x0d, (byte)0xbd, (byte)0x40, (byte)0x2f, 
                        (byte)0xf0, (byte)0xf4, (byte)0x72, (byte)0xf3, (byte)0xc1, (byte)0x9c, (byte)0xa2, (byte)0x5b, 
                        (byte)0x05, (byte)0xc9, (byte)0xff, (byte)0xb5, (byte)0x14, (byte)0x68, (byte)0x02, (byte)0x01, 
                        (byte)0xef, (byte)0x35, (byte)0x38, (byte)0xbb, (byte)0x68, (byte)0x8b, (byte)0xa0, (byte)0x2a, 
                        (byte)0xec, (byte)0x60, (byte)0x45, (byte)0xc0, (byte)0xc5, (byte)0xc0, (byte)0x6c, (byte)0xb0, 
                        (byte)0xca, (byte)0xef, (byte)0x25, (byte)0x51, (byte)0x90, (byte)0xb5, (byte)0xb6, (byte)0x3b, 
                        (byte)0x76, (byte)0xde, (byte)0x75, (byte)0x59, (byte)0xe9, (byte)0x2f, (byte)0x4c, (byte)0x6d, 
                        (byte)0x14, (byte)0xe0, (byte)0x8d, (byte)0x6e, (byte)0x81, (byte)0x40, (byte)0xd5, (byte)0x49, 
                        (byte)0x17, (byte)0x4f, (byte)0x12, (byte)0xe8, (byte)0x62, (byte)0x31, (byte)0xb6, (byte)0xf2, 
                        (byte)0x41, (byte)0x8a, (byte)0xcd, (byte)0x69, (byte)0xb1, (byte)0x0c, (byte)0x79, (byte)0x7d, 
                        (byte)0x5e, (byte)0x2a, (byte)0xd2, (byte)0xa9, (byte)0x24, (byte)0x8e, (byte)0x76, (byte)0x14, 
                        (byte)0x00, (byte)0xcd, (byte)0xac, (byte)0xaa, (byte)0x14, (byte)0x81, (byte)0xf6, (byte)0x94, 
                        (byte)0xe4, (byte)0x03, (byte)0xf3, (byte)0xf3, (byte)0xe4, (byte)0x64, (byte)0xd7, (byte)0x06, 
                        (byte)0x75, (byte)0xd3, (byte)0x68, (byte)0x3c, (byte)0xe8, (byte)0x2f, (byte)0xae, (byte)0x04, 
                        (byte)0x73, (byte)0x61, (byte)0x51, (byte)0x24, (byte)0x62, (byte)0xe6, (byte)0x4b, (byte)0xc9, 
                        (byte)0xd2, (byte)0x27, (byte)0xde, (byte)0xf0, (byte)0x66, (byte)0x5f, (byte)0x9b, (byte)0x22, 
                        (byte)0xd7, (byte)0x8c, (byte)0xc2, (byte)0x97, (byte)0xbd, (byte)0x69, (byte)0x22, (byte)0xc9, 
                        (byte)0xd3, (byte)0xc1, (byte)0x72, (byte)0x5a, (byte)0xdc, (byte)0x38, (byte)0xe7, (byte)0x39, 
                        (byte)0x48, (byte)0xbb, (byte)0xeb, (byte)0x6f, (byte)0x08, (byte)0xe7, (byte)0xd9, (byte)0x66, 
                        (byte)0xc1, (byte)0xdb, (byte)0xd7, (byte)0x23, (byte)0xbf, (byte)0xed, (byte)0x66, (byte)0x9f, 
                        (byte)0xee, (byte)0x49, (byte)0x04, (byte)0xdf, (byte)0xb1, (byte)0xe1, (byte)0x8d, (byte)0xb3, 
                        (byte)0x68, (byte)0x61, (byte)0x52, (byte)0x13, (byte)0x48, (byte)0x1c, (byte)0xbe, (byte)0xc8, 
                        (byte)0x8f, (byte)0x5b, (byte)0xb5, (byte)0x81, (byte)0x23, (byte)0xe8, (byte)0xf6, (byte)0xb2, 
                        (byte)0x39, (byte)0x14, (byte)0x2d, (byte)0x31, (byte)0x22, (byte)0xd4, (byte)0x82, (byte)0xf7, 
                        (byte)0x1f, (byte)0x81, (byte)0x12, (byte)0x88, (byte)0xfc, (byte)0x24, (byte)0x71, (byte)0xf0, 
                        (byte)0xdb, (byte)0xa8, (byte)0x35, (byte)0x51, (byte)0xd5, (byte)0xb0, (byte)0x37, (byte)0xc9, 
                        (byte)0x3f, (byte)0x4e, (byte)0x87, (byte)0xe5, (byte)0xf0, (byte)0xc6, (byte)0x0e, (byte)0x34, 
                        (byte)0xb5, (byte)0xab, (byte)0xbd, (byte)0xad, (byte)0x93, (byte)0x62, (byte)0x8a, (byte)0xdd, 
                        (byte)0x32, (byte)0x59, (byte)0x02, (byte)0x84, (byte)0xdf, (byte)0xdf, (byte)0x3e, (byte)0x7b, 
                        (byte)0x05, (byte)0x85, (byte)0x89, (byte)0xc1, (byte)0x51, (byte)0x9b, (byte)0x68, (byte)0x39, 
                        (byte)0x74, (byte)0xd0, (byte)0x59, (byte)0x0f, (byte)0x7c, (byte)0x59, (byte)0x0f, (byte)0x7d, 
                        (byte)0xb8, (byte)0x49, (byte)0xdc, (byte)0xc0, (byte)0x41, (byte)0xfe, (byte)0xad, (byte)0xd1, 
                        (byte)0x61, (byte)0x02, (byte)0x52, (byte)0x4a, (byte)0x5a, (byte)0xc4, (byte)0xc3, (byte)0x7c, 
                        (byte)0xa4, (byte)0x6d, (byte)0x7c, (byte)0xb7, (byte)0xc6, (byte)0x02, (byte)0x20, (byte)0xa2, 
                        (byte)0xd8, (byte)0x55, (byte)0x21, (byte)0x94, (byte)0x22, (byte)0xbd, (byte)0x02, (byte)0xb5, 
                        (byte)0x7c, (byte)0xd4, (byte)0xe3, (byte)0xb8, (byte)0x28, (byte)0x40, (byte)0x39, (byte)0x61, 
                        (byte)0xf1, (byte)0x17, (byte)0x6d, (byte)0xf3, (byte)0x8f, (byte)0xe0, (byte)0x92, (byte)0x91, 
                        (byte)0x2a, (byte)0xc8, (byte)0x90, (byte)0x52, (byte)0x53, (byte)0x81, (byte)0x88, (byte)0xd9, 
                        (byte)0x35, (byte)0x56, (byte)0xfe, (byte)0x8d, (byte)0xe0, (byte)0x9c, (byte)0x54, (byte)0x7f, 
                        (byte)0x79, (byte)0xa5, (byte)0x83, (byte)0xfc, (byte)0x35, (byte)0x9b, (byte)0xa2, (byte)0x54, 
                        (byte)0x30, (byte)0x3b, (byte)0x01, (byte)0xc3, (byte)0xf9, (byte)0xf2, (byte)0xe6, (byte)0xed, 
                        (byte)0x17, (byte)0xfb, (byte)0x15, (byte)0x76, (byte)0x50, (byte)0x5e, (byte)0x13, (byte)0xdc, 
                        (byte)0xaf, (byte)0x22, (byte)0x62, (byte)0xa2, (byte)0xb1, (byte)0xee, (byte)0x0e, (byte)0x67, 
                        (byte)0xe3, (byte)0x40, (byte)0xf3, (byte)0x59, (byte)0x24, (byte)0x94, (byte)0x11, (byte)0xf9, 
                        (byte)0xb5, (byte)0xc2, (byte)0x15, (byte)0x5a, (byte)0xe6, (byte)0xcd, (byte)0xb5, (byte)0x92, 
                        (byte)0x0e, (byte)0x3e, (byte)0x0b, (byte)0x62, (byte)0x46, (byte)0xd2, (byte)0x1e, (byte)0xbe, 
                        (byte)0x9e, (byte)0x05, (byte)0x67, (byte)0x1d, (byte)0xc5, (byte)0x3f, (byte)0x12, (byte)0x29, 
                        (byte)0x57, (byte)0xb9, (byte)0x67, (byte)0xc6, (byte)0xb2, (byte)0x4b, (byte)0xcb, (byte)0x17, 
                        (byte)0xb6, (byte)0xf9, (byte)0x08, (byte)0x5e, (byte)0x0d, (byte)0x76, (byte)0xcd, (byte)0x75, 
                        (byte)0x57, (byte)0xd5, (byte)0x4d, (byte)0x3d, (byte)0xb6, (byte)0x74, (byte)0xcd, (byte)0x85, 
                        (byte)0x2c, (byte)0x2d, (byte)0xe4, (byte)0x08, (byte)0x24, (byte)0x14, (byte)0x48, (byte)0xb0, 
                        (byte)0x50, (byte)0xc1, (byte)0x76, (byte)0x0e, (byte)0xb5, (byte)0x5b, (byte)0x84, (byte)0x20, 
                        (byte)0x99, (byte)0x3c, (byte)0x39, (byte)0xb8, (byte)0x40, (byte)0xd9, (byte)0x2c, (byte)0x3c, 
                        (byte)0xb4, (byte)0x0d, (byte)0x4b, (byte)0x64, (byte)0x55, (byte)0xf9, (byte)0x4f, (byte)0x03, 
                        (byte)0x72, (byte)0xaf, (byte)0x9c, (byte)0x69, (byte)0x35, (byte)0xe4, (byte)0xc5, (byte)0x09, 
                        (byte)0x02, (byte)0xf5, (byte)0xec, (byte)0xe9, (byte)0x4c, (byte)0x07, (byte)0x3b, (byte)0xb2, 
                        (byte)0xa5, (byte)0x02, (byte)0x54, (byte)0x92, (byte)0xf8, (byte)0xae, (byte)0x56, (byte)0x37, 
                        (byte)0x30, (byte)0x2f, (byte)0xdf, (byte)0x4e, (byte)0x56, (byte)0xb5, (byte)0x24, (byte)0x97, 
                        (byte)0x09, (byte)0x75, (byte)0xf9, (byte)0x2f, (byte)0x70, (byte)0x09, (byte)0xd0, (byte)0xba, 
                        (byte)0x1a, (byte)0xbc, (byte)0xc8, (byte)0x5b, (byte)0xa0, (byte)0x67, (byte)0x23, (byte)0x53, 
                        (byte)0xd7, (byte)0x9a, (byte)0x7c, (byte)0x2a, (byte)0x07, (byte)0x9d, (byte)0xe0, (byte)0xa2, 
                        (byte)0x1c, (byte)0x51, (byte)0x8e, (byte)0x22, (byte)0x69, (byte)0xe6, (byte)0x0b, (byte)0x30, 
                        (byte)0x3d, (byte)0x39, (byte)0x9e, (byte)0x9a, (byte)0x5d, (byte)0x0e, (byte)0x7d, (byte)0xef, 
                        (byte)0xa2, (byte)0xfc, (byte)0x47, (byte)0x09, (byte)0xdb, (byte)0x37, (byte)0x76, (byte)0xdc, 
                        (byte)0x0c, (byte)0xa3, (byte)0x6f, (byte)0xb5, (byte)0x04, (byte)0x98, (byte)0x07, (byte)0x50, 
                        (byte)0x73, (byte)0x4e, (byte)0x15, (byte)0x6e, (byte)0xb7, (byte)0xe2, (byte)0x6f, (byte)0xec, 
                        (byte)0xae, (byte)0x2e, (byte)0xef, (byte)0x48, (byte)0xb4, (byte)0x8a, (byte)0xaf, (byte)0x71, 
                        (byte)0x3d, (byte)0x21, (byte)0x8c, (byte)0x20, (byte)0x7c, (byte)0x32, (byte)0x47, 
                };
                public AESTestVector8(TestHarness h, Provider prov) {
                        super(h, testAESKey, testHighBits, testPlainText, testExpectedCiphertext, prov);
                }
                protected String getDesc() {
                        return "AES Test Vector #8 (1031 byte plaintext)";
                }
        }
}
