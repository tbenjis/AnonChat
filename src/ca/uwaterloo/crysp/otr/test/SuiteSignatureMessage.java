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
import ca.uwaterloo.crysp.otr.Data;
import ca.uwaterloo.crysp.otr.OutBuf;
import ca.uwaterloo.crysp.otr.Util;
import ca.uwaterloo.crysp.otr.message.OTRMessage;
import ca.uwaterloo.crysp.otr.message.SignatureMessage;

public class SuiteSignatureMessage extends TestSuite
{
	public SuiteSignatureMessage(TestHarness h)
	{
		super(h);
		createSuite();
	}
	
	public String getName()
	{
		return "Signature Message";
	}

	protected void createSuite()
	{
		this.addTestCase(new TestCaseReadMessage(this.harness));
		this.addTestCase(new TestCaseWriteMessage(this.harness));
	}

	private class TestCaseReadMessage extends TestCase
	{
		public TestCaseReadMessage(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			byte[] input = new byte[120];
			OutBuf outb = new OutBuf(input);

			/* 1 short version */
			short version = 2;

			/* 1 byte message type */
			byte type = (byte)0x12;

			/* encrypted signature DATA */
			Data encryptedSignature = new Data(new byte[]{
				(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff,
				(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff
			});

			/* Signature MAC */
			byte[] macSignature = {
				(byte)0x00, (byte)0x0a, (byte)0x11, (byte)0x18, 
				(byte)0x4d, (byte)0x01, (byte)0x0b, (byte)0x21,	
				(byte)0x2b, (byte)0x3c, (byte)0x02, (byte)0x0c, 
				(byte)0x31,	(byte)0x3b, (byte)0x2b, (byte)0x03, 
				(byte)0x0d, (byte)0x41,	(byte)0x4b, (byte)0x1a
			};

			try {
				outb.writeShort(version);
				outb.writeByte(type);
				outb.writeData(encryptedSignature);
				outb.writeBytes(macSignature);
			} catch(OTRException e) {
				throw new TestException("OTR message could not be written to buffer");
			}
			
			char[] base64Encoded = outb.encodeBase64();
			String base64EncodedString = new String(base64Encoded);

			SignatureMessage msg = null;
			// Parse message
			try {
				msg = (SignatureMessage)OTRMessage.parse(base64EncodedString);
			} catch (OTRException e) {
				throw new TestException("OTR message parse failed");
			}

			// Check protocol version
			if(msg.getProtocolVersion() != version ) {
				throw new TestException("Protocol version mismatch");
			}

			// Check message type
			if(msg.getType() != OTRMessage.MSG_SIGNATURE) {
				throw new TestException("DataMessage type mismatch");
			} else {
				msg = (SignatureMessage)msg;
			}

			// Check encrypted signature
			if(!msg.getEncryptedSignature().equals(encryptedSignature)) {
				throw new TestException("Encrypted signature mismatch");
			}
			
			// Check MAC signature
			if(!Util.arrayEquals(msg.getMacSignature(), macSignature)) {
				throw new TestException("MAC signature mismatch");
			}
		}

		public String getDesc()
		{
			return "Read Signature Message from InBuf stream";
		}
	}

	private class TestCaseWriteMessage extends TestCase
	{
		public TestCaseWriteMessage(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			int array_size = 120;
			byte[] input = new byte[array_size];
			OutBuf outb = new OutBuf(input);

			/* 1 short version */
			short version = 2;

			/* 1 byte message type */
			byte type = (byte)0x12;

			/* encrypted signature DATA */
			Data encryptedSignature = new Data(new byte[]{
				(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff,
				(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff
			});

			/* Signature MAC */
			byte[] macSignature = {
				(byte)0x00, (byte)0x0a, (byte)0x11, (byte)0x18, 
				(byte)0x4d, (byte)0x01, (byte)0x0b, (byte)0x21,	
				(byte)0x2b, (byte)0x3c, (byte)0x02, (byte)0x0c, 
				(byte)0x31,	(byte)0x3b, (byte)0x2b, (byte)0x03, 
				(byte)0x0d, (byte)0x41,	(byte)0x4b, (byte)0x1a
			};

			try {
				outb.writeShort(version);
				outb.writeByte(type);
				outb.writeData(encryptedSignature);
				outb.writeBytes(macSignature);
			} catch(OTRException e) {
				throw new TestException("OTR message could not be written to buffer");
			}
			
			char[] base64Encoded = outb.encodeBase64();
			String base64EncodedString = new String(base64Encoded);
			
			SignatureMessage msg = null;
			// Parse message
			try {
				msg = (SignatureMessage)OTRMessage.parse(base64EncodedString);
			} catch (OTRException e) {
				throw new TestException("Signature message parse failed");
			}
			
			byte[] output = new byte[array_size];
			OutBuf ostream = new OutBuf(output);

			try {
				msg.write(ostream);
			} catch (OTRException e) {
				throw new TestException("Signature message write failed");
			}

			for(int i=0; i<output.length; i++) {
				if(output[i] != input[i]) {
					throw new TestException("Signature message value mismatch");
				}
			}
		}

		public String getDesc()
		{
			return "Write Signature Message to OutBuf stream";
		}
	}
}
