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
import ca.uwaterloo.crysp.otr.message.DHCommitMessage;
import ca.uwaterloo.crysp.otr.message.OTRMessage;

public class SuiteDHCommitMessage extends TestSuite
{
	public SuiteDHCommitMessage(TestHarness h)
	{
		super(h);
		createSuite();
	}
	
	public String getName()
	{
		return "DH Commit Message";
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
			byte type = (byte)0x02;

			/* encrypted Gx */
			Data encryptedGx = new Data(new byte[]{
				(byte)0x20, (byte)0x04, (byte)0x1f, (byte)0xf4
			});
			
			/* hashed Gx */
			Data hashedGx = new Data(new byte[]{
				(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff
			});

			try {
				outb.writeShort(version);
				outb.writeByte(type);
				outb.writeData(encryptedGx);
				outb.writeData(hashedGx);
			} catch(OTRException e) {
				throw new TestException("OTR message could not be written to buffer");
			}
			
			char[] base64Encoded = outb.encodeBase64();
			String base64EncodedString = new String(base64Encoded);
			
			DHCommitMessage msg = null;
			// Parse message
			try {
				msg = (DHCommitMessage)OTRMessage.parse(base64EncodedString);
			} catch (OTRException e) {
				throw new TestException("OTR message parse failed");
			}

			// Check protocol version
			if(msg.getProtocolVersion() != version ) {
				throw new TestException("Protocol version mismatch");
			}

			// Check message type
			if(msg.getType() != OTRMessage.MSG_DH_COMMIT) {
				throw new TestException("DataMessage type mismatch");
			} else {
				msg = (DHCommitMessage)msg;
			}

			// Check encrypted Gx
			if(!msg.getEncryptedGx().equals(encryptedGx)) {
				throw new TestException("Encrypted Gx mismatch");
			}
			
			// Check hashed Gx
			if(!msg.getHashedGx().equals(hashedGx)) {
				throw new TestException("Hashed Gx mismatch");
			}
		}

		public String getDesc()
		{
			return "Read DH Commit Message from InBuf stream";
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
			int array_size = 64;
			byte[] input = new byte[array_size];
			OutBuf outb = new OutBuf(input);

			/* 1 short version */
			short version = 2;

			/* 1 byte message type */
			byte type = (byte)0x02;

			/* encrypted Gx */
			Data encryptedGx = new Data(new byte[]{
				(byte)0x20, (byte)0x04, (byte)0x1f, (byte)0xf4
			});
			
			/* hashed Gx */
			Data hashedGx = new Data(new byte[]{
				(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff
			});

			try {
				outb.writeShort(version);
				outb.writeByte(type);
				outb.writeData(encryptedGx);
				outb.writeData(hashedGx);
			} catch(OTRException e) {
				throw new TestException("OTR message could not be written to buffer");
			}
			
			char[] base64Encoded = outb.encodeBase64();
			String base64EncodedString = new String(base64Encoded);
			
			DHCommitMessage msg = null;
			// Parse message
			try {
				msg = (DHCommitMessage)OTRMessage.parse(base64EncodedString);
			} catch (OTRException e) {
				throw new TestException("OTR message parse failed");
			}	

			byte[] output = new byte[array_size];
			OutBuf ostream = new OutBuf(output);

			try {
				msg.write(ostream);
			} catch (OTRException e) {
				throw new TestException("DH Commit message write failed");
			}

			for(int i=0; i<output.length; i++) {
				if(output[i] != input[i]) {
					throw new TestException("DH Commit message value mismatch");
				}
			}

		}

		public String getDesc()
		{
			return "Write DH Commit Message to OutBuf stream";
		}
	}
}
