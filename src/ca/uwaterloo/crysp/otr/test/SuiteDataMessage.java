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
import ca.uwaterloo.crysp.otr.InBuf;
import ca.uwaterloo.crysp.otr.OutBuf;
import ca.uwaterloo.crysp.otr.Util;
import ca.uwaterloo.crysp.otr.crypt.MPI;
import ca.uwaterloo.crysp.otr.message.DataMessage;
import ca.uwaterloo.crysp.otr.message.OTRMessage;


public class SuiteDataMessage extends TestSuite
{
	public SuiteDataMessage(TestHarness h)
	{
		super(h);
		createSuite();
	}
	
	public String getName()
	{
		return "Data Message";
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
			byte type = (byte)0x03;

			/* 1 byte flag */
			byte flag = (byte)0xaf;

			/* 1 int sender key id */
			long senderKeyId = 82735;

			/* 1 int recipient key id */
			long recipientKeyId = 983798;

			/* 1 MPI DH y */
			MPI nextKey = null;
			try {
				nextKey = MPI.readMPI(
					new InBuf( 
						new byte[]{
							/* value with leading zeroes */	
							(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x04,	
							(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff
						}
					)
				);
			} catch(OTRException e) {
				throw new TestException("Could not create MPI for next key");
			}

			/* Top half of counter init */
			byte[] ctrInit = {
				(byte)0x00, (byte)0x0a, (byte)0x11, (byte)0x18,
				(byte)0x01, (byte)0x0b, (byte)0x21,	(byte)0x2b
			};

			/* encrypted message DATA */
			Data encryptedMsg = new Data(new byte[]{
				(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff
			});

			/* authenticator MAC */
			byte[] authenticator = {
				(byte)0x00, (byte)0x0a, (byte)0x11, (byte)0x18, 
				(byte)0x4d, (byte)0x01, (byte)0x0b, (byte)0x21,	
				(byte)0x2b, (byte)0x3c, (byte)0x02, (byte)0x0c, 
				(byte)0x31,	(byte)0x3b, (byte)0x2b, (byte)0x03, 
				(byte)0x0d, (byte)0x41,	(byte)0x4b, (byte)0x1a
			};

			/* Old MAC keys as DATA */
			Data oldMacKeys = new Data(new byte[]{
				(byte)0x00, (byte)0x0a, (byte)0x11, (byte)0x18, 
				(byte)0x2b, (byte)0x3c, (byte)0x02, (byte)0x0c, 
				(byte)0x31,	(byte)0x3b, (byte)0x2b, (byte)0x03, 
				(byte)0x00, (byte)0x0a, (byte)0x11, (byte)0x18, 
				(byte)0x4d, (byte)0x01, (byte)0x0b, (byte)0x21,	
				(byte)0x2b, (byte)0x3c, (byte)0x02, (byte)0x0c, 
				(byte)0x0d, (byte)0x41,	(byte)0x4b, (byte)0x1a, 
				(byte)0x31,	(byte)0x3b, (byte)0x2b, (byte)0x03, 
				(byte)0x4d, (byte)0x01, (byte)0x0b, (byte)0x21,	
				(byte)0x0d, (byte)0x41,	(byte)0x4b, (byte)0x1a, 
				(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff
			});

			try {
				outb.writeShort(version);
				outb.writeByte(type);
				outb.writeByte(flag);
				outb.writeUInt(senderKeyId);
				outb.writeUInt(recipientKeyId);
				nextKey.write(outb);
				outb.writeBytes(ctrInit);
				outb.writeData(encryptedMsg);
				outb.writeBytes(authenticator);
				outb.writeData(oldMacKeys);
			} catch(OTRException e) {
				throw new TestException("OTR message could not be written to buffer");
			}
			
			char[] base64Encoded = outb.encodeBase64();
			String base64EncodedString = new String(base64Encoded);

			DataMessage msg = null;
			// Parse message
			try {
				msg = (DataMessage)OTRMessage.parse(base64EncodedString);
			} catch (OTRException e) {
				throw new TestException("OTR message parse failed");
			}

			// Check protocol version
			if(msg.getProtocolVersion() != version ) {
				throw new TestException("Protocol version mismatch");
			}

			// Check message type
			if(msg.getType() != OTRMessage.MSG_DATA) {
				throw new TestException("DataMessage type mismatch");
			} else {
				msg = (DataMessage)msg;
			}

			// Check flags
			if(msg.getFlags() != flag) {
				throw new TestException("Flag mismatch");
			}

			// Check sender key id
			if(msg.getSenderKeyId() != senderKeyId) {
				throw new TestException("Sender Key Id mismatch");
			}

			// Check recipient key id
			if(msg.getRecipientKeyId() != recipientKeyId) {
				throw new TestException("Recipient Key Id mismatch");
			}

			// Check next public key for sender
			if(!msg.getNextSenderKey().equals(nextKey)) {
				throw new TestException("Next sender key mismatch");
			}
			
			// Check top half of counter init
			if(!Util.arrayEquals(msg.getCounterInit(), ctrInit)) {
				throw new TestException("Counter init mismatch");
			}
			
			// Check encrypted message
			if(!msg.getEncryptedMessage().equals(encryptedMsg)) {
				throw new TestException("Encrypted message mismatch");
			}
			
			// Check MAC authenticator
			if(!Util.arrayEquals(msg.getAuthenticator(), authenticator)) {
				throw new TestException("MAC authenticator mismatch");
			}
			
			// Check old MAC keys
			if(!msg.getOldKeys().equals(oldMacKeys)) {
				throw new TestException("Old MAC keys mismatch");
			}

		}

		public String getDesc()
		{
			return "Read Data Message from InBuf stream";
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
			byte type = (byte)0x03;

			/* 1 byte flag */
			byte flag = (byte)0xaf;

			/* 1 int sender key id */
			long senderKeyId = 82735;

			/* 1 int recipient key id */
			long recipientKeyId = 983798;

			/* 1 MPI DH y */
			MPI nextKey = null;
			try {
				nextKey = MPI.readMPI(
					new InBuf( 
						new byte[]{
							/* value with leading zeroes */	
							(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x08,	
							(byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00,	
							(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff
						}
					)
				);
			} catch(OTRException e) {
				throw new TestException("Could not create MPI for next key");
			}

			/* Top half of counter init */
			byte[] ctrInit = {
				(byte)0x00, (byte)0x0a, (byte)0x11, (byte)0x18,
				(byte)0x01, (byte)0x0b, (byte)0x21,	(byte)0x2b
			};

			/* encrypted message DATA */
			Data encryptedMsg = new Data(new byte[]{
				(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff
			});

			/* authenticator MAC */
			byte[] authenticator = {
				(byte)0x00, (byte)0x0a, (byte)0x11, (byte)0x18, 
				(byte)0x4d, (byte)0x01, (byte)0x0b, (byte)0x21,	
				(byte)0x2b, (byte)0x3c, (byte)0x02, (byte)0x0c, 
				(byte)0x31,	(byte)0x3b, (byte)0x2b, (byte)0x03, 
				(byte)0x0d, (byte)0x41,	(byte)0x4b, (byte)0x1a
			};

			/* Old MAC keys as DATA */
			Data oldMacKeys = new Data(new byte[]{
				(byte)0x00, (byte)0x0a, (byte)0x11, (byte)0x18, 
				(byte)0x2b, (byte)0x3c, (byte)0x02, (byte)0x0c, 
				(byte)0x31,	(byte)0x3b, (byte)0x2b, (byte)0x03, 
				(byte)0x00, (byte)0x0a, (byte)0x11, (byte)0x18, 
				(byte)0x4d, (byte)0x01, (byte)0x0b, (byte)0x21,	
				(byte)0x2b, (byte)0x3c, (byte)0x02, (byte)0x0c, 
				(byte)0x0d, (byte)0x41,	(byte)0x4b, (byte)0x1a, 
				(byte)0x31,	(byte)0x3b, (byte)0x2b, (byte)0x03, 
				(byte)0x4d, (byte)0x01, (byte)0x0b, (byte)0x21,	
				(byte)0x0d, (byte)0x41,	(byte)0x4b, (byte)0x1a, 
				(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff
			});

			try {
				outb.writeShort(version);
				outb.writeByte(type);
				outb.writeByte(flag);
				outb.writeUInt(senderKeyId);
				outb.writeUInt(recipientKeyId);
				nextKey.write(outb);
				outb.writeBytes(ctrInit);
				outb.writeData(encryptedMsg);
				outb.writeBytes(authenticator);
				outb.writeData(oldMacKeys);
			} catch(OTRException e) {
				throw new TestException("OTR message could not be written to buffer");
			}
			
			char[] base64Encoded = outb.encodeBase64();
			String base64EncodedString = new String(base64Encoded);
			
			DataMessage msg = null;
			// Parse message
			try {
				msg = (DataMessage)OTRMessage.parse(base64EncodedString);
			} catch (OTRException e) {
				throw new TestException("Data message parse failed");
			}
			
			byte[] output = new byte[array_size];
			OutBuf ostream = new OutBuf(output);

			try {
				msg.write(ostream);
			} catch (OTRException e) {
				throw new TestException("Data message write failed");
			}

			for(int i=0; i<output.length; i++) {
				if(output[i] != input[i]) {
					throw new TestException("Data message value mismatch");
				}
			}

		}

		public String getDesc()
		{
			return "Write Data Message to OutBuf stream";
		}
	}
}
