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
import ca.uwaterloo.crysp.otr.InBuf;
import ca.uwaterloo.crysp.otr.OutBuf;
import ca.uwaterloo.crysp.otr.crypt.MPI;
import ca.uwaterloo.crysp.otr.message.DHKeyMessage;
import ca.uwaterloo.crysp.otr.message.OTRMessage;

public class SuiteDHKeyMessage extends TestSuite
{
	public SuiteDHKeyMessage(TestHarness h)
	{
		super(h);
		createSuite();
	}
	
	public String getName()
	{
		return "DH Key Message";
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
			byte type = (byte)0x0a;

			/* 1 MPI encrypted G^y */
			MPI encryptedGy = null;
			try {
				encryptedGy = MPI.readMPI(
					new InBuf( 
						new byte[]{
							/* value with leading zeroes */	
							(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x08,	
							(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01,	
							(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff
						}
					)
				);
			} catch(OTRException e) {
				throw new TestException("Could not create MPI for encrypted Gy \n" + e);
			}

			try {
				outb.writeShort(version);
				outb.writeByte(type);
				encryptedGy.write(outb);
			} catch(OTRException e) {
				throw new TestException("OTR message could not be written to buffer");
			}
			
			char[] base64Encoded = outb.encodeBase64();
			String base64EncodedString = new String(base64Encoded);

			DHKeyMessage msg = null;
			// Parse message
			try {
				msg = (DHKeyMessage)OTRMessage.parse(base64EncodedString);
			} catch (OTRException e) {
				throw new TestException("OTR message parse failed");
			}

			// Check protocol version
			if(msg.getProtocolVersion() != version ) {
				throw new TestException("Protocol version mismatch");
			}

			// Check message type
			if(msg.getType() != OTRMessage.MSG_DH_KEY) {
				throw new TestException("SignatureMessage type mismatch");
			}
			
			// Check encrypted Gy
			if(!msg.getGy().equals(encryptedGy)) {
				throw new TestException("Encrypted Gy mismatch");
			}
		}

		public String getDesc()
		{
			return "Read DH Key Message from InBuf stream";
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
			byte type = (byte)0x0a;

			/* 1 MPI encrypted G^y */
			MPI encryptedGy = null;
			try {
				encryptedGy = MPI.readMPI(
					new InBuf( 
						new byte[]{
							/* value with leading zeroes */	
							(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01,	
							(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff
						}
					)
				);
			} catch(OTRException e) {
				throw new TestException("Could not create MPI for encrypted Gy");
			}

			try {
				outb.writeShort(version);
				outb.writeByte(type);
				encryptedGy.write(outb);
			} catch(OTRException e) {
				throw new TestException("OTR message could not be written to buffer");
			}
			
			char[] base64Encoded = outb.encodeBase64();
			String base64EncodedString = new String(base64Encoded);
			
			DHKeyMessage msg = null;
			// Parse message
			try {
				msg = (DHKeyMessage)OTRMessage.parse(base64EncodedString);
			} catch (OTRException e) {
				throw new TestException("OTR message parse failed");
			}
			
			byte[] output = new byte[array_size];
			OutBuf ostream = new OutBuf(output);

			try {
				msg.write(ostream);
			} catch (OTRException e) {
				throw new TestException("DH Key message write failed");
			}

			for(int i=0; i<output.length; i++) {
				if(output[i] != input[i]) {
					throw new TestException("DH Key message value mismatch");
				}
			}
		}

		public String getDesc()
		{
			return "Write DH Key Message to OutBuf stream";
		}
	}
}
