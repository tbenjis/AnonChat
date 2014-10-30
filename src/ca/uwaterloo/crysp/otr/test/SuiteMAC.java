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
import ca.uwaterloo.crysp.otr.MAC;
import ca.uwaterloo.crysp.otr.InBuf;
import ca.uwaterloo.crysp.otr.OutBuf;
import ca.uwaterloo.crysp.otr.OTRException;

public class SuiteMAC extends TestSuite
{
	public SuiteMAC(TestHarness h)
	{
		super(h);
		createSuite();
	}
	
	public String getName()
	{
		return "MAC";
	}

	protected void createSuite()
	{
		this.addTestCase(new TestCaseRead(this.harness));
		this.addTestCase(new TestCaseWrite(this.harness));
	}

	private class TestCaseRead extends TestCase
	{
		public TestCaseRead(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			byte[] input = { 
				(byte)0x00, (byte)0x0a, (byte)0x11, (byte)0x18, (byte)0x4d, 
				(byte)0x01, (byte)0x0b, (byte)0x21,	(byte)0x2b, (byte)0x3c, 
				(byte)0x02, (byte)0x0c, (byte)0x31,	(byte)0x3b, (byte)0x2b, 
				(byte)0x03, (byte)0x0d, (byte)0x41,	(byte)0x4b, (byte)0x1a, 
				(byte)0x04, (byte)0xfe  /* extra bytes should not be read */
			};

			InBuf stream = new InBuf(input);
			
			byte[] mac = null;
			try {
				mac = MAC.readMAC(stream);
			} catch (OTRException e) {
				throw new TestException("MAC read failed");
			}

			if(mac.length != MAC.MAC_SIZE) {
				throw new TestException("MAC length mismatch");
			}
			
			for(int i=0; i<mac.length; i++) {
				if(mac[i] != input[i]) {
					throw new TestException("MAC value mismatch");
				}
			}
		}

		public String getDesc()
		{
			return "Read MAC value from InBuf stream";
		}
	}

	private class TestCaseWrite extends TestCase
	{
		public TestCaseWrite(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			byte[] mac = { 
				(byte)0x01, (byte)0x0b, (byte)0x21,	(byte)0x2b, (byte)0x3c, 
				(byte)0x02, (byte)0x0c, (byte)0x31,	(byte)0x3b, (byte)0x2b, 
				(byte)0x00, (byte)0x0a, (byte)0x11, (byte)0x18, (byte)0x4d, 
				(byte)0x03, (byte)0x0d, (byte)0x41,	(byte)0x4b, (byte)0x1a
			};

			byte[] output = new byte[MAC.MAC_SIZE];
			OutBuf stream = new OutBuf(output);
			try {
				stream.writeBytes(mac);
			} catch (OTRException e) {
				throw new TestException("MAC write failed");
			}
	
			for(int i=0; i<mac.length; i++) {
				if(mac[i] != output[i]) {
					throw new TestException("MAC value mismatch");
				}
			}
		}

		public String getDesc()
		{
			return "Write MAC value to OutBuf stream";
		}
	}
}
