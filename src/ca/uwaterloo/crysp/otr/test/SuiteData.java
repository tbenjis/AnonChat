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
import ca.uwaterloo.crysp.otr.Data;
import ca.uwaterloo.crysp.otr.InBuf;
import ca.uwaterloo.crysp.otr.OutBuf;
import ca.uwaterloo.crysp.otr.OTRException;

public class SuiteData extends TestSuite
{
	public SuiteData(TestHarness h)
	{
		super(h);
		createSuite();
	}
	
	public String getName()
	{
		return "Data";
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

			byte[] input = { (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x04, /* 4 byte length */
							(byte)0x2b, (byte)0xa4, (byte)0x0f, (byte)0xff /* value */};
			InBuf stream = new InBuf(input);
			
			Data data = null;
			try {
				data = stream.readData();
			} catch (OTRException e) {
				throw new TestException("Data read failed");
			}

			if(data.getLength() != 4) {
				throw new TestException("Data length mismatch");
			}

			byte[] value = data.getValue();

			if(value[0] != (byte)0x2b
				|| value[1] != (byte)0xa4
				|| value[2] != (byte)0x0f
				|| value[3] != (byte)0xff) {
				
				throw new TestException("Data value mismatch");
			}
		}

		public String getDesc()
		{
			return "Read a Data object from InBuf stream";
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
			byte[] value = { (byte)0x2b, (byte)0xa4, 
							(byte)0x0f, (byte)0xff};
			Data data = new Data(value);

			byte[] output = new byte[4 + value.length];
			OutBuf stream = new OutBuf(output);
			try {
				stream.writeData(data);
			} catch (OTRException e) {
				throw new TestException("Data write failed");
			}

			if(output[0] != (byte)0x00
				|| output[1] != (byte)0x00
				|| output[2] != (byte)0x00
				|| output[3] != (byte)0x04
				|| output[4] != (byte)0x2b
				|| output[5] != (byte)0xa4
				|| output[6] != (byte)0x0f
				|| output[7] != (byte)0xff) {
				
				throw new TestException("Data value mismatch");
			}
		}

		public String getDesc()
		{
			return "Write a Data object to OutBuf stream";
		}
	}
}
