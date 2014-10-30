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
import ca.uwaterloo.crysp.otr.OutBuf;
import ca.uwaterloo.crysp.otr.message.OTRMessage;

public class SuiteQueryMessage extends TestSuite
{
	private String msg1 = "?OTRv2";
	private String msg2 = "?OTRv";
	private String msg3 = "?OTR?";
	
	public SuiteQueryMessage(TestHarness h)
	{
		super(h);
		createSuite();
	}
	
	public String getName()
	{
		return "Query Message";
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
			OTRMessage otr;
			
			// msg1 is a query message for version 2
			try {
				otr = OTRMessage.parse(msg1);
				if (otr.getType() != OTRMessage.MSG_QUERY) {
					throw new TestException(msg1 + " was not classified as an OTR query message!");
				}
			} catch (OTRException e) {
				throw new TestException("Exception when parsing " + msg1);
			}
			
			// msg2 is a query message
			try {
				otr = OTRMessage.parse(msg2);
				if (otr.getType() != OTRMessage.MSG_QUERY) {
					throw new TestException(msg2 + " was not classified as an OTR query message!");
				}
			} catch (OTRException e) {
				throw new TestException("Exception when parsing " + msg2);
			}
			
			// msg3 isn't a query message; ignore OTR version 1.
			try {
				otr = OTRMessage.parse(msg3);
				if (otr != null) {
					throw new TestException(msg3 + " was not supposed to be a valid OTR message!");
				}
			} catch (OTRException e) {
				throw new TestException("Exception when parsing " + msg3);
			}
		}

		public String getDesc()
		{
			return "Read OTR Query message";
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
			OTRMessage otr;
			
			// msg1 is a query message for version 2
			try {
				otr = OTRMessage.parse(msg1);
				byte[] output = new byte[100];
				OutBuf buf = new OutBuf(output);
				otr.write(buf);
				
				// Verify that output message is correct
				if (!(new String(output).trim().equals(msg1))) {
					throw new TestException("Incorrect serialization of msg1");
				}
			} catch (OTRException e) {
				throw new TestException("Exception when parsing " + msg1);
			}
			
			// msg2 is a query message
			try {
				otr = OTRMessage.parse(msg2);
				byte[] output = new byte[100];
				OutBuf buf = new OutBuf(output);
				otr.write(buf);
				
				// Verify that output message is correct
				if (!(new String(output).trim().equals(msg2))) {
					throw new TestException("Incorrect serialization of msg2");
				}
			} catch (OTRException e) {
				throw new TestException("Exception when parsing " + msg2);
			}
		}

		public String getDesc()
		{
			return "Write OTR Query message";
		}
	}
}
