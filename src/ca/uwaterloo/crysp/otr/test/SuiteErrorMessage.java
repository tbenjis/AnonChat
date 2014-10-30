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
import ca.uwaterloo.crysp.otr.message.ErrorMessage;
import ca.uwaterloo.crysp.otr.message.OTRMessage;

public class SuiteErrorMessage extends TestSuite
{
	private String errorMessage = "this is my error message";
	private String otrmsg = "?OTR Error:" + errorMessage;
	
	public SuiteErrorMessage(TestHarness h)
	{
		super(h);
		createSuite();
	}
	
	public String getName()
	{
		return "Error Message";
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
			
			try {
				otr = OTRMessage.parse(otrmsg);
				if (otr.getType() != OTRMessage.MSG_ERROR) {
					throw new TestException(otrmsg + " was not classified as an OTR error message!");
				}
				ErrorMessage emsg = (ErrorMessage)otr;
				// Verify that error message was correct
				if (!emsg.getErrorMessage().equals(errorMessage)) {
					throw new TestException("Error message was not parsed correctly!");
				}
			} catch (OTRException e) {
				throw new TestException("Exception when parsing " + otrmsg);
			}
		}

		public String getDesc()
		{
			return "Read OTR error message";
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
			
			try {
				otr = OTRMessage.parse(otrmsg);
				
				byte[] output = new byte[100];
				OutBuf buf = new OutBuf(output);
				otr.write(buf);
				
				// Verify that output message is correct
				if (!(new String(output).trim().equals(otrmsg))) {
					throw new TestException("Incorrect serialization of message");
				}
			} catch (OTRException e) {
				throw new TestException("Exception when parsing " + otrmsg);
			}
		}

		public String getDesc()
		{
			return "Write OTR error message";
		}
	}
}
