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
import ca.uwaterloo.crysp.otr.message.TaggedPlaintextMessage;

public class SuiteTaggedPlaintextMessage extends TestSuite
{
	public SuiteTaggedPlaintextMessage(TestHarness h)
	{
		super(h);
		createSuite();
	}
	
	public String getName()
	{
		return "Tagged plaintext message";
	}

	protected void createSuite()
	{
		this.addTestCase(new TestReadTaggedPlaintext(this.harness));
		this.addTestCase(new TestWriteTaggedPlaintext(this.harness));
	}

	private class TestReadTaggedPlaintext extends TestCase
	{
		public TestReadTaggedPlaintext(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			String taggedPlaintext = "aa \t  \t\t\t\t \t \t \t  bb";
			String normalMessage = "My normal message here.";
			String anotherNormalMessage = " \t  \t\ta\t\t \t \t \t  ";
			
			try {
				OTRMessage msg = OTRMessage.parse(taggedPlaintext);
				if (!(msg instanceof TaggedPlaintextMessage)) {
					throw new TestException(taggedPlaintext + " was not identified as a tagged plaintext message!");
				}
			} catch (OTRException e) {
				throw new TestException("Exception when parsing: " + taggedPlaintext);
			}
			
			try {
				OTRMessage.parse(normalMessage);
				/*if (msg != null) {
					throw new TestException(normalMessage + " was mistakenly identified as an OTR message!");
				}*/
			} catch (OTRException e) {
				throw new TestException("Exception when parsing: " + normalMessage);
			}
			
			try {
				OTRMessage.parse(anotherNormalMessage);
				/*if (msg != null) {
					throw new TestException(anotherNormalMessage + " was mistakenly identified as an OTR message!");
				}*/
			} catch (OTRException e) {
				throw new TestException("Exception when parsing: " + anotherNormalMessage);
			}
		}

		public String getDesc()
		{
			return "Reading tagged plaintext messages";
		}
	}
	
	private class TestWriteTaggedPlaintext extends TestCase
	{
		public TestWriteTaggedPlaintext(TestHarness h)
		{	
			super(h);
		}

		protected void runTest() throws TestException
		{
			String taggedPlaintext = "aa \t  \t\t\t\t \t \t \t  bb";
			
			try {
				OTRMessage msg = OTRMessage.parse(taggedPlaintext);
				byte[] output = new byte[100];
				OutBuf buf = new OutBuf(output);
				msg.write(buf);
				
				// Verify that output message is correct
				if (!(new String(output).trim().equals(taggedPlaintext))) {
					throw new TestException("Incorrect serialization of taggedPlaintext");
				}
			} catch (OTRException e) {
				throw new TestException("Exception when parsing: " + taggedPlaintext);
			}
		}

		public String getDesc()
		{
			return "Writing tagged plaintext messages";
		}
	}
}
