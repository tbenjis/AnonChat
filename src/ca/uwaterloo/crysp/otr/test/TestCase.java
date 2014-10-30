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

public abstract class TestCase implements ITest
{
	//private String testDescription;		// description of the test case
	private TestHarness harness;		// test harness to notify test results

	protected abstract void runTest() throws TestException;
	protected abstract String getDesc();

	public TestCase(TestHarness h)
	{
		this.harness = h;
		h.notifyTestCaseCreated();
	}

	public String run()
	{
		try {
			this.runTest();
		} catch (Exception e) {
			return harness.notifyTestFailure(this.getDesc(), e);
		}
		return harness.notifyTestSuccess(this.getDesc());
	}
}
