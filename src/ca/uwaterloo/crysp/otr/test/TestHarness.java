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

import java.util.Vector;
import ca.uwaterloo.crysp.otr.crypt.Provider;

public class TestHarness {
	private boolean verbose; // defines whether test details should be printed
	private int testCases; // total test cases run
	private int testSuccess; // number of test cases that succeeded
	private int testFailed; // number of test cases that failed
	private Vector testList; // list of tests
	private int activeCount; // stores the active test case number

	public static String execute(Provider prov) {
		// TODO get verbose option from command line argument
		boolean verbose = true;
		TestHarness th = new TestHarness(verbose);

		// add test cases and test suites
		th.addTest(new TestExample(th));

		// Crypt library
		th.addTest(new TestDSA(th, prov));
		th.addTest(new TestSHA1(th, prov));
		th.addTest(new TestSHA256(th, prov));
		th.addTest(new TestHMAC(th, prov));
		th.addTest(new TestAESCTR(th, prov));
		th.addTest(new TestDH(th, prov));

		// Base data structures
		th.addTest(new SuiteData(th));
		th.addTest(new SuiteMPI(th));
		th.addTest(new SuiteMAC(th));
		th.addTest(new SuiteCTR(th));

		// OTR Messages
		th.addTest(new SuiteDataMessage(th));
		th.addTest(new SuiteDHCommitMessage(th));
		th.addTest(new SuiteDHKeyMessage(th));
		th.addTest(new SuiteErrorMessage(th));
		th.addTest(new SuiteQueryMessage(th));
		th.addTest(new SuiteRevealSignatureMessage(th));
		th.addTest(new SuiteSignatureMessage(th));
		th.addTest(new SuiteTaggedPlaintextMessage(th));

		// execute tests and return results
		String ret=th.executeTests();
		ret+=th.printSummary();
		return ret;
	}

	public TestHarness(boolean verbose) {
		this.verbose = verbose;
		this.testCases = 0;
		this.testSuccess = 0;
		this.testFailed = 0;
		this.activeCount = 0;
		this.testList = new Vector();
	}

	public void addTest(ITest t) {
		this.testList.addElement(t);
	}

	public String notifyTestSuite(String testSuite, int testCases) {
		String ret="";
		if (verbose) {
			ret+="------------------------------------------------- \n";
			ret+="Suite: " + testSuite + " [" + testCases + " case";
			if (testCases > 1)
				ret+="s";
			ret+="]\n";
		}
		return ret;
	}

	public void notifyTestCaseCreated() {
		this.testCases++;
	}

	public String notifyTestSuccess(String testDesc) {
		this.testSuccess++;
		this.activeCount++;

		if (this.verbose) {
			return "[ Success ] - " + testDesc + "\n";
		}
		return "";
	}

	public String notifyTestFailure(String testDesc, Exception e) {
		this.testFailed++;
		this.activeCount++;
		String ret="";
		if (verbose) {
			ret+="[ Failed  ] - " + testDesc + "\n";
			if (e instanceof TestException) {
				ret+="** -> Error: " + e.getMessage() + "\n";
			} else {
				ret+="** -> Runtime exception: " + e.getMessage()+"\n";
				ret+="-------------- Stack trace start -------------\n";
				e.printStackTrace();
				ret+="-------------- Stack trace end ---------------\n";
			}
		}
		return ret;
	}

	public String executeTests() {
		String ret = "";
		ret += "=================================================\n";
		ret += "Starting harness to test " + this.testCases + " cases...\n";
		ITest test;
		for (int i = 0; i < this.testList.size(); ++i) {
			test = (ITest) this.testList.elementAt(i);
			ret+=test.run();
		}
		return ret;
	}

	public String printSummary() {
		String ret = "";
		ret += "=================================================\n";
		ret += " Total tests:     " + this.testCases + "\n";
		ret += " Total succeeded: " + this.testSuccess + "\n";
		ret += " Total failed:    " + this.testFailed + "\n";
		ret += " Total skipped:   " + (this.testCases - this.activeCount)
				+ "\n";
		ret += "=================================================\n";
		return ret;
	}

}
