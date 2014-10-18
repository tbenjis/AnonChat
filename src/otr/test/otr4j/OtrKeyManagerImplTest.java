package otr.test.otr4j;


import otr.main.otr4j.OtrKeyManager;
import otr.main.otr4j.OtrKeyManagerImpl;
import otr.main.otr4j.session.SessionID;

public class OtrKeyManagerImplTest extends junit.framework.TestCase {

	private SessionID aliceSessionID = new SessionID("Alice@Wonderland",
			"Bob@Wonderland", "Scytale");

	public void test() throws Exception {
		OtrKeyManager keyManager = new OtrKeyManagerImpl("otr.properties");
		keyManager.generateLocalKeyPair(aliceSessionID);
		System.out.println(aliceSessionID);

		keyManager.verify(aliceSessionID);
		assert (keyManager.isVerified(aliceSessionID));
	}
}
