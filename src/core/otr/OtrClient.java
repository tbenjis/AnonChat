package core.otr;

import otr.main.otr4j.OtrException;
import otr.main.otr4j.OtrPolicy;
import otr.main.otr4j.session.Session;
import otr.main.otr4j.session.SessionID;
import otr.main.otr4j.session.SessionImpl;

import core.Buddy;

/**
 * Created by gp on 2/5/14.
 */
public class OtrClient {

	private final String account;
	private Session session;
	OtrPolicy policy;

	public OtrClient(String account) {
		this.account = account;
	}

	public Session getSession() {
		return session;
	}

	public String getAccount() {
		return account;
	}

	public void setPolicy(OtrPolicy policy) {
		this.policy = policy;
	}

	public String sendOTRMessage(String recipient, String s) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account,
					recipient, "AnonChatProtocol");
			session = new SessionImpl(sessionID, new OtrEngineHostImpl());
		}

		String outgoingMessage = session.transformSending(s);
		return outgoingMessage;
	}

	public void exit() throws OtrException {
		if (session != null)
			session.endSession();
	}

	public void secureSession(String recipient) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account,
					recipient, "AnonChatProtocol");
			session = new SessionImpl(sessionID, new OtrEngineHostImpl());
		}

		session.startSession();
	}


	public String getOTRMessage(Buddy b, String m) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account, b.getAddress(),
					"AnonChatProtocol");
			session = new SessionImpl(sessionID, new OtrEngineHostImpl());
		}

		String receivedMessage = session.transformReceiving(m);
		return receivedMessage;

	}

}
