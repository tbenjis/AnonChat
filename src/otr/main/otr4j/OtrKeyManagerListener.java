package otr.main.otr4j;

import otr.main.otr4j.session.SessionID;

public interface OtrKeyManagerListener {
	public abstract void verificationStatusChanged(SessionID session);
}
