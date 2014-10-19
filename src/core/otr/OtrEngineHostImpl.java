package core.otr;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import core.Buddy;
import core.Logger;
import otr.main.otr4j.OtrEngineHost;
import otr.main.otr4j.OtrException;
import otr.main.otr4j.OtrPolicy;
import otr.main.otr4j.crypto.OtrCryptoEngineImpl;
import otr.main.otr4j.crypto.OtrCryptoException;
import otr.main.otr4j.session.InstanceTag;
import otr.main.otr4j.session.SessionID;

public class OtrEngineHostImpl implements OtrEngineHost {
	OtrClient c;
	 Buddy b;

	public void injectMessage(SessionID sessionID, String msg)
			throws OtrException {
		OtrClient c = new OtrClient(b.getAddress());

		//c.sendOTRMessage(b, msg);

		String msgDisplay = (msg.length() > 10) ? msg.substring(0, 10) + "..."
				: msg;
		Logger.log(Logger.INFO, this, "IM injects message: " + msgDisplay);
	}

	public void smpError(SessionID sessionID, int tlvType, boolean cheated)
			throws OtrException {
		Logger.log(Logger.SEVERE, this,"SM verification error with user: " + sessionID);
	}

	public void smpAborted(SessionID sessionID) throws OtrException {
		Logger.log(Logger.SEVERE, this,"SM verification has been aborted by user: " + sessionID);
	}

	public void finishedSessionMessage(SessionID sessionID, String msgText)
			throws OtrException {
		Logger.log(Logger.SEVERE, this,"SM session was finished. You shouldn't send messages to: "
				+ sessionID);
	}

	public void finishedSessionMessage(SessionID sessionID) throws OtrException {
		Logger.log(Logger.SEVERE, this,"SM session was finished. You shouldn't send messages to: "
				+ sessionID);
	}

	public void requireEncryptedMessage(SessionID sessionID, String msgText)
			throws OtrException {
		Logger.log(Logger.SEVERE, this,"Message can't be sent while encrypted session is not established: "
				+ sessionID);
	}

	public void unreadableMessageReceived(SessionID sessionID)
			throws OtrException {
		Logger.log(Logger.WARNING, this,"Unreadable message received from: " + sessionID);
	}

	public void unencryptedMessageReceived(SessionID sessionID, String msg)
			throws OtrException {
		Logger.log(Logger.WARNING, this,"Unencrypted message received: " + msg + " from "
				+ sessionID);
	}

	public void showError(SessionID sessionID, String error)
			throws OtrException {
		Logger.log(Logger.SEVERE, this,"IM shows error to user: " + error);
	}

	public String getReplyForUnreadableMessage() {
		return "You sent me an unreadable encrypted message.";
	}

	public void sessionStatusChanged(SessionID sessionID) {
		// don't care.
	}

	public KeyPair getLocalKeyPair(SessionID paramSessionID) {
		KeyPairGenerator kg;
		try {
			kg = KeyPairGenerator.getInstance("DSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		return kg.genKeyPair();
	}

	public OtrPolicy getSessionPolicy(SessionID ctx) {
		return c.policy;
	}

	public void askForSecret(SessionID sessionID, String question) {
		Logger.log(Logger.INFO, this,"Ask for secret from: " + sessionID + ", question: "
				+ question);
	}

	public void verify(SessionID sessionID, boolean approved) {
		Logger.log(Logger.INFO, this,"Session was verified: " + sessionID);
		if (!approved)
			Logger.log(Logger.INFO, this,"Your answer for the question was verified."
					+ "You should ask your opponent too or check shared secret.");
	}

	public void unverify(SessionID sessionID) {
		Logger.log(Logger.FATAL, this,"Session was not verified: " + sessionID);
	}

	public byte[] getLocalFingerprintRaw(SessionID sessionID) {
		try {
			return new OtrCryptoEngineImpl().getFingerprintRaw(getLocalKeyPair(
					sessionID).getPublic());
		} catch (OtrCryptoException e) {
			e.printStackTrace();
		}
		return null;
	}

	public void askForSecret(SessionID sessionID, InstanceTag receiverTag,
			String question) {

	}

	public void verify(SessionID sessionID, String fingerprint, boolean approved) {

	}

	public void unverify(SessionID sessionID, String fingerprint) {

	}

	public String getReplyForUnreadableMessage(SessionID sessionID) {
		return null;
	}

	public String getFallbackMessage(SessionID sessionID) {
		return null;
	}

	public void messageFromAnotherInstanceReceived(SessionID sessionID) {

	}

	public void multipleInstancesDetected(SessionID sessionID) {

	}

	public String getFallbackMessage() {
		return "Off-the-Record private conversation has been requested. However, you do not have a plugin to support that.";
	}
}
