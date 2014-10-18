package core.otr;

import otr.main.otr4j.OtrException;
import otr.main.otr4j.OtrPolicy;
import otr.main.otr4j.session.Session;
import otr.main.otr4j.session.SessionID;
import otr.main.otr4j.session.SessionImpl;

import java.util.LinkedList;
import java.util.Queue;
/**
 * Created by gp on 2/5/14.
 */
public class OtrClient {

	private final String account;
	private Session session;
	OtrPolicy policy;
	private Connection connection;
	private MessageProcessor processor;
	private Queue<ProcessedMessage> processedMsgs = new LinkedList<ProcessedMessage>();

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

	public void send(String recipient, String s) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account, recipient, "AnonChatProtocol");
			session = new SessionImpl(sessionID, new OtrEngineHostImpl());
		}

		String outgoingMessage = session.transformSending(s);
		connection.send(recipient, outgoingMessage);
	}

	public void exit() throws OtrException {
		this.processor.stop();
		if (session != null)
			session.endSession();
	}

	public void receive(String sender, String s) throws OtrException {
		this.processor.enqueue(sender, s);
	}

	public void secureSession(String recipient) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account, recipient, "AnonChatProtocol");
			session = new SessionImpl(sessionID, new OtrEngineHostImpl());
		}

		session.startSession();
	}

	public Connection getConnection() {
		return connection;
	}

	public ProcessedMessage pollReceivedMessage() {
		synchronized (processedMsgs) {
			ProcessedMessage m;
			while ((m = processedMsgs.poll()) == null) {
				try {
					processedMsgs.wait();
				} catch (InterruptedException e) {
				}
			}

			return m;
		}
	}

	class MessageProcessor implements Runnable {
		private final Queue<Message> messageQueue = new LinkedList<Message>();
		private boolean stopped;

		private void process(Message m) throws OtrException {
			if (session == null) {
				final SessionID sessionID = new SessionID(account, m.getSender(), "AnonChatProtocol");
				session = new SessionImpl(sessionID, new OtrEngineHostImpl());
			}

			String receivedMessage = session.transformReceiving(m.getContent());
			synchronized (processedMsgs) {
				processedMsgs.add(new ProcessedMessage(m, receivedMessage));
				processedMsgs.notify();
			}
		}

		public void run() {
			synchronized (messageQueue) {
				while (true) {

					Message m = messageQueue.poll();

					if (m == null) {
						try {
							messageQueue.wait();
						} catch (InterruptedException e) {

						}
					} else {
						try {
							process(m);
						} catch (OtrException e) {
							e.printStackTrace();
						}
					}

					if (stopped)
						break;
				}
			}
		}

		public void enqueue(String sender, String s) {
			synchronized (messageQueue) {
				messageQueue.add(new Message(sender, s));
				messageQueue.notify();
			}
		}

		public void stop() {
			stopped = true;

			synchronized (messageQueue) {
				messageQueue.notify();
			}
		}
	}

	
}
