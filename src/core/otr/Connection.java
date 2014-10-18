package core.otr;

import otr.main.otr4j.OtrException;

/**
 * Created by gp on 2/6/14.
 */
class Connection {

	private final OtrClient client;
	private final String connectionName;
	private final Server server;

	public String getSentMessage() {
		return sentMessage;
	}

	private String sentMessage;

	public Connection(Server server, OtrClient client, String connectionName) {
		this.client = client;
		this.server = server;
		this.connectionName = connectionName;
	}

	public OtrClient getClient() {
		return client;
	}

	@Override
	public String toString() {
		return "PriorityConnection{" +
				"connectionName='" + connectionName + '\'' +
				'}';
	}

	public void send(String recipient, String msg) throws OtrException {
		this.sentMessage = msg;
		server.send(this, recipient, msg);
	}

	public void receive(String sender, String msg) throws OtrException {
		this.client.receive(sender, msg);
	}
}