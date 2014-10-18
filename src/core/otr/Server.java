package core.otr;

import otr.main.otr4j.OtrException;

/**
 * Created by gp on 2/6/14.
 */
public interface Server {
	void send(Connection sender, String recipient, String msg) throws OtrException;

	Connection connect(OtrClient client);
}
