package commands;

import javax.swing.JOptionPane;

import util.ChatWindow;
import ca.uwaterloo.crysp.otr.iface.OTRCallbacks;
import ca.uwaterloo.crysp.otr.iface.OTRContext;
import ca.uwaterloo.crysp.otr.iface.OTRInterface;
import ca.uwaterloo.crysp.otr.iface.Policy;
import gui.GuiChatWindow;
import core.Buddy;
import core.Config;
import core.Logger;

/**
 * Display a messages that we send
 * 
 * @author tbenjis
 * 
 */
public class in_otr {
	public static void command(Buddy buddy, String s, GuiChatWindow w,
			OTRInterface us, OTRCallbacks callback, OTRContext conn) {

		// get the next 5 string
		String str = s.substring(5);
		// string to display in chat
		String chatString = s;
		boolean smp_request = false;
		try {
			
			//detect SMP request
			if (str.startsWith("/isq")) {
				smp_request = true;
				Logger.log(Logger.INFO, "IN_OTR", "Requesting Secret question");
				String question = JOptionPane
						.showInputDialog("Please input secret question");
				Logger.log(Logger.INFO, "IN_OTR", "Accepting Secret answer");
				str = JOptionPane.showInputDialog("Please input the secret");
				conn.initiateSmp_q(question, str, callback);
			} else if (str.startsWith("/is")) {
				smp_request = true;
				Logger.log(Logger.INFO, "IN_OTR", "initiating SMP");
				str = JOptionPane.showInputDialog("Please input the secret");
				conn.initiateSmp(str, callback);
				ChatWindow.update_window(0, w, "Sending SMP request to user, Please wait...", "", "",
						!buddy.isFullyConnected());
			} else if (str.startsWith("/rs")) {
				smp_request = true;
				Logger.log(Logger.INFO, "IN_OTR",
						"Accepting Secret answer from buddy");
				conn.respondSmp(str.substring(3), callback);
				ChatWindow.update_window(0, w, "Sending reply to user, Please wait...", "", "",
						!buddy.isFullyConnected());
			} else if (str.startsWith("/as")) {
				smp_request = true;
				Logger.log(Logger.INFO, "IN_OTR", "Aborting SMP");
				conn.abortSmp(callback);
			} else if (str.startsWith("/disc")) {
				smp_request = true;
				Logger.log(Logger.INFO, "IN_OTR", "Disconnecting encryption: "
						+ str);
				conn.disconnect(callback);
				conn.abortSmp(callback);
			} else {
				Logger.log(Logger.INFO, "IN_OTR",
						"Converting to OTR:" + str.length() + ":" + str);
				try {
					str = us.messageSending(Config.us, buddy.getClient(),
							buddy.getAddress(), s, null,
							Policy.FRAGMENT_SEND_ALL, callback);

					Logger.log(Logger.INFO, "IN_OTR",
							"To network:" + str.length() + ":" + str + "");
				} catch (Exception e) {
					Logger.log(Logger.SEVERE, "IN_OTR",
							"Null received, maybe OTR control message");
					// w.setPartialEncryption();
				}

			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		if (!smp_request)
			ChatWindow.update_window(5, w, chatString.substring(5), "", "",
					!buddy.isFullyConnected());
	}
}