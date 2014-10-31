package core.otr;

import util.ChatWindow;
import gui.GuiChatWindow;
import ca.uwaterloo.crysp.otr.iface.OTRCallbacks;
import ca.uwaterloo.crysp.otr.iface.OTRInterface;
import ca.uwaterloo.crysp.otr.iface.StringTLV;
import core.Buddy;
import core.Config;
import core.Logger;

public class ReceivingThread extends Thread implements Runnable {
	private Buddy buddy;
	private String data;
	private GuiChatWindow w;
	private OTRInterface us;
	private OTRCallbacks callback;

	public ReceivingThread(Buddy buddy, String s, GuiChatWindow w, OTRInterface us, OTRCallbacks callback) {
		this.buddy = buddy;
		this.data = s;
		this.w = w;
		this.us = us;
		this.callback = callback;
	}

	public void run() {
		while (true) {
			try {
				StringTLV stlv = us.messageReceiving(Config.us, buddy.getClient(),
						buddy.getAddress(), data, callback);
				if (stlv != null) {
					final String s = stlv.msg;
					Logger.log(Logger.INFO, "OUT_OTR", "From OTR:" + s.length()
							+ ": " + s);
					// message is encrypted you can enable the menus
					ChatWindow.update_window(6, w, s, "", "", false);
					
						// set encryption enabled
						w.setFullEncryption();
					
				} else {
					// received unencrypted message, message wasnt encrypted
					w.setPartialEncryption();
				}
			} catch (Exception e) {
				return;
			}
		}
	}
}