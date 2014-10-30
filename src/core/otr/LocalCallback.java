package core.otr;

import util.ChatWindow;
import gui.Gui;
import gui.GuiChatWindow;
import commands.list_of_commands;
import core.Buddy;
import core.Logger;
import ca.uwaterloo.crysp.otr.iface.OTRCallbacks;
import ca.uwaterloo.crysp.otr.iface.OTRContext;
import ca.uwaterloo.crysp.otr.iface.OTRInterface;
import ca.uwaterloo.crysp.otr.iface.Policy;

public class LocalCallback implements OTRCallbacks{
	
	Buddy bud;
	
	public LocalCallback(Buddy b) {
		bud=b;
	}

	public void injectMessage(String accName, String prot, String rec, String msg){
		if(msg==null)return;
		//return a log of injected message
		Logger.log(Logger.INFO, this.getClass(), "Injecting message to the recipient:"
				+msg.length()+": "+msg);
		
		//get chat window
		GuiChatWindow w = Gui.getChatWindow(bud, true, true);		
		ChatWindow.update_window(5, w, msg, "", msg, !bud.isFullyConnected());
	}

	public int getOtrPolicy(OTRContext conn) {
		return Policy.DEFAULT;
	}

	public void goneSecure(OTRContext context) {
		Logger.log(Logger.INFO, this.getClass(),"AKE succeeded");
	}

	public int isLoggedIn(String accountname, String protocol,
			String recipient) {
		return 1;
	}

	public int maxMessageSize(OTRContext context) {
		return 3000;
	}

	public void newFingerprint(OTRInterface us,
			String accountname, String protocol, String username,
			byte[] fingerprint) {
		Logger.log(Logger.INFO, this.getClass(),"New fingerprint is created.");
	}

	public void stillSecure(OTRContext context, int is_reply) {
		Logger.log(Logger.INFO, this.getClass(),"Still secure.");
	}

	public void updateContextList() {
		Logger.log(Logger.INFO, this.getClass(),"Updating context list.");
	}

	public void writeFingerprints() {
		Logger.log(Logger.INFO, this.getClass(),"Writing fingerprints.");
	}

	public String errorMessage(OTRContext context, int err_code) {
		if(err_code==OTRCallbacks.OTRL_ERRCODE_MSG_NOT_IN_PRIVATE){
			return "You sent an encrypted message, but we finished" +
					"the private conversation.";
		}
		return null;
	}

	public void handleMsgEvent(int msg_event,
			OTRContext context, String message) {
		if(msg_event==OTRCallbacks.OTRL_MSGEVENT_CONNECTION_ENDED){
			Logger.log(Logger.INFO, this.getClass(),"The private connection has already ended.");
		}else if(msg_event==OTRCallbacks.OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE){
			Logger.log(Logger.INFO, this.getClass(),"We received an encrypted message, but we are not in" +
					"encryption state.");
		}
	}

	public void handleSmpEvent(int smpEvent,
			OTRContext context, int progress_percent, String question) {
		if(smpEvent == OTRCallbacks.OTRL_SMPEVENT_ASK_FOR_SECRET){
			Logger.log(Logger.INFO, this.getClass(),"The other side has initialized SMP." +
					" Please respond with /rs.");
		}else if(smpEvent == OTRCallbacks.OTRL_SMPEVENT_ASK_FOR_ANSWER){
			Logger.log(Logger.INFO, this.getClass(),"The other side has initialized SMP, with question:" +
					question + ", "+
			" Please respond with /rs.");
		}else if(smpEvent == OTRCallbacks.OTRL_SMPEVENT_SUCCESS){
			Logger.log(Logger.INFO, this.getClass(),"SMP succeeded.");
		}else if(smpEvent == OTRCallbacks.OTRL_SMPEVENT_FAILURE){
			Logger.log(Logger.INFO, this.getClass(),"SMP failed.");
		}
		
		
	}
	
}