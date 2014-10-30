package core.otr;

import gui.Gui;
import gui.GuiChatWindow;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;

import commands.list_of_commands;
import core.Buddy;
import core.Logger;
import ca.uwaterloo.crysp.otr.iface.OTRCallbacks;
import ca.uwaterloo.crysp.otr.iface.OTRContext;
import ca.uwaterloo.crysp.otr.iface.OTRInterface;
import ca.uwaterloo.crysp.otr.iface.Policy;

public class LocalCallback implements OTRCallbacks{
	
	Buddy bud;
	
	public LocalCallback(Buddy b) throws IOException{
		bud=b;
	}

	public void injectMessage(String accName, String prot, String rec, String msg){
		if(msg==null)return;
		//return a log of injected message
		Logger.log(Logger.WARNING, this.getClass(), "Injecting message to the recipient:"
				+msg.length()+": "+msg);
		
		//get chat window
		GuiChatWindow w = Gui.getChatWindow(bud, true, true);		
		list_of_commands.in_command(bud, msg, w);
	}

	public int getOtrPolicy(OTRContext conn) {
		return Policy.DEFAULT;
	}

	public void goneSecure(OTRContext context) {
		System.out.println("\033[31mAKE succeeded\033[0m");
	}

	public int isLoggedIn(String accountname, String protocol,
			String recipient) {
		return 1;
	}

	public int maxMessageSize(OTRContext context) {
		return 1000;
	}

	public void newFingerprint(OTRInterface us,
			String accountname, String protocol, String username,
			byte[] fingerprint) {
		System.out.println("\033[31mNew fingerprint is created.\033[0m");
	}

	public void stillSecure(OTRContext context, int is_reply) {
		System.out.println("\033[31mStill secure.\033[0m");
	}

	public void updateContextList() {
		System.out.println("\033[31mUpdating context list.\033[0m");
	}

	public void writeFingerprints() {
		System.out.println("\033[31mWriting fingerprints.\033[0m");
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
			System.out.println("\033[31mThe private connection has already ended.\033[0m");
		}else if(msg_event==OTRCallbacks.OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE){
			System.out.println("\033[31mWe received an encrypted message, but we are not in" +
					"encryption state.\033[0m");
		}
	}

	public void handleSmpEvent(int smpEvent,
			OTRContext context, int progress_percent, String question) {
		if(smpEvent == OTRCallbacks.OTRL_SMPEVENT_ASK_FOR_SECRET){
			System.out.println("\033[31mThe other side has initialized SMP." +
					" Please respond with /rs.\033[0m");
		}else if(smpEvent == OTRCallbacks.OTRL_SMPEVENT_ASK_FOR_ANSWER){
			System.out.println("\033[31mThe other side has initialized SMP, with question:" +
					question + ", "+
			" Please respond with /rs.\033[0m");
		}else if(smpEvent == OTRCallbacks.OTRL_SMPEVENT_SUCCESS){
			System.out.println("\033[31mSMP succeeded.\033[0m");
		}else if(smpEvent == OTRCallbacks.OTRL_SMPEVENT_FAILURE){
			System.out.println("\033[31mSMP failed.\033[0m");
		}
		
		
	}
	
}