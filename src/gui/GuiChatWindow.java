package gui;

import java.awt.Color;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.swing.GroupLayout;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import javax.swing.text.html.HTML;

import util.ChatWindow;
import ca.uwaterloo.crysp.otr.UserState;
import ca.uwaterloo.crysp.otr.iface.OTRCallbacks;
import ca.uwaterloo.crysp.otr.iface.OTRInterface;
import commands.list_of_commands;
import core.Buddy;
import core.Config;
import core.otr.LocalCallback;
import listeners.LinkController;
import fileTransfer.FileDrop;
import fileTransfer.FileSender;

import javax.swing.JMenuBar;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JLabel;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;

import java.awt.Font;

/**
 * The main chat window
 * @author tbenjis
 *
 */
@SuppressWarnings("serial")
public class GuiChatWindow extends JFrame implements ActionListener {

	public Buddy b;
	private Style timestampStyle;
	private Style myNameStyle;
	private Style theirNameStyle;
	private Boolean shiftpress;
	private Style OTRStyle;

	// private Style normalStyle;

	// Clickable links start

	public void addUrlText(String type, String text) {

		if (Config.ClickableLinks == 0) {
			append(type, text);
		} else {
			String[] splittall = text.split(" ");

			int x = 0;
			while (x < splittall.length) {

				if (splittall[x].startsWith("http://")) {
					try {
						addHyperlink(new URL(splittall[x]),
								splittall[x].substring(7), Color.blue);
						append(type, " ");
					} catch (MalformedURLException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} // if the original doesnt have a protocol specified,
						// insert http:// at the beggining
				} else if (splittall[x].startsWith("https://")) {
					try {
						addHyperlink(new URL(splittall[x]),
								splittall[x].substring(8), Color.blue);
						append(type, " ");
					} catch (MalformedURLException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} // if the original doesnt have a protocol specified,
						// insert http:// at the beggining
				} else {
					append(type, splittall[x]);

					if (x < splittall.length - 1) {
						append(type, " ");
					}
				}

				x++;
			}
		}
	}

	public void addHyperlink(URL url, String text, Color color) {
		try {
			Document doc = textPane1.getDocument();
			SimpleAttributeSet attrs = new SimpleAttributeSet();
			StyleConstants.setUnderline(attrs, true);
			StyleConstants.setForeground(attrs, color);
			attrs.addAttribute(HTML.Attribute.HREF, url.toString());
			doc.insertString(doc.getLength(), text, attrs);
		} catch (BadLocationException e) {
			e.printStackTrace(System.err);
		}
	}

	// Clickable Links End

	public GuiChatWindow(Buddy b) {
		this.b = b;
		this.shiftpress = false;
		initComponents();
		LinkController lc = new LinkController();
		textPane1.addMouseListener(lc);
		textPane1.addMouseMotionListener(lc);

		new FileDrop(textPane1, new FileDrop.Listener() {

			@Override
			public void filesDropped(java.io.File[] files) {
				Buddy b = ((GuiChatWindow) (textPane1).getRootPane()
						.getParent()).getBuddy();
				for (int i = 0; i < files.length; i++) {
					new FileSender(b, files[i].getAbsolutePath());
				}

			}

		});

		System.out.println(textPane1.getDocument().getClass()
				.getCanonicalName());
		textPane1.setEditable(false);

		textArea4.setWrapStyleWord(true);
		textArea4.setLineWrap(true);
		
		menuBar = new JMenuBar();
		setJMenuBar(menuBar);
		
		mnFile = new JMenu("File");
		menuBar.add(mnFile);
		
		mntmSaveChat = new JMenuItem("Save Chat");
		mnFile.add(mntmSaveChat);
		//menu for saving logs
		mntmSaveChat.addActionListener(this);
		
		mntmHelp = new JMenuItem("Help");
		mnFile.add(mntmHelp);
		mntmHelp.addActionListener(this);
		
		mnFile.add(new JSeparator());
		
		mntmExit = new JMenuItem("Exit");
		mnFile.add(mntmExit);
		mntmExit.addActionListener(this);
		
		mnEncryptedChat = new JMenu("Encrypted Chat");
		menuBar.add(mnEncryptedChat);
		
		mntmStartEncryptedChat = new JMenuItem("Start Encrypted Chat");
		mnEncryptedChat.add(mntmStartEncryptedChat);
		mntmStartEncryptedChat.addActionListener(this);
		
		mntmStopEncryptedChat = new JMenuItem("Stop Encrypted Chat");
		mnEncryptedChat.add(mntmStopEncryptedChat);
		mntmStopEncryptedChat.addActionListener(this);
		
		mnEncryptedChat.add(new JSeparator());
		
		mntmAuthenticateContactmitm = new JMenuItem("Authenticate Contact (MITM)");
		mnEncryptedChat.add(mntmAuthenticateContactmitm);
		
		//disable stop encryption menu during initialization
		this.mntmStopEncryptedChat.setEnabled(false);
		this.mntmAuthenticateContactmitm.setEnabled(false);
		
		addWindowFocusListener(new WindowAdapter() {

			@Override
			public void windowGainedFocus(WindowEvent e) {
				textArea4.requestFocusInWindow();
			}
		});
		timestampStyle = ((StyledDocument) textPane1.getDocument()).addStyle(
				"Time Stamp", null);
		StyleConstants.setForeground(timestampStyle, Color.gray.darker());
		/** //OTR style
		OTRStyle = ((StyledDocument) textPane1.getDocument()).addStyle(
				"<<OTR>>", null);
		StyleConstants.setForeground(OTRStyle, Color.GREEN.darker());
		**/
		myNameStyle = ((StyledDocument) textPane1.getDocument()).addStyle("Me",
				null);
		StyleConstants.setForeground(myNameStyle, Color.blue.darker());
		theirNameStyle = ((StyledDocument) textPane1.getDocument()).addStyle(
				"Them", null);
		StyleConstants.setForeground(theirNameStyle, Color.red.darker());
		textPane1.addKeyListener(new KeyListener() {

			@Override
			public void keyTyped(KeyEvent e) {
				textArea4.dispatchEvent(e);
				textArea4.requestFocusInWindow();

			}

			@Override
			public void keyPressed(KeyEvent e) {
			}

			@Override
			public void keyReleased(KeyEvent e) {
			}

		});
	}

	private void textArea4KeyReleased(KeyEvent e) {
		if (e.getKeyCode() == 16) {
			shiftpress = false;
		}

		if (e.getKeyCode() == 10 & shiftpress) {
			textArea4.setText(textArea4.getText() + "\n");
		}

		if (e.getKeyCode() == 10 & !shiftpress) { // enter key
			if (!textArea4.getText().trim().equals("")) {
				String msg = textArea4.getText();
				//check if otr is enabled
				boolean right = true;
				if (msg.startsWith("/")) {
					if(OTR_ENABLED)
					{
						right = list_of_commands.in_command(b, "/otr "+msg, this, alice, callback);
					}else{
						right = list_of_commands.in_command(b, msg, this);
					}
				}
				if (right) {
					ChatWindow.update_window(1, this, msg, "", msg,
							!b.isFullyConnected());
				}

			} else {
				textArea4.setText("");
			}
		}
	}

	private void textArea4KeyPressed(KeyEvent e) {

		if (e.getKeyCode() == 16) {
			shiftpress = true;
		}
		if (e.getKeyCode() == 10) {
			e.consume();
		}
	}

	private void initComponents() {
		// JFormDesigner - Component initialization - DO NOT MODIFY
		// //GEN-BEGIN:initComponents
		// Generated using JFormDesigner Evaluation license - TIm daaa
		scrollPane3 = new JScrollPane();
		textPane1 = new JTextPane();
		scrollPane4 = new JScrollPane();
		textArea4 = new JTextArea();

		// ======== this ========
		Container contentPane = getContentPane();

		// ======== scrollPane3 ========
		{
			scrollPane3.setViewportView(textPane1);
		}

		// ======== scrollPane4 ========
		{

			// ---- textArea4 ----
			textArea4.addKeyListener(new KeyAdapter() {
				@Override
				public void keyPressed(KeyEvent e) {
					textArea4KeyPressed(e);
				}

				@Override
				public void keyReleased(KeyEvent e) {
					textArea4KeyReleased(e);
				}
			});
			scrollPane4.setViewportView(textArea4);
		}
		
		lblStatus = new JLabel("Status: ");
		lblStatus.setFont(new Font("Tahoma", Font.BOLD, 11));
		
		lblNotEncrypted = new JLabel("Not Encrypted");
		lblStatus.setLabelFor(lblNotEncrypted);
		lblNotEncrypted.setForeground(Color.RED);

		GroupLayout contentPaneLayout = new GroupLayout(contentPane);
		contentPaneLayout.setHorizontalGroup(
			contentPaneLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(contentPaneLayout.createSequentialGroup()
					.addContainerGap()
					.addComponent(lblStatus, GroupLayout.PREFERRED_SIZE, 55, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(lblNotEncrypted, GroupLayout.PREFERRED_SIZE, 248, GroupLayout.PREFERRED_SIZE)
					.addContainerGap(38, Short.MAX_VALUE))
				.addComponent(scrollPane3, GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)
				.addComponent(scrollPane4, GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)
		);
		contentPaneLayout.setVerticalGroup(
			contentPaneLayout.createParallelGroup(Alignment.TRAILING)
				.addGroup(contentPaneLayout.createSequentialGroup()
					.addComponent(scrollPane3, GroupLayout.DEFAULT_SIZE, 330, Short.MAX_VALUE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(scrollPane4, GroupLayout.PREFERRED_SIZE, 59, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(contentPaneLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblNotEncrypted)
						.addComponent(lblStatus))
					.addContainerGap())
		);
		contentPane.setLayout(contentPaneLayout);
		pack();
		setLocationRelativeTo(getOwner());
		// JFormDesigner - End of component initialization
		// //GEN-END:initComponents
	}

	public void append(String style, String text) {
		try {
			StyledDocument doc = (StyledDocument) textPane1.getDocument(); // Create a style object and set attributes
																			
			doc.insertString(doc.getLength(), text, doc.getStyle(style));
		} catch (BadLocationException ble) {
			ble.printStackTrace();
		}
	}

	public JTextArea get_textArea4() {
		return textArea4;
	}

	public JTextPane get_textPane1() {
		return textPane1;
	}

	// JFormDesigner - Variables declaration - DO NOT MODIFY
	// //GEN-BEGIN:variables
	// Generated using JFormDesigner Evaluation license - TIm daaa
	private JScrollPane scrollPane3;
	private JTextPane textPane1;
	private JScrollPane scrollPane4;
	private JTextArea textArea4;
	private JMenuBar menuBar;
	private JMenu mnFile;
	private JMenuItem mntmSaveChat;
	private JMenuItem mntmHelp;
	private JMenuItem mntmExit;
	private JMenu mnEncryptedChat;
	private JMenuItem mntmStartEncryptedChat;
	private JMenuItem mntmStopEncryptedChat;
	private JMenuItem mntmAuthenticateContactmitm;
	private JLabel lblStatus;
	private JLabel lblNotEncrypted;
	//needed for otr
	private UserState alice;
	private LocalCallback callback;
	private boolean OTR_ENABLED = false;

	// JFormDesigner - End of variables declaration //GEN-END:variables

	public JEditorPane getTextPane1() {
		return textPane1;
	}

	public JTextArea getTextArea4() {
		return textArea4;
	}

	public static String getTime() {
		return new SimpleDateFormat("h:mm:ss").format(new Date());
		// return Calendar.getInstance().get(Calendar.HOUR) + ":" +
		// Calendar.getInstance().get(Calendar.MINUTE) + ":" +
		// Calendar.getInstance().get(Calendar.SECOND);
	}

	public Buddy getBuddy() {
		return b;
	}

	//action listener for the menus
	@Override
	public void actionPerformed(ActionEvent e) {
		if(e.getSource() == this.mntmSaveChat){
			list_of_commands.in_command(b, "/log", this);
		}
		
		if(e.getSource() == this.mntmHelp){
			list_of_commands.in_command(b, "/help", this);
		}
		
		if(e.getSource() == this.mntmExit){
			dispose();
		}
		
		if(e.getSource() == this.mntmStartEncryptedChat){
			//findout if the client is fully connected
			if (b.isFullyConnected())
			{
				//begin the encrypted chat process
				// Generate the keys
				 alice = new UserState(new ca.uwaterloo.crysp.otr.crypt.jca.JCAProvider());
				 callback = new LocalCallback(b);
				 //set otr encryption enabled
				 OTR_ENABLED = true;
				
			
				//after the process is complete disable stop encrypted chat menu
				this.mntmStartEncryptedChat.setEnabled(false);
				this.mntmStopEncryptedChat.setEnabled(true);
				
				
			}else{
				JOptionPane.showMessageDialog(this, "Client not fully connected, cannot initiate encryption. Please try again.");
			}
		}
		
		if(e.getSource() == this.mntmStopEncryptedChat){
			//begin the encrypted chat process
			
			//findout if the client is fully connected
			if (b.isFullyConnected())
			{
				this.mntmStopEncryptedChat.setEnabled(false);
				
				//after the process is complete disable start encrypted chat menu
				this.mntmStartEncryptedChat.setEnabled(true);
				OTR_ENABLED = false;
				list_of_commands.in_command(b, "/otr /disc", this, alice, callback);
				
			}else{
				JOptionPane.showMessageDialog(this, "Client not fully connected, cannot stop encryption. Please try again.");

			}
		}
		
	}
}
