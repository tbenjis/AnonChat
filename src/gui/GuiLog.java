package gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Container;
import java.awt.event.*;


import javax.swing.*;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;

import core.Config;



import util.LogWriter;

@SuppressWarnings("serial")
public class GuiLog extends JFrame {
	public static long lastclear = System.currentTimeMillis() / 1000;
	public static GuiLog instance;
	public GuiLog() {
		initComponents();
		setSize(755, 402);
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		setTitle("Application Log");
		textPane1.setEditable(false);
		initDocument();
	}
	
	private void initDocument() {
		DefaultStyledDocument d = (DefaultStyledDocument) textPane1.getDocument();
		Style timestampStyle = d.addStyle("Time Stamp", null);
	    StyleConstants.setForeground(timestampStyle, Color.gray.darker());
	    Style theirNameStyle = d.addStyle("Err", null);
	    StyleConstants.setForeground(theirNameStyle, Color.red.darker());
	    Style classc = d.addStyle("Class-c", null);
	    StyleConstants.setForeground(classc, Color.green.darker());
	    Style classt = d.addStyle("Class-t", null);
	    StyleConstants.setForeground(classt, Color.green.darker().darker().darker());
	}

	static {
		Gui.setLAF("Nimbus");
		instance = new GuiLog();
//		instance.setVisible(true);
	}

	private static Object LOCK = new Object(); 
	
	public static void append(String text, String style) {
		synchronized(LOCK) {
			DefaultStyledDocument d = (DefaultStyledDocument) instance.textPane1.getDocument();
			try {
				d.insertString(d.getLength(), text, style == null ? null : d.getStyle(style));
				trimText();
				instance.textPane1.setCaretPosition(d.getLength());
			} catch (BadLocationException ble) {
				ble.printStackTrace();
			}
		}
	}

	public static void updateErr(String s) {
		synchronized(LOCK) {
			DefaultStyledDocument d = (DefaultStyledDocument) instance.textPane1.getDocument();
			try {
				d.insertString(d.getLength(), s, d.getStyle("Err"));
				trimText();
				instance.textPane1.setCaretPosition(d.getLength());
				} catch (BadLocationException ble) {
				ble.printStackTrace();
			}
		}
	}

	public static void updateOut(String s) {
		synchronized(LOCK) {
			DefaultStyledDocument d = (DefaultStyledDocument) instance.textPane1.getDocument();
			try {
				d.insertString(d.getLength(), s, null);
				trimText();
				instance.textPane1.setCaretPosition(d.getLength());
			} catch (BadLocationException ble) {
				ble.printStackTrace();
			}
		}
	}
	
	private static void trimText() {
		if (Config.fulllog == 0)
		{
		if (instance.textPane1.getDocument().getLength() > 10000) {
			instance.textPane1.setCaretPosition(0);
			int i = instance.textPane1.getText().indexOf("\n");
			try {
			instance.textPane1.getDocument().remove(0, i + 1);
			} catch (BadLocationException e) {
			e.printStackTrace();
			}
			trimText();
			}}
	}
	
	
	private void save(ActionEvent e) {
		LogWriter.LogWrite(instance.textPane1.getText(),0,"");
	}

	private void clear(ActionEvent e) {
		instance.textPane1.setCaretPosition(0);
		instance.textPane1.setDocument(new DefaultStyledDocument());
		initDocument();
		System.gc(); // ask the jvm to collect garbage
	}

	private void close(ActionEvent e) {
		instance.setVisible(false);
	}

	
	private void initComponents() {
		// JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
		// Generated using JFormDesigner Evaluation license - dfddfd dfdfdf
		menuBar1 = new JMenuBar();
		menuItem2 = new JMenuItem();
		menuItem1 = new JMenuItem();
		menuItem3 = new JMenuItem();
		scrollPane1 = new JScrollPane();
		textPane1 = new JTextPane();

		//======== this ========
		Container contentPane = getContentPane();
		contentPane.setLayout(new BorderLayout(8, 8));

		//======== menuBar1 ========
		{

			//---- menuItem2 ----
			menuItem2.setText("Save");
			menuItem2.setHorizontalTextPosition(SwingConstants.CENTER);
			menuItem2.setHorizontalAlignment(SwingConstants.CENTER);
			menuItem2.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					save(e);
				}
			});
			menuBar1.add(menuItem2);

			//---- menuItem1 ----
			menuItem1.setText("Clear");
			menuItem1.setHorizontalTextPosition(SwingConstants.CENTER);
			menuItem1.setHorizontalAlignment(SwingConstants.CENTER);
			menuItem1.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					clear(e);
				}
			});
			menuBar1.add(menuItem1);

			//---- menuItem3 ----
			menuItem3.setText("Close");
			menuItem3.setHorizontalTextPosition(SwingConstants.CENTER);
			menuItem3.setHorizontalAlignment(SwingConstants.CENTER);
			menuItem3.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					close(e);
				}
			});
			menuBar1.add(menuItem3);
		}
		setJMenuBar(menuBar1);

		//======== scrollPane1 ========
		{
			scrollPane1.setViewportView(textPane1);
		}
		contentPane.add(scrollPane1, BorderLayout.CENTER);
		pack();
		setLocationRelativeTo(getOwner());
		// JFormDesigner - End of component initialization  //GEN-END:initComponents
	}

	// JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
	// Generated using JFormDesigner Evaluation license - dfddfd dfdfdf
	private JMenuBar menuBar1;
	private JMenuItem menuItem2;
	private JMenuItem menuItem1;
	private JMenuItem menuItem3;
	private JScrollPane scrollPane1;
	private JTextPane textPane1;
	// JFormDesigner - End of variables declaration  //GEN-END:variables


}


