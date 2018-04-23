import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.*;
import java.io.*;

public class Content extends JPanel implements ActionListener {

	private JLabel plaintext, key, ciphertext;
    private JTextField sourceField, keyField, targetFileName;
    private JButton decrypt, encrypt, openKey, openFile, saveFile;

	public Content() {
        setLayout(null);
        initComponents();
        setSize(800,600);
        addContent();
	}

	private void addContent() {
        add(plaintext);
        add(key);
        add(ciphertext);
        add(sourceField);
        add(keyField);
        add(targetFileName);
        add(decrypt);
        add(encrypt);
        add(openKey);
        add(openFile);
        add(saveFile);
    }

	private void initComponents() {
        plaintext = new JLabel("Source        :");
        plaintext.setHorizontalAlignment(SwingConstants.LEFT);
        plaintext.setSize(220, 20);
        plaintext.setHorizontalTextPosition(SwingConstants.CENTER);
        plaintext.setVerticalTextPosition(SwingConstants.CENTER);
        plaintext.setLocation(70, 70);

        key = new JLabel("Key              :");
        key.setHorizontalAlignment(SwingConstants.LEFT);
        key.setSize(220, 20);
        key.setHorizontalTextPosition(SwingConstants.CENTER);
        key.setVerticalTextPosition(SwingConstants.CENTER);
        key.setLocation(70, 120);

        ciphertext = new JLabel("Target         :");
        ciphertext.setHorizontalAlignment(SwingConstants.LEFT);
        ciphertext.setSize(220, 20);
        ciphertext.setHorizontalTextPosition(SwingConstants.CENTER);
        ciphertext.setVerticalTextPosition(SwingConstants.CENTER);
        ciphertext.setLocation(70, 170);

        sourceField =new JTextField(20);
        sourceField.setSize(sourceField.getPreferredSize());
        sourceField.setLocation(250, 70);
        sourceField.setSize(220, 20);

        keyField =new JTextField(20);
        keyField.setSize(keyField.getPreferredSize());
        keyField.setLocation(250, 120);
        keyField.setSize(220, 20);

        targetFileName =new JTextField(20);
        targetFileName.setSize(targetFileName.getPreferredSize());
        targetFileName.setLocation(250, 170);
        targetFileName.setSize(220, 20);

        openFile = new JButton("Source");
        openFile.setSize(150, 20);
        openFile.setLocation(550, 70);
        openFile.addActionListener(this);

        openKey = new JButton("Key");
        openKey.setSize(150, 20);
        openKey.setLocation(550, 120);
        openKey.addActionListener(this);

        saveFile = new JButton("Target");
        saveFile.setSize(150, 20);
        saveFile.setLocation(550, 170);
        saveFile.addActionListener(this);

        decrypt = new JButton("Decrypt");
        decrypt.setSize(100, 20);
        decrypt.setLocation(230, 230);
        decrypt.addActionListener(this);

        encrypt = new JButton("Encrypt");
        encrypt.setSize(100, 20);
        encrypt.setLocation(400, 230);
        encrypt.addActionListener(this);
    }

    @Override
    public void actionPerformed(ActionEvent aksi) {
    	final String dataUnit = "00000000000000ff";
    	String tweakKey = "3141592653589793238462643383279502884197169399375105820974944592";
        if (aksi.getSource() == openFile) {
            FilePicker fpSource = new FilePicker();
            sourceField.setText(fpSource.path);
        } else if (aksi.getSource() == openKey) {
            FilePicker fpKey = new FilePicker();
            keyField.setText(fpKey.path);
        } else if (aksi.getSource() == saveFile) {
            FilePicker fpTarget = new FilePicker();
            targetFileName.setText(fpTarget.path);
        } else if (aksi.getSource() == encrypt || aksi.getSource() == decrypt) {
        	try {
                /** Gets all of the required file paths */
                String sourcePath = sourceField.getText();
                String targetPath = targetFileName.getText();
                String keyPath = keyField.getText();

                /** Encrypt/Decrypt using XTS-AES */
                XTS xts = new XTS(sourcePath, keyPath, targetPath);
                boolean forEncryption;
            	if (aksi.getSource() == encrypt) {
                    forEncryption = true;
    	        } else {
                    forEncryption = false;
            	}
                xts.processData(forEncryption);
        	} catch (Exception e) {
        		e.printStackTrace(System.out);
        	}
        }
    }

}