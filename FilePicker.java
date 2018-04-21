import java.io.*;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

public class FilePicker {

	private JFileChooser picker;
	private File file;
	public String path;


	public FilePicker() {
		picker = new JFileChooser();
		int ret = picker.showOpenDialog(null);
		if (ret == JFileChooser.APPROVE_OPTION) {
			loadFile();
		}
	}

	public void loadFile() {
		file = picker.getSelectedFile();
		path = file.getPath();
	}

}