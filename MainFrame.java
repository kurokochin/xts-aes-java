import javax.swing.JFrame;

public class MainFrame extends JFrame {

    public MainFrame() {
        super("XTS AES");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(null);
        setSize(800, 600);
        setLocationRelativeTo(null);
        setResizable(false);
        getContentPane().add(new Content());
        setVisible(true);
    }
}