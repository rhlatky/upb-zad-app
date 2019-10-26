package com.decipher.gui;

import javax.swing.*;
import javax.swing.filechooser.FileSystemView;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

public class decypherGui extends Component {
    private JButton chooseButton;
    private JTextField textField;
    private JButton decypherButton;
    private JPanel mainPanel;
    private JTextArea textArea;
    private File selectedFile;

    private decypherGui() {
        chooseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
                int returnValue = jfc.showOpenDialog(null);

                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    selectedFile = jfc.getSelectedFile();
                    textField.setText(selectedFile.getName());
                }
            }
        });
        decypherButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                System.out.println(textArea.getText());
                System.out.println(selectedFile.getName() + " " + selectedFile.getAbsolutePath());
            }
        });
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("decypherGui");
        frame.setContentPane(new decypherGui().mainPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }

}
