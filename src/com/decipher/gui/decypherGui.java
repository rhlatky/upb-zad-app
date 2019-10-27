package com.decipher.gui;

import encryption.CipherHandler;
import encryption.RSAHandler;
import encryption.GUIexception;
import javax.crypto.*;
import javax.swing.*;
import javax.swing.filechooser.FileSystemView;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class decypherGui extends Component {
    private JButton chooseButton;
    private JTextField textField;
    private JButton decypherButton;
    private JPanel mainPanel;
    private JTextArea textArea;
    private JTextField textField1;
    private File selectedFile;

    private encryption.CipherHandler cipherHandler = new CipherHandler();

    private encryption.RSAHandler rsaHandler = new RSAHandler();

    private Path decryptRSALocal(Path filePath, String privateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        byte[] plainText = Files.readAllBytes(filePath);
        PrivateKey newPrivateKey = rsaHandler.getPrivate(Base64.getDecoder().decode(privateKey));
        byte[] plain = cipherHandler.decrypt(plainText, newPrivateKey); //TODO THIS
        String decipheredText = new String(plain);

        Path newPath = Paths.get("Decrypted-"+ filePath.getFileName());
        this.writeToFile(decipheredText, newPath);
        return newPath;
    }

    private void writeToFile(String text, Path filePath) throws IOException {
        File file = new File(filePath.toString());
        BufferedWriter writer = new BufferedWriter(new FileWriter(file));
        writer.write(text);
        writer.close();
    }

    private decypherGui() throws NoSuchPaddingException, NoSuchAlgorithmException {
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
                try {
                    if (textArea.getText().equals("") || !selectedFile.isFile()){
                        throw new GUIexception("Chyba vam spravny subor alebo kluc");
                    }
                    Path savedPathed = decryptRSALocal(selectedFile.toPath(), textArea.getText());
                    System.out.println(savedPathed.toAbsolutePath().toString());
                    textField1.setText("Uložené: " + savedPathed.toAbsolutePath().toString());
                } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | GUIexception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("decypherGui");

        try {
            frame.setContentPane(new decypherGui().mainPanel);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }
}
