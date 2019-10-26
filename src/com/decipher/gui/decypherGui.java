package com.decipher.gui;

import encryption.CipherHandler;
import encryption.RSAHandler;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class decypherGui extends Component {
    private JButton chooseButton;
    private JTextField textField;
    private JButton decypherButton;
    private JPanel mainPanel;
    private JTextArea textArea;
    private File selectedFile;
    private RSAHandler rsaHandler = new RSAHandler();;
    private CipherHandler cipherHandler  = new CipherHandler(); ;



    private SecretKey decryptSecretKey(final String key, final String encryptedKey) throws InvalidKeySpecException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        PrivateKey privateKey = rsaHandler.getPrivate(Base64.getDecoder().decode(key));
        byte[] decrypted = rsaHandler.decryptText(encryptedKey.getBytes(), privateKey);
        return new SecretKeySpec(decrypted, 0, decrypted.length, "AES"); //TODO THIS - desifrovanie
    }

    private void decryptRSA(Files file, Path filePath, SecretKey originalKey) throws IOException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        byte[] plainText = file.readAllBytes(filePath);
        byte[] plain = cipherHandler.decrypt(plainText, iv, originalKey, mac); //TODO THIS
        String decipheredText = new String(plain);
        this.writeToFile(decipheredText, filePath);
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
                System.out.println("LOADING aaasadfadsgaa");
                System.out.println(textArea.getText());
                System.out.println(selectedFile.getName() + " " + selectedFile.getAbsolutePath());
                Path pathFile = selectedFile.toPath();
                System.out.println(pathFile);
                try {
                    String secretKey2 = new String((byte[]) Files.getAttribute(pathFile, "user:key"));
                    System.out.println("secretKey2: ");
                    System.out.println(secretKey2);
                } catch (IOException e) {
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
