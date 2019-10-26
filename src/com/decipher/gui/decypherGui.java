package com.decipher.gui;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
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
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
//        byte[] plain = cipherHandler.decrypt(plainText, iv, originalKey, mac); //TODO THIS
//        String decipheredText = new String(plain);
//        this.writeToFile(decipheredText, filePath);
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
//                    String secretKey2 = new String((byte[]) Files.getAttribute(pathFile, "user:key"));
                    System.out.println("secretKey2: ");
//                    System.out.println(secretKey2);
                    writeToFile("Skuska TXT mada", Paths.get("C:\\Users\\Admin\\Desktop\\SKuska.txt"));
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

    public class CipherHandler {
        SecureRandom secureRandom = new SecureRandom();

        public CipherHandler() {
        }

        SecretKey generateSecretKey() {
            byte[] key = new byte[16];
            this.secureRandom.nextBytes(key);
            return new SecretKeySpec(key, "AES");
        }

        byte[] generateInitialVector() {
            byte[] iv = new byte[12];
            this.secureRandom.nextBytes(iv);
            return iv;
        }

        SecretKey generateMacKey() {
            byte [] key = new byte [32];
            secureRandom.nextBytes(key);
            return new SecretKeySpec(key, "HmacSHA256");
        }

        byte[] doEncrypt(final byte[] iv, final SecretKey secretKey, final SecretKey macKey, final byte[] plainText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcm = new GCMParameterSpec(128, iv);
            final Mac hmac = Mac.getInstance("HmacSHA256");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcm);
            byte[] cipherText = null;

            try {
                cipherText = cipher.doFinal(plainText);
            } catch (IllegalBlockSizeException var8) {
                var8.printStackTrace();
            } catch (BadPaddingException var9) {
                var9.printStackTrace();
            }

            //mac authentication
            hmac.init(macKey);
            hmac.update(iv);
            hmac.update(cipherText);

            byte [] mac = hmac.doFinal();

            return this.concatCipherToSingleMessage(iv, cipherText, mac);
        }

        public byte[] decrypt(final byte[] cipherText, final byte[] initialVector, final SecretKey key, final SecretKey macKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
            // java.lang.NullPointerException: null
            ByteBuffer buf = ByteBuffer.wrap(cipherText);

            int ivLength = buf.getInt();

            byte [] iv = new byte[ivLength];
            buf.get(iv);

            int macLength = (buf.get()); //TODO tu je chybam dava negativny macLength, e.g. macLength = -17
            byte [] mac = new byte[macLength];
            buf.get(mac);

            byte [] cipherT = new byte[buf.remaining()];
            buf.get(cipherT);

            final Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(macKey);
            hmac.update(iv);
            hmac.update(cipherT);
            byte [] refMac = hmac.doFinal();

            if (!MessageDigest.isEqual(refMac, mac)) {
                throw new SecurityException("could not authenticate");
            }

            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));

            return cipher.doFinal(cipherT);

        }

        private byte[] concatCipherToSingleMessage(final byte[] iv, final byte[] cipherText, final byte [] mac) {
            ByteBuffer buffer = ByteBuffer.allocate(4 + iv.length + 1 + mac.length + cipherText.length);
            buffer.putInt(iv.length);
            buffer.put(iv);
            buffer.put((byte) mac.length);
            buffer.put(mac);
            buffer.put(cipherText);
            return buffer.array();
        }
    }

    public class RSAHandler {
        private Cipher cipher;

        public RSAHandler() throws NoSuchAlgorithmException, NoSuchPaddingException {
            this.cipher = Cipher.getInstance("RSA");
        }

        public PrivateKey getPrivate (byte[] privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }

        public PublicKey getPublic (byte[] publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }

        public String encryptText(byte[] msg, PublicKey key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            this.cipher.init(Cipher.ENCRYPT_MODE, key);
            return org.apache.tomcat.util.codec.binary.Base64.encodeBase64String(cipher.doFinal(msg));
        }

        public byte[] decryptText(byte [] msg, PrivateKey key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            this.cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(org.apache.tomcat.util.codec.binary.Base64.decodeBase64(msg));
        }
    }
}
