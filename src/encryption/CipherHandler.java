package encryption;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;

public class CipherHandler {
    RSAHandler rsaHandler = new RSAHandler();

    public CipherHandler() throws NoSuchPaddingException, NoSuchAlgorithmException {
    }
    public byte[] decrypt(final byte[] cipherText, final PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // java.lang.NullPointerException: null

        ByteBuffer buf = ByteBuffer.wrap(cipherText);

        int ivLength = buf.getInt();

        byte [] iv = new byte[ivLength];
        buf.get(iv);


        int encryptedKeyLength = (buf.get()); //TODO tu je chybam dava negativny macLength, e.g. macLength = -17
        byte [] encryptedKey = new byte[encryptedKeyLength];
        buf.get(encryptedKey);

        byte [] cipherT = new byte[buf.remaining()];
        buf.get(cipherT);

        byte[] decrypted = rsaHandler.decryptText(encryptedKey, privateKey);
        SecretKey originalKey = new SecretKeySpec(decrypted, 0, decrypted.length, "AES");

        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, originalKey, new GCMParameterSpec(128, iv));

        return cipher.doFinal(cipherT);
    }

}
