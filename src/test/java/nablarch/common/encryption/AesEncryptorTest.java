package nablarch.common.encryption;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;

import nablarch.common.encryption.AesEncryptor.AesContext;
import nablarch.core.util.Base64Util;

import org.junit.Test;

/**
 * @author Kiyohito Itoh
 */
public class AesEncryptorTest {

    @Test
    public void testEncryptAndDecrypt() {

        Encryptor<AesContext> encryptor = new AesEncryptor();
        AesContext context = encryptor.generateContext();

        byte[] src = "abcdefg123456\\[]@\"!".getBytes();
        byte[] encrypted = encryptor.encrypt(context, src);
        byte[] decrypted = encryptor.decrypt(context, encrypted);
        assertThat(decrypted, is(src));

        src = "".getBytes();
        encrypted = encryptor.encrypt(context, src);
        decrypted = encryptor.decrypt(context, encrypted);
        assertThat(decrypted, is(src));
    }

    @Test
    public void testEncryptAndDecryptWithSpecifyKeyAndIv() {

        AesEncryptor encryptor = new AesEncryptor();
        encryptor.setKey("1234567890123456");
        encryptor.setIv("6543210987654321");
        AesContext context = encryptor.generateContext();

        byte[] src = "abcdefg123456\\[]@\"!".getBytes();
        byte[] encrypted = encryptor.encrypt(context, src);
        byte[] decrypted = encryptor.decrypt(context, encrypted);
        assertThat(decrypted, is(src));

        src = "".getBytes();
        encrypted = encryptor.encrypt(context, src);
        decrypted = encryptor.decrypt(context, encrypted);
        assertThat(decrypted, is(src));
    }

    @Test
    public void testEncryptAndDecryptWithSpecifyBase64Key() throws Exception {
        final AesEncryptor sut = new AesEncryptor();
        final byte[] key = KeyGenerator.getInstance("AES")
                                       .generateKey()
                                       .getEncoded();

        final Base64Key base64Key = new Base64Key();
        base64Key.setKey(Base64Util.encode(key));
        sut.setBase64Key(base64Key);
        final AesContext context = sut.generateContext();

        assertThat("base64エンコードされた鍵が利用されること", context.getKey()
                                                     .getEncoded(), is(key));

        final String src = "あいうえお!!!!";
        final byte[] encrypted = sut.encrypt(context, src.getBytes("utf-8"));
        final byte[] decrypted = sut.decrypt(context, encrypted);

        assertThat(new String(decrypted, "utf-8"), is(src));
    }

    @Test
    public void testEncryptAndDecryptWithSpecifyBase64Iv() throws Exception {
        final AesEncryptor sut = new AesEncryptor();

        final byte[] iv = generateIv();
        final Base64Key base64Key = new Base64Key();
        base64Key.setIv(Base64Util.encode(iv));
        sut.setBase64Key(base64Key);
        final AesContext context = sut.generateContext();

        assertThat("base64エンコードされたIVが利用されること", context.getIv(), is(iv));

        final String src = "あいうえお!!!!";
        final byte[] encrypted = sut.encrypt(context, src.getBytes("utf-8"));
        final byte[] decrypted = sut.decrypt(context, encrypted);
        assertThat(new String(decrypted, "utf-8"), is(src));
    }

    @Test
    public void testEncryptAndDecryptWithSpecifyBase64KeyAndIv() throws Exception {
        final AesEncryptor sut = new AesEncryptor();
        final KeyGenerator aes = KeyGenerator.getInstance("AES");
        final byte[] key = aes.generateKey()
                              .getEncoded();
        final byte[] iv = generateIv();

        final Base64Key base64Key = new Base64Key();
        base64Key.setKey(Base64Util.encode(key));
        base64Key.setIv(Base64Util.encode(iv));
        sut.setBase64Key(base64Key);
        final AesContext context = sut.generateContext();

        assertThat("base64エンコードされたkeyが利用されること", context.getKey().getEncoded(), is(key));
        assertThat("base64エンコードされたIVが利用されること", context.getIv(), is(iv));

        final String src = "あいうえお!!!!";
        final byte[] encrypted = sut.encrypt(context, src.getBytes("utf-8"));
        final byte[] decrypted = sut.decrypt(context, encrypted);
        assertThat(new String(decrypted, "utf-8"), is(src));
    }

    @Test
    public void testInvalidParameter() {

        AesEncryptor encryptor = new AesEncryptor();
        AesContext context = encryptor.generateContext();

        // encryption

        byte[] src = "abcdefg123456\\[]@\"!".getBytes();

        try {
            encryptor.encrypt(null, src);
            fail("must throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(), is("context or src is null."));
        }

        try {
            encryptor.encrypt(context, null);
            fail("must throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(), is("context or src is null."));
        }

        AesContext badContext = new AesContext(generateBadKey(), encryptor.generateIv(128));
        try {
            encryptor.encrypt(badContext, src);
            fail("must throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(), is("encryption failed. transformation = [AES/CBC/PKCS5Padding]"));
            assertThat(e.getCause()
                        .getClass()
                        .getName(), is(InvalidKeyException.class.getName()));
        }

        // decryption

        try {
            encryptor.decrypt(null, src);
            fail("must throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(), is("context or src is null."));
        }

        try {
            encryptor.decrypt(context, null);
            fail("must throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(), is("context or src is null."));
        }
    }

    private Key generateBadKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("DES");
            return generator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testTempering() {

        Encryptor<AesContext> encryptor = new AesEncryptor();
        AesContext context = encryptor.generateContext();

        byte[] src = "abcdefg123456\\[]@\"!".getBytes();

        // different key
        byte[] encrypted = encryptor.encrypt(context, src);
        AesContext context2 = encryptor.generateContext();
        try {
            encryptor.decrypt(context2, encrypted);
            fail("must throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(), is("decryption failed. transformation = [AES/CBC/PKCS5Padding]"));
            assertThat(e.getCause()
                        .getClass()
                        .getName(), is(BadPaddingException.class.getName()));
        }

        // illegal block size
        byte[] badEncrypted = new byte[encrypted.length + 3];
        System.arraycopy(encrypted, 0, badEncrypted, 3, encrypted.length);
        badEncrypted[0] = 1;
        badEncrypted[1] = 1;
        badEncrypted[2] = 1;
        try {
            encryptor.decrypt(context, badEncrypted);
            fail("must throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(), is("decryption failed. transformation = [AES/CBC/PKCS5Padding]"));
            assertThat(e.getCause()
                        .getClass()
                        .getName(), is(IllegalBlockSizeException.class.getName()));
        }

        // tempering
        encrypted[1] = 1;
        encrypted[3] = 3;
        encrypted[5] = 5;
        try {
            encryptor.decrypt(context, encrypted);
            fail("must throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(), is("decryption failed. transformation = [AES/CBC/PKCS5Padding]"));
            assertThat(e.getCause()
                        .getClass()
                        .getName(), is(BadPaddingException.class.getName()));
        }
    }

    private byte[] generateIv() {
        final SecureRandom random = new SecureRandom();
        final byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }
}
