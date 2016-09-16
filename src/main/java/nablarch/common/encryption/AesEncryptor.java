package nablarch.common.encryption;

import java.io.Serializable;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import nablarch.core.util.StringUtil;


/**
 * AES暗号(128bit, CBC, PKCS5Padding)を使用して暗号化と復号を行うクラス。
 * @author Kiyohito Itoh
 */
public class AesEncryptor implements Encryptor<AesEncryptor.AesContext> {

    /** 暗号化に使用する鍵長 */
    private static final int KEY_LENGTH = 128;
    
    /** 暗号化に使用するアルゴリズム */
    private static final String CIPHER_ALGORITHM = "AES";
    
    /** 暗号化に使用するモード */
    private static final String CIPHER_MODE = "CBC";
    
    /** 暗号化に使用するパディング */
    private static final String CIPHER_PADDING = "PKCS5Padding";
    
    /** 変換形式(アルゴリズム/モード/パディング) */
    private static final String TRANSFORMATION = String.format("%s/%s/%s", CIPHER_ALGORITHM, CIPHER_MODE, CIPHER_PADDING);
    
    /** 乱数ジェネレータ */
    private static final SecureRandom RANDOM;
    
    /** 乱数ジェネレータに使用するアルゴリズム */
    private static final String RANDOM_ALGORITHM = "SHA1PRNG";
    
    static {
        try {
            RANDOM = SecureRandom.getInstance(RANDOM_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            // アルゴリズムが固定のため到達不能
            throw new IllegalStateException("SecureRandom initialization failed.", e);
        }
    }

    /** 暗号化に使用する共通鍵(128bit) */
    private String key;

    /** 暗号化に使用するIV(イニシャルバリュー)(128bit) */
    private String iv;

    /**
     * 暗号化に使用する共通鍵(128bit)を設定する。
     * @param key 暗号化に使用する共通鍵(128bit)
     */
    public void setKey(String key) {
        this.key = key;
    }

    /**
     * 暗号化に使用するIV(イニシャルバリュー)(128bit)を設定する。
     * @param iv 暗号化に使用するIV(イニシャルバリュー)(128bit)
     */
    public void setIv(String iv) {
        this.iv = iv;
    }

    /**
     * {@inheritDoc}<br>
     * 共通鍵とIV(イニシャルバリュー)を生成し、コンテキスト情報として返す。
     * <p/>
     * {@link #key}プロパティ、{@link #iv}プロパティが設定されている場合は、
     * 設定されている値から、共通鍵とIV(イニシャルバリュー)を生成する。
     * 設定されていない場合は、乱数ジェネレータにより自動生成する。
     */
    public AesContext generateContext() {
        return new AesContext(generateKey(KEY_LENGTH), generateIv(KEY_LENGTH));
    }
    
    /**
     * {@inheritDoc}
     */
    public byte[] encrypt(AesContext context, byte[] src) {
        if (context == null || src == null) {
            throw new IllegalArgumentException("context or src is null.");
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, context.getKey(), new IvParameterSpec(context.getIv()));
            return cipher.doFinal(src);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(String.format("encryption failed. transformation = [%s]", TRANSFORMATION), e);
        }
    }
    
    /**
     * {@inheritDoc}
     */
    public byte[] decrypt(AesContext context, byte[] src) {
        if (context == null || src == null) {
            throw new IllegalArgumentException("context or src is null.");
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, context.getKey(), new IvParameterSpec(context.getIv()));
            return cipher.doFinal(src);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(String.format("decryption failed. transformation = [%s]", TRANSFORMATION), e);
        }
    }

    /**
     * 共通鍵又はIV(イニシャルバリュー)の文字列からバイト配列を取得する。
     * <p/>
     * デフォルト実装では"UTF-8"で符号化する。
     * 
     * @param text 共通鍵又はIV(イニシャルバリュー)の文字列
     * @return バイト配列
     */
    protected byte[] getBytes(String text) {
        return text.getBytes(Charset.forName("UTF-8"));
    }

    /**
     * 共通鍵を生成する。
     * @param length 鍵長(bit)
     * @return 共通鍵
     */
    protected Key generateKey(int length) {
        if (StringUtil.hasValue(key)) {
            return new SecretKeySpec(getBytes(key), CIPHER_ALGORITHM);
        } else {
            try {
                KeyGenerator generator = KeyGenerator.getInstance(CIPHER_ALGORITHM);
                generator.init(length, RANDOM);
                return generator.generateKey();
            } catch (NoSuchAlgorithmException e) {
                // アルゴリズムが固定のため到達不能
                throw new IllegalStateException(String.format("key generating failed. cipher algorithm = [%s]", CIPHER_ALGORITHM), e);
            }
        }
    }
    
    /**
     * IV(イニシャルバリュー)を生成する。
     * @param length 鍵長(bit)
     * @return IV(イニシャルバリュー)
     */
    protected byte[] generateIv(int length) {
        if (StringUtil.hasValue(iv)) {
            return getBytes(iv);
        } else {
            byte[] iv = new byte[length / 8];
            RANDOM.nextBytes(iv);
            return iv;
        }
    }
    
    /**
     * AES暗号のコンテキスト情報を保持するクラス。
     * @author Kiyohito Itoh
     */
    public static final class AesContext implements Serializable {
        
        /** 共通鍵 */
        private final Key key;
        
        /** IV(イニシャルバリュー) */
        private final byte[] iv;
        
        /**
         * @param key 共通鍵
         * @param iv IV(イニシャルバリュー)
         */
        public AesContext(Key key, byte[] iv) {
            this.key = key;
            this.iv = iv;
        }
        
        /**
         * 共通鍵を取得する。
         * @return 共通鍵
         */
        public Key getKey() {
            return key;
        }
        
        /**
         * IV(イニシャルバリュー)を取得する。
         * @return IV(イニシャルバリュー)
         */
        public byte[] getIv() {
            return iv;
        }
    }
}
