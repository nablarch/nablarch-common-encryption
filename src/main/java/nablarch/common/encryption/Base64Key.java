package nablarch.common.encryption;

import nablarch.core.util.Base64Util;

/**
 * Base64エンコードされた鍵を持つクラス。
 *
 * @author siosio
 */
public class Base64Key {

    /** 暗号化に使用する共通鍵(128bit) */
    private byte[] key;

    /** 暗号化に使用するIV(イニシャルバリュー)(128bit) */
    private byte[] iv;

    /**
     * 暗号化に使用する共通鍵(128bit)を設定する。
     * <p>
     * Base64エンコードされた鍵を設定すること。
     *
     * @param key 暗号化に使用する共通鍵(128bit)
     */
    public void setKey(final String key) {
        this.key = Base64Util.decode(key);
    }

    /**
     * 暗号化に使用するIV(128bit)を設定する。
     * <p>
     * Base64エンコードされたIVを設定すること。
     *
     * @param iv 暗号化に使用するIV(128bit)
     */
    public void setIv(final String iv) {
        this.iv = Base64Util.decode(iv);
    }

    /**
     * 共通鍵(128bit)を返す。
     * @return 共通鍵(128bit)
     */
    public byte[] getKey() {
        return key;
    }

    /**
     * IV(128bit)を返す。
     * @return IV(128bit)
     */
    public byte[] getIv() {
        return iv;
    }
}
