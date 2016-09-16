package nablarch.common.encryption;

import java.io.Serializable;

import nablarch.core.util.annotation.Published;

/**
 * 暗号化と復号を行うインタフェース。
 * @author Kiyohito Itoh
 * @param <C> 暗号化と復号に使用するコンテキスト情報の型
 */
@Published(tag = "architect")
public interface Encryptor<C extends Serializable> {

    /**
     * 暗号化と復号に使用するコンテキスト情報を生成する。<br>
     * コンテキスト情報には、共通鍵暗号方式であれば使用する共通鍵を保持する。
     * @return 暗号化と復号に使用するコンテキスト情報
     */
    C generateContext();
    
    /**
     * コンテキスト情報を使用して暗号化を行う。
     * @param context コンテキスト情報
     * @param src 暗号元
     * @return 暗号結果
     * @throws IllegalArgumentException 暗号化できなかった場合
     */
    byte[] encrypt(C context, byte[] src) throws IllegalArgumentException;
    
    /**
     * コンテキスト情報を使用して復号を行う。
     * @param context コンテキスト情報
     * @param src 復号元
     * @return 復号結果
     * @throws IllegalArgumentException 復号できなかった場合
     */
    byte[] decrypt(C context, byte[] src) throws IllegalArgumentException;
}
