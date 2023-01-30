import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class GenerateHashedPw {
  // パスワードのアルゴリズム
  private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
  // ストレッチング回数
  private static final int ITERATION_COUNT = 10000;
  // 生成される鍵の長さ
  private static final int KEY_LENGTH = 256;

  /**
   * @getHashedSalt 受け取った文字列をソルトとしてbyte配列に変換
   *
   * @param salt ソルト
   * @return saltをbyte配列にて返却
   */
  private static byte[] getHashedSalt(String salt) {
    MessageDigest messageDigest;
    try {
      messageDigest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
    messageDigest.update(salt.getBytes());
    return messageDigest.digest();
  }

  /**
   * @getSafetyPassword 安全なパスワードの生成
   * 
   * @parm password
   * @parm
   */
  public static String getSafetyPassword(String password, String salt) {
    char[] passCharAry = password.toCharArray();
    // ユーザIDをソルトとしてbyte配列に変換
    byte[] hashedSalt = getHashedSalt(salt);

    /**第1引数：パスワード
     * 第2引数：ソルト
     * 第3引数：ストレッチング回数
     * 第4引数：生成文字列長
     */
    PBEKeySpec keySpec = new PBEKeySpec(, hashedSalt, ITERATION_COUNT, KEY_LENGTH);

    //秘密鍵生成のアルゴリズムを定義
    SecretKeyFactory skf;
    try {
      skf = SecretKeyFactory.getInstance(ALGORITHM);
    } catch (InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
    byte[] passByteAry = SecretKey.getEncoded();

    //生成されたバイト配列を16進数の文字列に変換
    StringBuilder sb = new StringBuilder(64);
    for(byte b : passByteAry) {
      sb.append(String.format("%02x", b & 0xff));
    }
    return sb.toString();
  }
}