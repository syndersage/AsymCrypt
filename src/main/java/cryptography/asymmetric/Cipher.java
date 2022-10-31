package cryptography.asymmetric;

public interface Cipher {
  byte[] encrypt(byte[] data);
  byte[] decrypt(byte[] data);
  void genKeyPair(int keyLength);
  byte[] getKeyPair();
  void setPublicKey(byte[] key);
  void setPrivateKey(byte[] key);
}
