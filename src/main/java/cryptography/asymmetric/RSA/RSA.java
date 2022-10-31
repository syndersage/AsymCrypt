package cryptography.asymmetric.RSA;

import cryptography.asymmetric.BasicAlgorithms;
import cryptography.asymmetric.Cipher;
import cryptography.asymmetric.Numbers;
import java.math.BigInteger;
import java.util.Arrays;

public class RSA implements Cipher {

  public static boolean USE_DEFAULT_PUBLIC_KEY = true;
  public static final BigInteger DEFAULT_PUBLIC_PRIME_BIG = BigInteger.valueOf(65_537);
  public static final int MAX_KEY_LENGTH = 6144;
  public static final int MIN_KEY_LENGTH = 128;

  public String padding = "None";

  private BigInteger privateKey = null;
  private BigInteger publicKey = null;
  private BigInteger modulus = null;

  private int keyLength;

  private int byteKeyLength;


  @Override
  public byte[] encrypt(byte[] data) throws NullPointerException {
    if (privateKey == null | publicKey == null || modulus == null) {
      throw new NullPointerException("Key pair is not specified");
    }
    //Данные делятся на блоки, если они не помещаются в один (деление происходит на основании максимально допустимого значения по требованию OAEP)
    int messageSize;
    if (padding.equals("None")) {
      messageSize = byteKeyLength - 1;
    } else if (padding.equals("PKCS#1-OAEP")) {
      messageSize = byteKeyLength - 2 * Numbers.digest.getDigestLength() - 2;
    } else {
      throw new NullPointerException("Invalid padding name");
    }
    byte[][] splittedData = Numbers.splitArray(data, messageSize);
    for (byte[] bytes : splittedData) {
      System.out.println(Arrays.toString(bytes));
      System.out.println(bytes.length);
    }
    byte[][] encryptedData = new byte[splittedData.length][];
    BigInteger paddedChunk;
    for (int i = 0; i < encryptedData.length; i++) {
      if (padding.equals("PKCS#1-OAEP")) {
        //Каждому блоку добавляется паддинг (OAEP), результат преобразуется в положительный integer
        paddedChunk = Numbers.os2ip(OAEP.wrap(splittedData[i], byteKeyLength));
        //Производится шифрования и результат обратно преобразуется в массив байт
        encryptedData[i] = Numbers.i2osp(paddedChunk.modPow(publicKey, modulus), byteKeyLength);
      } else if (padding.equals("None")) {
        encryptedData[i] = Numbers.i2osp(new BigInteger(1, splittedData[i]).modPow(publicKey, modulus), byteKeyLength);
        System.out.println("ENCRYPTED: " + Arrays.toString(encryptedData[i]));
      }
    }
    //Блоки объединяются в один
    return Numbers.convert2Dto1D(encryptedData);
  }

  @Override
  public byte[] decrypt(byte[] data) throws NullPointerException {
    if (privateKey == null | publicKey == null || modulus == null) {
      throw new NullPointerException("Key pair is not specified");
    }
    byte[][] splittedData = Numbers.splitArray(data, byteKeyLength);
    for (byte[] bytes : splittedData) {
      System.out.println("RECEIVED: " + Arrays.toString(bytes));
    }
    byte[][] decryptedData = new byte[splittedData.length][];
    BigInteger paddedChunk;
    for (int i = 0; i < decryptedData.length; i++) {
      if (padding.equals("PKCS#1-OAEP")) {
        paddedChunk = Numbers.os2ip(splittedData[i]);
        decryptedData[i] = Numbers.i2osp(paddedChunk.modPow(privateKey, modulus), byteKeyLength);
        decryptedData[i] = OAEP.unwrap(decryptedData[i], byteKeyLength);
      } else if (padding.equals("None")) {
        decryptedData[i] = Numbers.i2osp(new BigInteger(1, splittedData[i]).modPow(privateKey, modulus), byteKeyLength);
        //Так как шифруемый блок размером (длина ключа в байтах - 1), то первый байт после операции сверху всегда будет ноль, а общий размер равен длине ключа в байтах
        //Это вызвано проблемой деления на блоки: если блоки будут длины ключа, то их целочисленное выражение может быть больше модуля, поэтому берется на 1 байт меньше
        byte[] removeFirstByte = new byte[byteKeyLength - 1];
        System.arraycopy(decryptedData[i], 1, removeFirstByte, 0, byteKeyLength - 1);
        decryptedData[i] = removeFirstByte;
      } else {
        throw new NullPointerException("Invalid padding name");
      }
    }
    for (byte[] bytes : decryptedData) {
      System.out.println("DECRYPTED: " + Arrays.toString(bytes));
    }
    return Numbers.convert2Dto1D(decryptedData);
  }

  @Override
  public void genKeyPair(final int keyLength) throws IllegalArgumentException {
    BigInteger p, q;
    try {
      if (keyLength > MAX_KEY_LENGTH) {
        throw new IllegalArgumentException("Key length too big: max able length is " + MAX_KEY_LENGTH);
      }
      if (keyLength < MIN_KEY_LENGTH) {
        throw new IllegalArgumentException("Key length too small: min able length is " + MIN_KEY_LENGTH);
      }
      if (keyLength % 2 != 0) {
        throw new IllegalArgumentException("Key length have to be even");
      }
      do {
        p = Numbers.genNumber(keyLength / 2);
        while (!Numbers.isPrime(p)) {
          p = Numbers.genNumber(keyLength / 2);
        }
        q = Numbers.genNumber(keyLength / 2);
        while (!Numbers.isPrime(q)) {
          q = Numbers.genNumber(keyLength / 2);
        }
        modulus = p.multiply(q);
      } while (modulus.toByteArray().length != (keyLength / 8) | modulus.toByteArray()[0] == 0);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid key length", e);
    }

    BigInteger totient = BasicAlgorithms.binaryLCM(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));

    if (!USE_DEFAULT_PUBLIC_KEY) {
      BigInteger e;
      try {
        int publicKeyLength = totient.bitLength() - totient.bitLength() % 8;
        e = Numbers.genNumber(publicKeyLength);
        while ( e.gcd(totient).compareTo(BigInteger.ONE) != 0) {
          e = Numbers.genNumber(publicKeyLength);
        }
      } catch (IllegalArgumentException exception) {
        throw new IllegalArgumentException("Invalid public key length", exception);
      }
      publicKey = e;
    } else {
      publicKey = DEFAULT_PUBLIC_PRIME_BIG;
    }

    privateKey = publicKey.modInverse(totient);

    this.keyLength = keyLength;
    this.byteKeyLength = keyLength / 8;
  }

  @Override
  public byte[] getKeyPair() {
    return new byte[0];
  }

  @Override
  public void setPublicKey(byte[] key) {

  }

  @Override
  public void setPrivateKey(byte[] key) {

  }
}
