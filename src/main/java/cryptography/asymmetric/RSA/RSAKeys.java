package cryptography.asymmetric.RSA;

import cryptography.asymmetric.BasicAlgorithms;
import cryptography.asymmetric.Numbers;
import java.math.BigInteger;

public class RSAKeys {

  public static boolean USE_DEFAULT_PUBLIC_KEY = true;
  public static final BigInteger DEFAULT_PUBLIC_PRIME = BigInteger.valueOf(65_537);

  //Длина выше - очень долгая генерация ключей (30+ секунд)
  public static final int MAX_KEY_LENGTH = 6144;

  //Длина меньше 16 не позволит сгенерировать числа (т.к. они генерируются по байтам).
  //Длина 16 не позволит потому что у всех получающихся модулей всегда будет 3-й байт с обозначением знака (BigInteger)
  public static final int MIN_KEY_LENGTH = 32;

  public byte[] publicKey;
  public byte[] privateKey;
  public byte[] modulus;

  /**
   * Генерируется пара {@code byte} ключей RSA (открытый, закрытый и модуль)
   * @param keyLength требуемая длина ключа (модуля)
   * @throws IllegalArgumentException некорректная длина ключа (модуль должен быть кратен 2, открытый и закрытый кратны 8 (байту). Кратность 8 объясняется тем, что генерация числа происходит побайтово
   */
  public RSAKeys(final int keyLength) throws IllegalArgumentException {
    BigInteger p, q, tempModulus;
    int byteKeyLength = keyLength / 8;
    //System.out.println(byteKeyLength);
    try {
      if (keyLength > MAX_KEY_LENGTH) {
        throw new IllegalArgumentException("Key length too big: max auto generation length is " + MAX_KEY_LENGTH + " bits");
      }
      if (keyLength < MIN_KEY_LENGTH) {
        throw new IllegalArgumentException("Key length too small: min auto generation length is " + MIN_KEY_LENGTH + " bits");
      }
      if (keyLength % 2 != 0) {
        throw new IllegalArgumentException("Key length have to be even");
      }
      do {
        p = Numbers.genNumber(keyLength / 2);
        while (p.compareTo(BigInteger.TWO) <= 0 || !Numbers.isPrime(p)) {
          p = Numbers.genNumber(keyLength / 2);
        }
        q = Numbers.genNumber(keyLength / 2);
        while (q.compareTo(BigInteger.TWO) <= 0 || !Numbers.isPrime(q)) {
          q = Numbers.genNumber(keyLength / 2);
        }
        tempModulus = p.multiply(q);
      } while (tempModulus.toByteArray().length != (byteKeyLength) | tempModulus.toByteArray()[0] == 0);
      modulus = Numbers.i2osp(tempModulus, byteKeyLength);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid key length", e);
    }

    BigInteger totient = BasicAlgorithms.binaryLCM(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));

    BigInteger tempPublic;
    if (!USE_DEFAULT_PUBLIC_KEY) {
      BigInteger e;
      try {
        int publicKeyLength = totient.bitLength() - totient.bitLength() % 8;
        e = Numbers.genNumber(publicKeyLength);
        while (e.gcd(totient).compareTo(BigInteger.ONE) != 0) {
          e = Numbers.genNumber(publicKeyLength);
        }
      } catch (IllegalArgumentException exception) {
        throw new IllegalArgumentException("Invalid public key length", exception);
      }
      tempPublic = e;
    } else {
      tempPublic = DEFAULT_PUBLIC_PRIME;
    }
    publicKey = tempPublic.toByteArray();
    this.privateKey = tempPublic.modInverse(totient).toByteArray();

  }

  public RSAKeys(BigInteger publicKey, BigInteger privateKey, BigInteger modulus) throws NullPointerException {
    if (modulus == null) {
      throw new NullPointerException("Modulus have to be specified");
    }
    this.modulus = modulus.toByteArray();
    if (publicKey == null & privateKey == null) {
      throw new NullPointerException("Private or public key have to be specified");
    } else {
      if (publicKey != null) {
        this.publicKey = publicKey.toByteArray();
      } else {
        this.privateKey = privateKey.toByteArray();
      }
    }
  }
}
