package cryptography.asymmetric.elgamal;

import cryptography.asymmetric.Numbers;
import java.math.BigInteger;
import java.util.Map;

public class ElGamalKeys {

  public static final int MAX_KEY_LENGTH = 3072;
  public static final int MIN_KEY_LENGTH = 8;
  public byte[] modulus;
  public int byteKeyLength;
  public byte[] base;
  public byte[] personalPublicKey;
  public byte[] personalPrivateKey;

  public ElGamalKeys(int keyLength) throws IllegalArgumentException {
    if (keyLength < MIN_KEY_LENGTH | keyLength > MAX_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "Key length (in bits) have to in range from " + MIN_KEY_LENGTH + " to " + MAX_KEY_LENGTH);
    }
    Map<String, BigInteger> group = Numbers.generateCyclicGroup(keyLength);
    modulus = group.get("Modulus").toByteArray();
    base = group.get("Generator").toByteArray();
    this.byteKeyLength = modulus.length;
  }

  public ElGamalKeys(BigInteger base, BigInteger modulus) throws IllegalArgumentException {
    if (modulus.bitLength() < MIN_KEY_LENGTH
        | modulus.bitLength() > MAX_KEY_LENGTH + Numbers.randomValueSize + 1) {
      throw new IllegalArgumentException(
          " Elgamal key length min and max length respectively: " + MIN_KEY_LENGTH + ", "
              + MAX_KEY_LENGTH);
    }
    if (base.compareTo(BigInteger.ONE) <= 0 | base.compareTo(modulus) >= 0) {
      throw new IllegalArgumentException(" Generator must be positive and less than modulus");
    }
    this.base = base.toByteArray();
    this.modulus = modulus.toByteArray();
    this.byteKeyLength = this.modulus.length;
  }

  public void setPersonalKeys() {
    BigInteger tempPrivate;
    do {
      tempPrivate = new BigInteger(byteKeyLength * 8, Numbers.random);
    } while (tempPrivate.compareTo(new BigInteger(modulus).add(BigInteger.ONE)) >= 0);
    personalPublicKey = new BigInteger(base).modPow(tempPrivate, new BigInteger(modulus))
        .toByteArray();
    personalPrivateKey = tempPrivate.toByteArray();
  }

  public void setPersonalKeys(BigInteger publicKey, BigInteger privateKey)
      throws IllegalArgumentException {
    if (publicKey.compareTo(BigInteger.ONE) <= 0 | publicKey.compareTo(new BigInteger(modulus)) >= 0
        | privateKey.compareTo(BigInteger.ONE) <= 0
        | privateKey.compareTo(new BigInteger(modulus)) >= 0) {
      throw new IllegalArgumentException(" Keys must be greater than 1 and less than modulus");
    }
    personalPublicKey = publicKey.toByteArray();
    personalPrivateKey = privateKey.toByteArray();
  }

  public void setPersonalKeys(BigInteger personalKey, boolean isPublicKey)
      throws IllegalArgumentException {
    if (personalKey.compareTo(BigInteger.ONE) <= 0
        | personalKey.compareTo(new BigInteger(modulus)) >= 0) {
      throw new IllegalArgumentException((isPublicKey ? " Public" : "Private")
          + " key must be greater than 1 and less than modulus");
    }
    if (isPublicKey) {
      personalPublicKey = personalKey.toByteArray();
    } else {
      personalPrivateKey = personalKey.toByteArray();
    }
  }
}
