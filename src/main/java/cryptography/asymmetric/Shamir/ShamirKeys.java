package cryptography.asymmetric.Shamir;

import cryptography.asymmetric.Numbers;
import java.math.BigInteger;

public class ShamirKeys {

  public byte[] publicKey;
  public byte[] firstPrivateKey;
  public byte[] secondPrivateKey;

  //Длина ключа в битах
  public int keySize = 1;

  public ShamirKeys(int keyLength) {
    BigInteger tempPublic;
    do {
      tempPublic = new BigInteger(keyLength, Numbers.random);
    } while (tempPublic.toByteArray().length * 8 != keyLength || !tempPublic.isProbablePrime(128));
    publicKey = tempPublic.toByteArray();
    keySize = keyLength;
  }

  public ShamirKeys(BigInteger publicKey) {
    this.publicKey = publicKey.toByteArray();
    keySize = this.publicKey.length * 8;
  }

  public void setPrivateKeys() {
    BigInteger tempFirst, tempPublic = new BigInteger(publicKey);
    do {
      tempFirst = new BigInteger(tempPublic.bitLength(), Numbers.random);
    } while (tempFirst.compareTo(tempPublic.subtract(BigInteger.ONE)) >= 0 || tempFirst.gcd(tempPublic.subtract(BigInteger.ONE)).compareTo(BigInteger.ONE) != 0);
    secondPrivateKey = tempFirst.modInverse(tempPublic.subtract(BigInteger.ONE)).toByteArray();
    firstPrivateKey = tempFirst.toByteArray();
  }

  public void setPrivateKeys(BigInteger firstPrivateKey, BigInteger secondPrivateKey) throws IllegalArgumentException {
    BigInteger tempPublic = new BigInteger(publicKey);
    if (firstPrivateKey.compareTo(tempPublic) >= 0 | secondPrivateKey.compareTo(tempPublic) >= 0) {
      throw new IllegalArgumentException("Private keys cannot be bigger than public key");
    }
    if (firstPrivateKey.gcd(tempPublic.subtract(BigInteger.ONE)).compareTo(BigInteger.ONE) != 0) {
      System.out.println(tempPublic);
      System.out.println(firstPrivateKey);
      System.out.println(secondPrivateKey);
      throw new IllegalArgumentException("First private key must have modular inverse value (i.e. gcd(public, private№1) == 1)");
    }
    this.firstPrivateKey = firstPrivateKey.toByteArray();
    this.secondPrivateKey = secondPrivateKey.toByteArray();
  }
}
