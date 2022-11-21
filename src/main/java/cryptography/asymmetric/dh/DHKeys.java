package cryptography.asymmetric.dh;

import cryptography.asymmetric.Numbers;
import java.math.BigInteger;

public class DHKeys {

  public byte[] base;
  public byte[] modulus;
  public byte[] privateKey;

  public static final BigInteger MIN_BASE = new BigInteger("2");
  public static final BigInteger MIN_MODULUS = new BigInteger("16");


  public DHKeys(int keyLength) throws IllegalArgumentException {
    if (keyLength < 4 | keyLength > 3072) {
      throw new IllegalArgumentException("Too " + (keyLength < 4 ? "small" : "big") + " key length");
    }
    BigInteger tempBase, tempModulus, subGroup;
    do {
      subGroup = new BigInteger(keyLength, Numbers.random);
    } while (!subGroup.isProbablePrime(128));
    BigInteger multiplier;
    do {
      multiplier = new BigInteger(16, Numbers.random);
      tempModulus = subGroup.multiply(multiplier).add(BigInteger.ONE);
    } while (!tempModulus.isProbablePrime(128));
    do {
      tempBase = new BigInteger(16, Numbers.random).modPow(multiplier, tempModulus);
    } while (tempBase.equals(BigInteger.ONE));
    base = tempBase.toByteArray();
    modulus = tempModulus.toByteArray();
  }

  public DHKeys(BigInteger base, BigInteger modulus) {
    if (base.compareTo(new BigInteger("1")) <= 0) {
      throw new IllegalArgumentException(" Base cannot be less than 2");
    }
    if (modulus.compareTo(new BigInteger("15")) <= 0) {
      throw new IllegalArgumentException(" Modulus cannot be less than 16");
    }
    System.out.println("BASE: " + base);
    System.out.println("MODU: " + modulus);
    if (base.compareTo(modulus) >= 0) {
      throw new IllegalArgumentException("Base size have to be smaller than modulus");
    }
    this.base = base.toByteArray();
    this.modulus = modulus.toByteArray();
  }

  public void setPrivateKey(BigInteger key) {
    if (key.compareTo(BigInteger.ONE) <= 0) {
      throw new IllegalArgumentException(" Private ey cannot be less than 1");
    }
    if (key.compareTo(new BigInteger(modulus)) >= 0) {
      throw new IllegalArgumentException(" Private key size have to be smaller than modulus");
    }
    this.privateKey = key.toByteArray();
  }

  public void setPrivateKey() {
    do {
      privateKey = new BigInteger(modulus.length * 8, Numbers.random).toByteArray();
    } while (new BigInteger(privateKey).compareTo(new BigInteger(modulus)) >= 0 | new BigInteger(privateKey).compareTo(BigInteger.ONE) <= 0);
  }
}
