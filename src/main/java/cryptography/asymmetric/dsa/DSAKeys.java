package cryptography.asymmetric.dsa;

import cryptography.asymmetric.Numbers;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;

public class DSAKeys {

  public byte[] modulus;

  public byte[] groupOrder;

  public byte[] base;
  public byte[] personalPublicKey;

  public byte[] personalPrivateKey;

  public static final int[][] ABLE_PAIRS = {{1024, 160}, {2048, 224}, {2048, 256}, {3072, 256}};

  public DSAKeys(int modulusLength, int order) throws IllegalArgumentException {
    int contain = 0;
    for (int[] ablePair : ABLE_PAIRS) {
      if (modulusLength == ablePair[0] & order == ablePair[1]) {
        contain++;
        break;
      }
    }
    if (contain != 1) {
      throw new IllegalArgumentException(" Modulus size and group order must one of the following pairs:" + Arrays.deepToString(
          ABLE_PAIRS));
    }
    Map<String, BigInteger> group = Numbers.generateCyclicGroup(modulusLength, order);
    modulus = group.get("Modulus").toByteArray();
    base = group.get("Generator").toByteArray();
    groupOrder = group.get("Order").toByteArray();
  }

  public DSAKeys(BigInteger base, BigInteger modulus, BigInteger order) throws IllegalArgumentException {
    int contain = 0;
    for (int[] ablePair : ABLE_PAIRS) {
      if (modulus.bitLength() == ablePair[0] & order.bitLength() == ablePair[1]) {
        contain++;
        break;
      }
    }
    if (contain != 1) {
      throw new IllegalArgumentException("Modulus size and group order must one of the following pairs:" + Arrays.deepToString(
          ABLE_PAIRS));
    }
    if (base.compareTo(BigInteger.ONE) <= 0 | base.compareTo(modulus) >= 0) {
      throw new IllegalArgumentException(" Generator must be positive and less than modulus");
    }
    this.base = base.toByteArray();
    this.modulus = modulus.toByteArray();
    this.groupOrder = order.toByteArray();
  }

  public void setPersonalKeys() {
    BigInteger tempPrivate;
    do {
      tempPrivate = new BigInteger(groupOrder.length * 8, Numbers.random);
    } while (tempPrivate.compareTo(new BigInteger(1, groupOrder)) >= 0);
    personalPublicKey = new BigInteger(1, base).modPow(tempPrivate, new BigInteger(1, modulus)).toByteArray();
    personalPrivateKey = tempPrivate.toByteArray();
  }

  public void setPersonalKeys(BigInteger publicKey, BigInteger privateKey) throws IllegalArgumentException {
    if (publicKey.compareTo(BigInteger.ONE) <= 0 | publicKey.compareTo(new BigInteger(1, modulus)) >= 0
        | privateKey.compareTo(BigInteger.ONE) <= 0 | privateKey.compareTo(new BigInteger(1, groupOrder)) >= 0) {
      throw new IllegalArgumentException(" Keys must be greater than 1 and less than group order");
    }
    personalPublicKey = publicKey.toByteArray();
    personalPrivateKey = privateKey.toByteArray();
  }

  public void setPublicKey(BigInteger publicKey) throws IllegalArgumentException {
    if (publicKey.compareTo(new BigInteger(1, modulus)) >= 0 | publicKey.compareTo(BigInteger.ONE) <= 0) {
      throw new IllegalArgumentException("Incorrect public key size");
    } else {
      personalPublicKey = publicKey.toByteArray();
    }
  }

  public void setPrivateKey(BigInteger privateKey) throws IllegalArgumentException {
    if (privateKey.compareTo(new BigInteger(1, groupOrder)) >= 0 | privateKey.compareTo(BigInteger.ONE) <= 0) {
      throw new IllegalArgumentException("Incorrect public key size");
    } else {
      personalPrivateKey = privateKey.toByteArray();
    }
  }
}
