package cryptography.asymmetric.ElGamal;

import cryptography.asymmetric.Numbers;
import java.math.BigInteger;
import java.util.Map;

public class ElGamalKeys {

  public byte[] modulus;

  public int keyLength;
  public byte[] base;
  public byte[] personalPublicKey;

  public byte[] personalPrivateKey;

  public static final int MAX_KEY_LENGTH = 3072;
  public static final int MIN_KEY_LENGTH = 8;

  public ElGamalKeys(int keyLength) throws IllegalArgumentException {
    if (keyLength < MIN_KEY_LENGTH | keyLength > MAX_KEY_LENGTH) {
      throw new IllegalArgumentException("Key length (in bites) have to in range from " + MIN_KEY_LENGTH + " to " + MAX_KEY_LENGTH);
    }
    Map<String, BigInteger> group = Numbers.generateCyclicGroup(keyLength);
    modulus = group.get("Modulus").toByteArray();
    base = group.get("Generator").toByteArray();
    this.keyLength = keyLength;
  }

  public void setPersonalKeys() {
    BigInteger tempPrivate;
    do {
      tempPrivate = new BigInteger(keyLength, Numbers.random);
    } while (tempPrivate.compareTo(new BigInteger(modulus).add(BigInteger.ONE)) >= 0);
    personalPublicKey = new BigInteger(base).modPow(tempPrivate, new BigInteger(modulus)).toByteArray();
    personalPrivateKey = tempPrivate.toByteArray();
  }
}
