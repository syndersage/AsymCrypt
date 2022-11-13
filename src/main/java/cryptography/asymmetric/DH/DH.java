package cryptography.asymmetric.DH;

import java.math.BigInteger;

public class DH {
  public static byte[] calculate(DHKeys keys) {
    byte[] base = keys.base;
    byte[] modulus = keys.modulus;
    byte[] privateKey = keys.privateKey;
    BigInteger intBase = new BigInteger(base);
    BigInteger intModulus = new BigInteger(modulus);
    BigInteger intKey = new BigInteger(privateKey);
    return intBase.modPow(intKey, intModulus).toByteArray();
  }
}
