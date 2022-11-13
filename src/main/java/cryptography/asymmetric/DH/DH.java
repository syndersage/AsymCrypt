package cryptography.asymmetric.DH;

import java.math.BigInteger;

public class DH {
  public static byte[] calculate(byte[] base, byte[] modulus, byte[] privateKey) {
    BigInteger intBase = new BigInteger(base);
    BigInteger intModulus = new BigInteger(modulus);
    BigInteger intKey = new BigInteger(privateKey);
    return intBase.modPow(intKey, intModulus).toByteArray();
  }
}
