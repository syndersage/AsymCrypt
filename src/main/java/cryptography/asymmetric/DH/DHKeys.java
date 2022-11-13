package cryptography.asymmetric.DH;

import cryptography.asymmetric.Numbers;
import java.math.BigInteger;

public class DHKeys {

  public byte[] base;
  public byte[] modulus;

  public DHKeys(int keyLength) throws IllegalArgumentException {
    BigInteger tempBase;
    do {
      tempBase = Numbers.genNumber(keyLength - 1);
      while (!Numbers.isPrime(tempBase)) {
        tempBase = Numbers.genNumber(keyLength - 1);
      }
      modulus = tempBase.multiply(BigInteger.TWO).add(BigInteger.ONE).toByteArray();
      System.out.println(Numbers.isPrime(new BigInteger(modulus)));
    } while (modulus.length != keyLength);
    base = tempBase.toByteArray();
  }
}
