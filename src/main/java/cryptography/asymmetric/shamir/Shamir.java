package cryptography.asymmetric.shamir;

import cryptography.asymmetric.Numbers;
import java.math.BigInteger;

public class Shamir {

  public static byte[] calculate(byte[] data, ShamirKeys keys, boolean firstPart) {
    byte[] publicKey = keys.publicKey;
    byte[] privateKey = firstPart ? keys.firstPrivateKey : keys.secondPrivateKey;
    BigInteger intData = Numbers.os2ip(data);
    BigInteger intPublic = new BigInteger(publicKey);
    BigInteger intPrivate = new BigInteger(privateKey);
    return Numbers.i2osp(intData.modPow(intPrivate, intPublic), publicKey.length);
  }

}
