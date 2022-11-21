package cryptography.asymmetric.shamir;

import cryptography.asymmetric.Numbers;
import java.math.BigInteger;
import java.util.Arrays;

public class Shamir {

  public static byte[] calculate(byte[] data, ShamirKeys keys, boolean firstPart) {
    System.out.println(Arrays.toString(data));
    byte[] publicKey = keys.publicKey;
    byte[] privateKey = firstPart ? keys.firstPrivateKey : keys.secondPrivateKey;
    BigInteger intData = Numbers.os2ip(data);
    BigInteger intPublic = new BigInteger(publicKey);
    BigInteger intPrivate = new BigInteger(privateKey);
    System.out.println(
        Arrays.toString(Numbers.i2osp(intData.modPow(intPrivate, intPublic), publicKey.length)));
    System.out.println(publicKey.length);
    return Numbers.i2osp(intData.modPow(intPrivate, intPublic), publicKey.length);
  }

}
