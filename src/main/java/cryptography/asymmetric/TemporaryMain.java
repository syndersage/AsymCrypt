package cryptography.asymmetric;

import cryptography.asymmetric.elgamal.ElGamalKeys;
import cryptography.asymmetric.elgamal.ElGamalSignature;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TemporaryMain {

  public static void main(String[] args) {
    Security.addProvider(new BouncyCastleProvider());
    double startTime = System.nanoTime();

    ElGamalKeys keys = new ElGamalKeys(32);
    keys.setPersonalKeys();

    byte[] data = "123".getBytes(StandardCharsets.UTF_8);

    byte[] signed = ElGamalSignature.sign(data, keys);

    byte[] validation = ElGamalSignature.verify(keys, signed);

    byte[][] splitted = Numbers.splitArray(validation, validation.length / 2);

    System.out.println("Time: " + (System.nanoTime() - startTime) / 1_000_000_000);
  }
}
