package cryptography.asymmetric;

import cryptography.asymmetric.dsa.DSA;
import cryptography.asymmetric.dsa.DSAKeys;
import cryptography.asymmetric.gui.UserSelections;
import cryptography.asymmetric.md5.MD5;
import cryptography.asymmetric.sha.SHA;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TemporaryMain {

  public static void main(String[] args) {
    Security.addProvider(new BouncyCastleProvider());
    double startTime = System.nanoTime();

    DSAKeys key = new DSAKeys(1024, 160);
    key.setPersonalKeys();
    byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
    byte[] sign = DSA.sign(data, key);
    System.out.println(Arrays.toString(sign));
    System.out.println(Arrays.toString(DSA.verify(data, key, sign)));

    System.out.println("Time: " + (System.nanoTime() - startTime) / 1_000_000_000);
  }
}
