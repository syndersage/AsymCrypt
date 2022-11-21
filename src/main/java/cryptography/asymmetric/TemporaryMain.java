package cryptography.asymmetric;

import cryptography.asymmetric.md5.MD5;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TemporaryMain {

  public static BigInteger base;
  public static BigInteger modulus;
  public static BigInteger subgroup1;
  public static byte[] privateKey;

  public static void main(String[] args) {
    Security.addProvider(new BouncyCastleProvider());
    double startTime = System.nanoTime();

    MD5 md5 = new MD5();
    String data = "012345678901234567890123456789012345678901234567890123456789";
    byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
    try {
      bytes = Files.readAllBytes(Path.of("F:\\Пользователи\\Pavel\\OneDrive\\Рабочий стол\\Уроки\\4 курс.rar"));
      System.out.println(bytes.length);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    md5.calculate(bytes);

    System.out.println("Time: " + (System.nanoTime() - startTime) / 1_000_000_000);
  }

}
