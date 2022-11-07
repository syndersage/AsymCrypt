package cryptography.asymmetric;

import cryptography.asymmetric.RSA.OAEP;
import cryptography.asymmetric.RSA.RSA;
import cryptography.asymmetric.RSA.RSAKeys;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class TemporaryMain {

  public static void main(String[] args) {
    double startTime = System.nanoTime();

    RSAKeys keys = new RSAKeys(2048);
    OAEP paddingParams = new OAEP(new byte[0], 1024 / 8);
    keys = new RSAKeys(1024);
    System.out.println(keys.modulus.length);
    System.out.println("Key gen time: " + (System.nanoTime() - startTime) / 1_000_000_000);

    byte[] in = new byte[1];
    try {
      in = Files.readAllBytes(Path.of("F:\\Пользователи\\Pavel\\OneDrive\\Рабочий стол\\Уроки\\КМЗИ (2 семестр)\\Тест.docx"));
    } catch (IOException e) {
      e.printStackTrace();
    }

    double encryptTime = System.nanoTime();

    byte[] encryptedData = RSA.encrypt(in, keys, paddingParams);

    System.out.println("Encrypt time: " + (System.nanoTime() - encryptTime) / 1_000_000_000);

    double decryptTime = System.nanoTime();

    System.out.println();
    System.out.println();
    System.out.println();

    byte[] decryptedData = RSA.decrypt(encryptedData, keys, paddingParams);

    try {
      Files.write(Path.of("F:\\Пользователи\\Pavel\\OneDrive\\Рабочий стол\\Уроки\\КМЗИ (2 семестр)\\Тест4.docx"), decryptedData);
    } catch (IOException e) {
      e.printStackTrace();
    }

    System.out.println("Decrypt time: " + (System.nanoTime() - decryptTime) / 1_000_000_000);
  }

}
