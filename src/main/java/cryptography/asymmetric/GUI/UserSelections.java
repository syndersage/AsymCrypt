package cryptography.asymmetric.GUI;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.concurrent.Semaphore;
import javax.swing.JProgressBar;
import javax.swing.SwingWorker;
import org.bouncycastle.jcajce.provider.digest.SHA256;

public class UserSelections {

  public static String currentAlgorithm = null;

  //true - encrypt, false - decrypt
  public static boolean encryptOrDecrypt = true;

  //true - auto, false - manually
  public static boolean keyGenAutoOrManually = true;

  //true - file input, false - text field input
  public static boolean fileInput = false;

  public static String inputFilePath;

  public static String outputFilePath;

  public static byte[] testUserOutput;
  public static String rsaPadding = "None";

  public static MessageDigest digest = new SHA256.Digest();

  //Кодировку нужно выбирать ту, на которой у тебя ОС (в винде проверить - chcp в powershell)
  public static String charsetString = "CP866";

  public static JProgressBar progress;

  public static Semaphore progressQueue = new Semaphore(1);

  public static SwingWorker<Void, Void> calculationThread;
}
