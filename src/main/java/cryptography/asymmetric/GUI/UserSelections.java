package cryptography.asymmetric.GUI;

public class UserSelections {

  public static String currentAlgorithm = null;

  public static String encryptOrDecrypt = "Encrypt";

  //true - auto, false - manually
  public static boolean keyGenAutoOrManually = true;

  //true - file input, false - text field input
  public static boolean fileInput = false;

  public static String inputFilePath;

  public static String outputFilePath;

  public static byte[] testUserOutput;
  public static String rsaPadding = "None";
}
