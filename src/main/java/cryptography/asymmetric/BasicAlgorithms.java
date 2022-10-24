package cryptography.asymmetric;

import java.util.ArrayList;

public class BasicAlgorithms {

  private static ArrayList<Boolean> decimalToBinary(int decimal) {
    ArrayList<Boolean> binary = new ArrayList<>();
    while (decimal > 0) {
      binary.add((decimal % 2) == 1);
      decimal = decimal / 2;
    }
    return binary;
  }

  private static int pow2mod(int base, int power, int module) {
    for (int i = 0; i < power; i++) {
      base = (base * base) % module;
    }
    return base;
  }

  public static int pow(int base, int power, int module) {
    ArrayList<Boolean> binaryPower = decimalToBinary(power);
    int result = 1, counter = 0;
    for (Boolean bin: binaryPower) {
      if (bin) {
        result *= pow2mod(base, counter, module);
        result %= module;
      }
      counter++;
    }
    return result;
  }


}
