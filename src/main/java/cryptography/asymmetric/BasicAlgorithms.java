package cryptography.asymmetric;

import java.math.BigInteger;
import java.util.ArrayList;

public class BasicAlgorithms {

  /**
   * Преобразует {@code int} десятичное входное число в двоичную форму
   * <p>Внимание! Возвращаемый бинарный результат представляется в обратном порядке</p>
   *
   * @param decimal {@code int} десятичная форма числа
   * @return двоичная форма числа в формате списка {@code ArrayList<Boolean>} со значениями true (1)
   * и false (0)
   */
  private static ArrayList<Boolean> decimalToBinary(int decimal) {
    ArrayList<Boolean> binary = new ArrayList<>();
    while (decimal > 0) {
      binary.add((decimal % 2) == 1);
      decimal = decimal / 2;
    }
    return binary;
  }

  /**
   * Преобразует {@code BigInteger} десятичное входное число в двоичную форму
   * <p>Внимание! Возвращаемый бинарный результат представляется в обратном порядке</p>
   *
   * @param decimal {@code BigInteger} десятичная форма числа
   * @return двоичная форма числа в формате списка {@code ArrayList<Boolean>} со значениями true (1)
   * и false (0)
   */
  public static ArrayList<Boolean> decimalToBinary(BigInteger decimal) {
    ArrayList<Boolean> binary = new ArrayList<>();
    while (decimal.compareTo(BigInteger.ZERO) > 0) {
      binary.add((decimal.mod(BigInteger.TWO)).equals(BigInteger.ONE));
      decimal = decimal.divide(BigInteger.TWO);
    }
    return binary;
  }

  /**
   * Возведение {@code int base} в степень {@code 2^power} по модулю {@code modulo}
   *
   * @param base   основание
   * @param power  степень 2, в которую будет возводиться основание
   * @param modulo модуль
   * @return {@code int base} число, возведенное в степень {@code 2^power} по модулю {@code module}
   */
  public static int pow2mod(int base, int power, int modulo) {
    for (int i = 0; i < power; i++) {
      base = (base * base) % modulo;
    }
    return base;
  }

  /**
   * Возведение {@code BigInteger base} в степень {@code 2^power} по модулю {@code modulo}
   *
   * @param base   основание
   * @param power  степень 2, в которую будет возводиться основание
   * @param modulo модуль
   * @return {@code BigInteger base} число, возведенное в степень {@code 2^power} по модулю
   * {@code module}
   */
  public static BigInteger pow2mod(BigInteger base, BigInteger power, BigInteger modulo) {
    for (BigInteger i = BigInteger.ZERO; i.compareTo(power) < 0; i = i.add(BigInteger.ONE)) {
      base = base.pow(2).mod(modulo);
    }
    return base;
  }

  /**
   * Возведение в степень по модулю бинарным алгоритмом
   *
   * @param base   основание
   * @param power  степень
   * @param modulo модуль
   * @return {@code int base} число, возведенное в степень {@code power} по модулю {@code modulo}
   * @see <a
   * href="https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/fast-modular-exponentiation">Описание
   * алгоритма</a>
   * @see #pow2mod(int, int, int)
   */
  public static int pow(int base, int power, int modulo) {
    ArrayList<Boolean> binaryPower = decimalToBinary(
        power); //Массив хранящий 1 и 0 в виде true и false бинарного вида степени
    int result = 1, counter = 0;
    for (Boolean bin : binaryPower) {
      //Если 1, то результат по модулю домножается на 2^counter
      if (bin) {
        result *= pow2mod(base, counter, modulo);
        result %= modulo;
      }
      counter++;
    }
    return result;
  }

  /**
   * Возведение в степень по модулю бинарным алгоритмом
   *
   * @param base   основание
   * @param power  степень
   * @param modulo модуль
   * @return {@code BigInteger base} число, возведенное в степень {@code power} по модулю
   * {@code modulo}
   * @see <a
   * href="https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/fast-modular-exponentiation">Описание
   * алгоритма</a>
   * @see #pow2mod(BigInteger, BigInteger, BigInteger)
   */
  public static BigInteger pow(BigInteger base, BigInteger power, BigInteger modulo) {
    ArrayList<Boolean> binaryPower = decimalToBinary(
        power); //Массив хранящий 1 и 0 в виде true и false бинарного вида степени
    BigInteger result = BigInteger.ONE, counter = BigInteger.ZERO;
    for (Boolean bin : binaryPower) {
      //Если 1, то результат по модулю домножается на 2^counter
      if (bin) {
        result = result.multiply(pow2mod(base, counter, modulo));
        result = result.mod(modulo);
      }
      counter = counter.add(BigInteger.ONE);
    }
    return result;
  }

  /**
   * Вычисление {@code int} степени 2, на сколько максимально возможно поделить передаваемое число
   * без остатка
   *
   * @param x число, для которого ищется максимальная степень 2, чтобы число было делимым
   * @return {@code int} степень 2, т.е. 2^return делит число x без остатка, а 2^(return+1) уже нет
   * @see <a href="https://en.wikipedia.org/wiki/Find_first_set#CTZ">CTZ - Count Trailing Zeroes</a>
   */
  public static int trailingZeroes(int x) {
    //Если входное число = 0, то максимальная степень это 0
    if (x == 0) {
      return x;
    }
    int divideByTwo = 0; //Степень двойки
    int binaryCheck = 1; //Число, используемое для логического И вместе с x
    //Проверка в бинарной форме делимости x на 2^divideByTwo
    while ((x & binaryCheck) == 0) { //Пока биты равны 0, число делится на 2^divideByTwo
      divideByTwo++;
      binaryCheck <<= 1; //Побитовый сдвиг 1 -> 10 -> 100 -> 1000 и т.д.
    }
    return divideByTwo;
  }

  /**
   * Вычисление {@code BigInteger} степени 2, на сколько максимально возможно поделить передаваемое
   * число без остатка
   *
   * @param x число, для которого ищется максимальная степень 2, чтобы число было делимым
   * @return {@code BigInteger} степень 2, т.е. 2^return делит число x без остатка, а 2^(return+1)
   * уже нет
   * @see <a href="https://en.wikipedia.org/wiki/Find_first_set#CTZ">CTZ - Count Trailing Zeroes</a>
   */
  public static BigInteger trailingZeroes(BigInteger x) {
    //Если входное число = 0, то максимальная степень это 0
    if (x.compareTo(BigInteger.ZERO) == 0) {
      return x;
    }
    BigInteger divideByTwo = BigInteger.ZERO; //Степень двойки
    BigInteger binaryCheck = BigInteger.ONE; //Число, используемое для логического И вместе с x
    //Проверка в бинарной форме делимости x на 2^divideByTwo
    while (x.and(binaryCheck).compareTo(BigInteger.ZERO)
        == 0) { //Пока биты равны 0, число делится на 2^divideByTwo
      divideByTwo = divideByTwo.add(BigInteger.ONE);
      binaryCheck = binaryCheck.shiftLeft(1); //Побитовый сдвиг 1 -> 10 -> 100 -> 1000 и т.д.
    }
    return divideByTwo;
  }


  /**
   * Нахождение наибольшего {@code int} общего делителя НОД({@code a}, {@code b}) с помощью
   * бинарного алгоритма
   *
   * @param a первое число
   * @param b второе число
   * @return Наибольший общий делитель двух входных параметров
   * @see cryptography.asymmetric.BasicAlgorithms#trailingZeroes(int)
   * @see <a href="https://en.wikipedia.org/wiki/Binary_GCD_algorithm">Описание алгоритма</a>
   */
  public static int binaryGCD(int a, int b) {
    if (a == 0) {
      return b;
    } else if (b == 0) {
      return a;
    }
    //Сколько раз a и b делятся на 2
    int aPowerOf2 = trailingZeroes(a), bPowerOf2 = trailingZeroes(b);
    a >>= aPowerOf2;
    b >>= bPowerOf2;
    int minPowerOf2 = Math.min(aPowerOf2, bPowerOf2);
    while (true) {
      if (a < b) {
        int temp = a;
        a = b;
        b = temp;
      }
      a -= b;
      if (b == 0) {
        return a << minPowerOf2;
      }
      a >>= trailingZeroes(a);
    }
  }

  /**
   * Нахождение наибольшего {@code BigInteger} общего делителя НОД({@code a}, {@code b}) с помощью
   * бинарного алгоритма
   *
   * @param a первое число
   * @param b второе число
   * @return Наибольший общий делитель двух входных параметров
   * @see cryptography.asymmetric.BasicAlgorithms#trailingZeroes(BigInteger)
   * @see <a href="https://en.wikipedia.org/wiki/Binary_GCD_algorithm">Описание алгоритма</a>
   */
  public static BigInteger binaryGCD(BigInteger a, BigInteger b) {
    if (a.compareTo(BigInteger.ZERO) == 0) {
      return b;
    } else if (b.compareTo(BigInteger.ZERO) == 0) {
      return a;
    }
    BigInteger aPowerOf2 = trailingZeroes(a), bPowerOf2 = trailingZeroes(b);
    a = a.shiftRight(aPowerOf2.intValue());
    b = b.shiftRight(bPowerOf2.intValue());
    BigInteger minPowerOf2 = aPowerOf2.min(bPowerOf2);
    BigInteger temp;
    while (true) {
      if (a.compareTo(b) < 0) {
        temp = a;
        a = b;
        b = temp;
      }
      a = a.add(b.negate());
      if (b.compareTo(BigInteger.ZERO) == 0) {
        return a.shiftLeft(minPowerOf2.intValue());
      }
      a = a.shiftRight(trailingZeroes(a).intValue());
    }
  }

  /**
   * Нахождение {@code int} обратного числа в конечном поле
   * <p>Частный случай:
   * <li> Если обратного числа не существует, результат = -1
   *
   * @param a число, для которого ищется обратное
   * @param p число элементов поля, в котором ищется обратное число
   * @return обратное для {@code a} число по модулю {@code p}
   * @see <a href="http://www-math.ucdenver.edu/~wcherowi/courses/m5410/exeucalg.html">Расширенный
   * алгоритм Евклида</a>
   */
  public static int multiplicativeInverse(int a, int p) {
    //Если НОД не 1, то обратного числа не существует
    if (binaryGCD(a, p) != 1) {
      return -1;
    }
    a %= p;
    //p0 и p1 - величины для нахождения обратного числа, temp для присваивания новых величин
    //r - остаток от деления, b - заменяет p в выражении НОД(a, p) так как начальная величина модуля не должно меняться
    int p0 = 0, p1 = 1, r = p % a, b = p, temp;
    //Продолжать пока число не будет делиться без остатка
    while (r != 0) {
      //Вычисление по формуле p(i) = (p(i-2) - p(i-1) * q(i-2)) mod n (где i, i-1, i-2 порядковые номера p и q)
      temp = p1;
      p1 = (p0 - p1 * (b / a)) % p;
      //Когда число получается отрицательным, то вычисляется его положительное значение в поле
      if (p1 < 0) {
        p1 = p + p1;
      }
      p0 = temp;
      //Вычисление a, b, r нового шага
      b = a;
      a = r;
      r = b % a;
    }
    return p1;
  }

  /**
   * Нахождение {@code BigInteger} обратного числа в конечном поле
   * <p>Частный случай:
   * <li> Если обратного числа не существует, результат = -1
   *
   * @param a число, для которого ищется обратное
   * @param p число элементов поля, в котором ищется обратное число
   * @return обратное для {@code a} число по модулю {@code p}
   * @see <a href="http://www-math.ucdenver.edu/~wcherowi/courses/m5410/exeucalg.html">Расширенный
   * алгоритм Евклида</a>
   */
  public static BigInteger multiplicativeInverse(BigInteger a, BigInteger p) {
    //Если НОД не 1, то обратного числа не существует
    if (binaryGCD(a, p).compareTo(BigInteger.ONE) != 0) {
      return BigInteger.ONE.negate();
    }
    a = a.mod(p);
    //p0 и p1 - величины для нахождения обратного числа, temp для присваивания новых величин
    //r - остаток от деления, b - заменяет p в выражении НОД(a, p) так как начальная величина модуля не должно меняться
    BigInteger p0 = BigInteger.ZERO, p1 = BigInteger.ONE, r = p.mod(a), b = p, temp;
    //Продолжать пока число не будет делиться без остатка
    while (r.compareTo(BigInteger.ZERO) != 0) {
      //Вычисление по формуле p(i) = (p(i-2) - p(i-1) * q(i-2)) mod n (где i, i-1, i-2 порядковые номера p и q)
      temp = p1;
      p1 = p0.add(b.divide(a).multiply(p1).negate()).mod(p);
      //p1 = (p0 - p1 * (b / a)) % p;
      //Когда число получается отрицательным, то вычисляется его положительное значение в поле
      if (p1.compareTo(BigInteger.ZERO) < 0) {
        p1 = p.add(p1);
      }
      p0 = temp;
      //Вычисление a, b, r нового шага
      b = a;
      a = r;
      r = b.mod(a);
    }
    return p1;
  }

  /**
   * Нахождение {@code int} НОК (наименьшего общего кратного) от двух чисел с использованием НОД
   *
   * @param a первое число
   * @param b второе число
   * @return {@code int} НОК
   * @see #binaryGCD(int, int)
   * @see <a href="https://en.wikipedia.org/wiki/Least_common_multiple#Calculation">LCM formula</a>
   */
  public static int binaryLCM(int a, int b) {
    return a / binaryGCD(a, b) * b;
  }

  /**
   * Нахождение {@code BigInteger} НОК (наименьшего общего кратного) от двух чисел с использованием
   * НОД
   *
   * @param a первое число
   * @param b второе число
   * @return {@code BigInteger} НОК
   * @see #binaryGCD(BigInteger, BigInteger)
   * @see <a href="https://en.wikipedia.org/wiki/Least_common_multiple#Calculation">LCM formula</a>
   */
  public static BigInteger binaryLCM(BigInteger a, BigInteger b) {
    return a.divide(a.gcd(b)).multiply(b);
  }
}
