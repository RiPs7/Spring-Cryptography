package com.rips7.cybersecurity.utils;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PrimeUtils {

  public static BigInteger randomPrime() {
    return BigInteger.probablePrime(510, new SecureRandom());
  }
}
