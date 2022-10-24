package com.rips7.cybersecurity.algorithms.encrypt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static com.rips7.cybersecurity.utils.PrimeUtils.randomPrime;

@Getter
@RequiredArgsConstructor
public class ElGamal {

  private final BigInteger p;

  private final BigInteger g;

  private final BigInteger x;

  private final BigInteger y;

  public ElGamal() {
    this(randomPrime());
  }

  public ElGamal(final BigInteger p) {
    this(p, p.divide(BigInteger.TWO));
  }

  public ElGamal(final BigInteger p, final BigInteger g) {
    this(p, g, randomPrime());
  }

  public ElGamal(final BigInteger p, final BigInteger g, final BigInteger x) {
    this(p, g, x, g.modPow(x, p));
  }

  public String encrypt(final String message) {
    final BigInteger m = new BigInteger(message.getBytes(StandardCharsets.UTF_8));
    final BigInteger k = randomPrime();
    final BigInteger a = g.modPow(k, p);
    final BigInteger b = y.modPow(k, p).multiply(m).mod(p);
    return a + "," + b;
  }

  public String decrypt(final String ab) {
    final String[] parts = ab.split(",");
    final BigInteger a = new BigInteger(parts[0]);
    final BigInteger b = new BigInteger(parts[1]);
    final BigInteger m = a.modPow(p.subtract(BigInteger.ONE).subtract(x), p).multiply(b).mod(p);
    return new String(m.toByteArray(), StandardCharsets.UTF_8);
  }
}
