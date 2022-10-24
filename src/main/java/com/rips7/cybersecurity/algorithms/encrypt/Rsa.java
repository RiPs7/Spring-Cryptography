package com.rips7.cybersecurity.algorithms.encrypt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.rips7.cybersecurity.utils.PrimeUtils.randomPrime;

@Getter
@RequiredArgsConstructor
public class Rsa {

  private final BigInteger N;

  private final BigInteger e;

  private final BigInteger d;

  public Rsa() {
    this(randomPrime(), randomPrime());
  }

  public Rsa(final BigInteger p, final BigInteger q) {
    this(
        p.multiply(q),
        new BigInteger("65537"),
        new BigInteger("65537")
            .modInverse(p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))));
  }

  public String encrypt(final String message) {
    final BigInteger m = new BigInteger(message.getBytes(StandardCharsets.UTF_8));
    final BigInteger cipher = m.modPow(e, N);
    return new String(Base64.getEncoder().encode(cipher.toByteArray()), StandardCharsets.UTF_8);
  }

  public String decrypt(final String messageB64) {
    final BigInteger m =
        new BigInteger(Base64.getDecoder().decode(messageB64.getBytes(StandardCharsets.UTF_8)));
    final BigInteger plain = m.modPow(d, N);
    return new String(plain.toByteArray(), StandardCharsets.UTF_8);
  }

  public String sign(final String message) {
    final BigInteger m = new BigInteger(message.getBytes(StandardCharsets.UTF_8));
    final BigInteger signed = m.modPow(d, N);
    return new String(Base64.getEncoder().encode(signed.toByteArray()), StandardCharsets.UTF_8);
  }

  public boolean verify(final String message, final String signatureB64) {
    final BigInteger s =
        new BigInteger(Base64.getDecoder().decode(signatureB64.getBytes(StandardCharsets.UTF_8)));
    final BigInteger check = s.modPow(e, N);
    return new String(check.toByteArray(), StandardCharsets.UTF_8).equals(message);
  }
}
