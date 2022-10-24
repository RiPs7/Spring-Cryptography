package com.rips7.cybersecurity.services.encrypt;

import com.rips7.cybersecurity.algorithms.encrypt.Rsa;
import com.rips7.cybersecurity.models.encrypt.RsaDTO;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Optional;

import static com.rips7.cybersecurity.controllers.utils.Preconditions.checkAllNonNull;
import static com.rips7.cybersecurity.controllers.utils.Preconditions.checkAllNull;

@Service
public class RsaService {

  public Optional<RsaDTO> generate(final String p, final String q) {
    final Rsa rsa;
    if (checkAllNull(p, q)) {
      rsa = new Rsa();
    } else if (checkAllNonNull(p, q)) {
      rsa = new Rsa(new BigInteger(p), new BigInteger(q));
    } else {
      return Optional.empty();
    }
    final RsaDTO rsaDTO =
        RsaDTO.builder()
            .n(rsa.getN().toString())
            .e(rsa.getE().toString())
            .d(rsa.getD().toString())
            .build();
    return Optional.of(rsaDTO);
  }

  public Optional<RsaDTO> encrypt(
      final String N, final String e, final String d, final String message) {
    final Rsa rsa;
    if (checkAllNonNull(N, e, d, message)) {
      rsa = new Rsa(new BigInteger(N), new BigInteger(e), new BigInteger(d));
    } else {
      return Optional.empty();
    }
    final RsaDTO rsaDTO = RsaDTO.builder().cipher(rsa.encrypt(message)).build();
    return Optional.of(rsaDTO);
  }

  public Optional<RsaDTO> decrypt(
      final String N, final String e, final String d, final String cipher) {
    final Rsa rsa;
    if (checkAllNonNull(N, d, e, cipher)) {
      rsa = new Rsa(new BigInteger(N), new BigInteger(e), new BigInteger(d));
    } else {
      return Optional.empty();
    }
    final RsaDTO rsaDTO = RsaDTO.builder().plain(rsa.decrypt(cipher)).build();
    return Optional.of(rsaDTO);
  }

  public Optional<RsaDTO> sign(
      final String N, final String e, final String d, final String message) {
    final Rsa rsa;
    if (checkAllNonNull(N, d, e, message)) {
      rsa = new Rsa(new BigInteger(N), new BigInteger(e), new BigInteger(d));
    } else {
      return Optional.empty();
    }
    final RsaDTO rsaDTO = RsaDTO.builder().signature(rsa.sign(message)).build();
    return Optional.of(rsaDTO);
  }

  public Optional<RsaDTO> verify(
      final String N,
      final String e,
      final String d,
      final String message,
      final String signature) {
    final Rsa rsa;
    if (checkAllNonNull(N, d, e, message, signature)) {
      rsa = new Rsa(new BigInteger(N), new BigInteger(e), new BigInteger(d));
    } else {
      return Optional.empty();
    }
    final RsaDTO rsaDTO = RsaDTO.builder().verified(rsa.verify(message, signature)).build();
    return Optional.of(rsaDTO);
  }
}
