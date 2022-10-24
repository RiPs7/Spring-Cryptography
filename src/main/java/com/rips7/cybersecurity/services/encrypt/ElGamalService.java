package com.rips7.cybersecurity.services.encrypt;

import com.rips7.cybersecurity.algorithms.encrypt.ElGamal;
import com.rips7.cybersecurity.models.encrypt.ElGamalDTO;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Optional;

import static com.rips7.cybersecurity.controllers.utils.Preconditions.checkAllNonNull;
import static com.rips7.cybersecurity.controllers.utils.Preconditions.checkAllNull;

@Service
public class ElGamalService {

  public Optional<ElGamalDTO> generate(
      final String p, final String g, final String x, final String y) {
    final ElGamal elgamal;
    if (checkAllNull(p, g, x, y)) {
      elgamal = new ElGamal();
    } else if (checkAllNonNull(p, g, x, y)) {
      elgamal =
          new ElGamal(new BigInteger(p), new BigInteger(g), new BigInteger(x), new BigInteger(y));
    } else if (checkAllNonNull(p, g)) {
      elgamal = new ElGamal(new BigInteger(p), new BigInteger(g));
    } else {
      return Optional.empty();
    }
    final ElGamalDTO elgamalDTO =
        ElGamalDTO.builder()
            .p(elgamal.getP().toString())
            .g(elgamal.getG().toString())
            .x(elgamal.getX().toString())
            .y(elgamal.getY().toString())
            .build();
    return Optional.of(elgamalDTO);
  }

  public Optional<ElGamalDTO> encrypt(
      final String p, final String g, final String x, final String y, final String message) {
    final ElGamal elgamal;
    if (checkAllNonNull(p, g, x, y, message)) {
      elgamal =
          new ElGamal(new BigInteger(p), new BigInteger(g), new BigInteger(x), new BigInteger(y));
    } else {
      return Optional.empty();
    }
    final ElGamalDTO elgamalDTO = ElGamalDTO.builder().cipher(elgamal.encrypt(message)).build();
    return Optional.of(elgamalDTO);
  }

  public Optional<ElGamalDTO> decrypt(
      final String p, final String g, final String x, final String y, final String cipher) {
    final ElGamal elgamal;
    if (checkAllNonNull(p, g, x, y, cipher)) {
      elgamal =
          new ElGamal(new BigInteger(p), new BigInteger(g), new BigInteger(x), new BigInteger(y));
    } else {
      return Optional.empty();
    }
    final ElGamalDTO elgamalDTO = ElGamalDTO.builder().plain(elgamal.decrypt(cipher)).build();
    return Optional.of(elgamalDTO);
  }
}
