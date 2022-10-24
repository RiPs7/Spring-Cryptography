package com.rips7.cybersecurity.controllers.encrypt;

import com.rips7.cybersecurity.models.encrypt.ElGamalDTO;
import com.rips7.cybersecurity.services.encrypt.ElGamalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${api.basePath}/elgamal")
@SuppressWarnings("unused")
public class ElGamalController {

  @Autowired private ElGamalService elgamalService;

  @GetMapping()
  public ResponseEntity<ElGamalDTO> generate(
      @RequestParam(required = false) final String p,
      @RequestParam(required = false) final String g,
      @RequestParam(required = false) final String x,
      @RequestParam(required = false) final String y) {
    return elgamalService
        .generate(p, g, x, y)
        .map(elgamal -> ResponseEntity.status(200).body(elgamal))
        .orElse(ResponseEntity.status(400).build());
  }

  @PostMapping("/encrypt")
  public ResponseEntity<ElGamalDTO> encrypt(@RequestBody ElGamalDTO elgamalDTO) {
    final String p = elgamalDTO.getP();
    final String g = elgamalDTO.getG();
    final String x = elgamalDTO.getX();
    final String y = elgamalDTO.getY();
    final String message = elgamalDTO.getMessage();

    return elgamalService
        .encrypt(p, g, x, y, message)
        .map(elgamal -> ResponseEntity.status(200).body(elgamal))
        .orElse(ResponseEntity.status(400).build());
  }

  @PostMapping("/decrypt")
  public ResponseEntity<ElGamalDTO> decrypt(@RequestBody ElGamalDTO elgamalDTO) {
    final String p = elgamalDTO.getP();
    final String g = elgamalDTO.getG();
    final String x = elgamalDTO.getX();
    final String y = elgamalDTO.getY();
    final String cipher = elgamalDTO.getCipher();

    return elgamalService
        .decrypt(p, g, x, y, cipher)
        .map(elgamal -> ResponseEntity.status(200).body(elgamal))
        .orElse(ResponseEntity.status(400).build());
  }
}
