package com.rips7.cybersecurity.controllers.encrypt;

import com.rips7.cybersecurity.models.encrypt.RsaDTO;
import com.rips7.cybersecurity.services.encrypt.RsaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${api.basePath}/rsa")
@SuppressWarnings("unused")
public class RsaController {

  @Autowired private RsaService rsaService;

  @GetMapping()
  public ResponseEntity<RsaDTO> generate(
      @RequestParam(required = false) final String p,
      @RequestParam(required = false) final String q) {
    return rsaService
        .generate(p, q)
        .map(rsa -> ResponseEntity.status(200).body(rsa))
        .orElse(ResponseEntity.status(400).build());
  }

  @PostMapping("/encrypt")
  public ResponseEntity<RsaDTO> encrypt(@RequestBody RsaDTO rsaDTO) {
    final String N = rsaDTO.getN();
    final String e = rsaDTO.getE();
    final String d = rsaDTO.getD();
    final String message = rsaDTO.getMessage();

    return rsaService
        .encrypt(N, e, d, message)
        .map(rsa -> ResponseEntity.status(200).body(rsa))
        .orElse(ResponseEntity.status(400).build());
  }

  @PostMapping("/decrypt")
  public ResponseEntity<RsaDTO> decrypt(@RequestBody RsaDTO rsaDTO) {
    final String N = rsaDTO.getN();
    final String e = rsaDTO.getE();
    final String d = rsaDTO.getD();
    final String cipher = rsaDTO.getCipher();

    return rsaService
        .decrypt(N, e, d, cipher)
        .map(rsa -> ResponseEntity.status(200).body(rsa))
        .orElse(ResponseEntity.status(400).build());
  }

  @PostMapping("sign")
  public ResponseEntity<RsaDTO> sign(@RequestBody RsaDTO rsaDTO) {
    final String N = rsaDTO.getN();
    final String e = rsaDTO.getE();
    final String d = rsaDTO.getD();
    final String message = rsaDTO.getMessage();

    return rsaService
        .sign(N, e, d, message)
        .map(rsa -> ResponseEntity.status(200).body(rsa))
        .orElse(ResponseEntity.status(400).build());
  }

  @PostMapping("verify")
  public ResponseEntity<RsaDTO> verify(@RequestBody RsaDTO rsaDTO) {
    final String N = rsaDTO.getN();
    final String e = rsaDTO.getE();
    final String d = rsaDTO.getD();
    final String message = rsaDTO.getMessage();
    final String signature = rsaDTO.getSignature();

    return rsaService
        .verify(N, e, d, message, signature)
        .map(rsa -> ResponseEntity.status(200).body(rsa))
        .orElse(ResponseEntity.status(400).build());
  }
}
