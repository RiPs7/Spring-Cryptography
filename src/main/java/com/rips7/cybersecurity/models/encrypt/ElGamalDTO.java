package com.rips7.cybersecurity.models.encrypt;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ElGamalDTO {

  private final String p;

  private final String g;

  private final String x;

  private final String y;

  private final String a;

  private final String b;

  private final String message;

  private final String cipher;

  private final String plain;

  private final String signature;

  private final Boolean verified;
}
