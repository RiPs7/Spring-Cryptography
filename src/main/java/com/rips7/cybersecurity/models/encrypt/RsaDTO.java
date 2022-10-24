package com.rips7.cybersecurity.models.encrypt;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RsaDTO {

  private final String n;

  private final String e;

  private final String d;

  private final String message;

  private final String cipher;

  private final String plain;

  private final String signature;

  private final Boolean verified;
}
