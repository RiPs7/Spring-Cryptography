package com.rips7.cybersecurity.controllers.utils;

import java.util.Arrays;
import java.util.Objects;

public class Preconditions {

  public static boolean checkAllNull(Object... elements) {
    return Arrays.stream(elements).allMatch(Objects::isNull);
  }

  public static boolean checkAllNonNull(Object... elements) {
    return Arrays.stream(elements).allMatch(Objects::nonNull);
  }
}
