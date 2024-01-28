package com.eatthepath.hkdf;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

@State(Scope.Benchmark)
public class MacGetInstanceBenchmark {

  private Mac mac;
  private Provider provider;
  private String providerName;

  private static final String ALGORITHM = "HmacSHA256";

  @Setup
  public void setUp() throws NoSuchAlgorithmException {
    mac = Mac.getInstance(ALGORITHM);
    provider = mac.getProvider();
    providerName = provider.getName();
  }

  @Benchmark
  public Mac getInstanceByName() throws NoSuchAlgorithmException {
    return Mac.getInstance(ALGORITHM);
  }

  @Benchmark
  public Mac getInstanceByNameWithNamedProvider() throws NoSuchAlgorithmException, NoSuchProviderException {
    return Mac.getInstance(ALGORITHM, providerName);
  }

  @Benchmark
  public Mac getInstanceByNameWithGivenProvider() throws NoSuchAlgorithmException {
    return Mac.getInstance(ALGORITHM, provider);
  }

  @Benchmark
  public Mac cloneInstance() throws CloneNotSupportedException {
    return (Mac) mac.clone();
  }
}
