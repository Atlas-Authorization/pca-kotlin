package net.atlasauth.pca.zk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.zip.GZIPInputStream;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Zk;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The real pairing check over libpcazk: every verifyPolicyVmProof case of the shared reference corpus (BN254 and BLS12-381: valid
 * proofs, tampered signals and points, wrong and malformed keys, points outside the subgroup, the snarkjs quirks) must give the
 * reference's verdict through {@link Zk#verifyPolicyVmProof}. Set ATLAS_PCA_LIBPCAZK (or -Dpca.zk.lib); ATLAS_PCA_LIBPCAZK_REQUIRED=1
 * makes a missing library a failure instead of a skip. The corpus is the core module's test-data/ref-zk.json.gz.
 */
class NativeZkTest {
  @BeforeAll
  static void lib() {
    boolean ok = NativeZk.available();
    if ("1".equals(System.getenv("ATLAS_PCA_LIBPCAZK_REQUIRED"))) assertTrue(ok, "libpcazk must load (ATLAS_PCA_LIBPCAZK)");
    assumeTrue(ok, "libpcazk not available");
    NativeZk.register();
  }

  @AfterAll
  static void reset() { Zk.resetGroth16Engine(); }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

  private static List<Map<String, Object>> cases() throws Exception { return cases("verifyPolicyVmProof"); }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> cases(String fn) throws Exception {
    Path file = Path.of("..", "..", "test-data", "ref-zk.json.gz");
    assertTrue(Files.exists(file), "the shared corpus is missing: " + file.toAbsolutePath());
    List<Map<String, Object>> out = new ArrayList<>();
    try (BufferedReader in = new BufferedReader(new InputStreamReader(new GZIPInputStream(Files.newInputStream(file)), StandardCharsets.UTF_8))) {
      for (String line; (line = in.readLine()) != null; ) {
        if (!line.startsWith("{\"fn\":\"" + fn + "\",")) continue;
        out.add((Map<String, Object>) Json.parseLenient(line.endsWith(",") ? line.substring(0, line.length() - 1) : line));
      }
    }
    return out;
  }

  /** The corpus spells a pin supplier as {"$expectThunk": X} ("throw": one that throws). */
  private static Map<String, Object> opts(Object raw) {
    if (m(raw) == null) return null;
    Map<String, Object> o = new LinkedHashMap<>(m(raw));
    Map<String, Object> e = m(o.get("expect"));
    if (e != null && e.containsKey("$expectThunk")) {
      Object x = e.get("$expectThunk");
      o.put("expect", "throw".equals(x) ? (Supplier<Object>) () -> { throw new IllegalStateException("thunk"); } : (Supplier<Object>) () -> x);
    }
    return o;
  }

  @Test void theVerifyCasesOfTheReferenceCorpus() throws Exception {
    List<Map<String, Object>> cs = cases();
    assertEquals(169, cs.size());
    List<String> bad = new ArrayList<>();
    int valid = 0;
    for (Map<String, Object> c : cs) {
      List<?> a = (List<?>) c.get("args");
      Object got;
      try {
        got = Zk.verifyPolicyVmProof(a.get(0), opts(a.size() > 1 ? a.get(1) : null));
      } catch (RuntimeException e) {
        got = "threw " + e;
      }
      if (!c.get("out").equals(got)) bad.add(c.get("name") + ": want " + c.get("out") + ", got " + got);
      if (Boolean.TRUE.equals(got)) valid++;
    }
    assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad));
    assertTrue(valid >= 10, "only " + valid + " cases verified");
  }

  @Test void strictModeRefusesWhatOnlySnarkjsAccepts() throws Exception {
    int quirks = 0;
    for (Map<String, Object> c : cases()) {
      String name = (String) c.get("name");
      if (!name.contains("/quirk-")) continue;
      List<?> a = (List<?>) c.get("args");
      Map<String, Object> env = m(a.get(0));
      byte[] vkey = Json.canonicalize(m(a.get(1)).get("verificationKey")).getBytes(StandardCharsets.UTF_8);
      byte[] proof = Json.canonicalize(env.get("proof")).getBytes(StandardCharsets.UTF_8);
      byte[] signals = Json.canonicalize(env.get("publicSignals")).getBytes(StandardCharsets.UTF_8);
      int curve = name.contains("/bn/") ? NativeZk.CURVE_BN254 : NativeZk.CURVE_BLS12_381;
      assertTrue(NativeZk.verify(curve, true, vkey, proof, signals), name + " (compatible mode)");
      assertNull(NativeZk.reason(curve, true, vkey, proof, signals), name);
      assertFalse(NativeZk.verify(curve, false, vkey, proof, signals), name + " (strict mode)");
      assertNotNull(NativeZk.reason(curve, false, vkey, proof, signals), name);
      quirks++;
    }
    assertEquals(6, quirks);
  }

  /**
   * The prover contract case of the corpus (provePolicyVmCompliance/roundtrip): proving the sample witness of the Policy-VM circuit gives
   * exactly the recorded public signals, and the proof verifies. It needs the circuit build, so it runs only with PCA_ZK_POLICYVM_WASM
   * (the witness calculator), PCA_ZK_POLICYVM_ZKEY (the proving key) and PCA_ZK_POLICYVM_VKEY (the verification key of THAT setup; a fresh
   * single-party setup has its own key, not the committed one); PCA_ZK_PROVE_REQUIRED=1 makes missing paths a failure instead of a skip.
   */
  @Test void provePolicyVmRoundtrip() throws Exception {
    String wasm = System.getenv("PCA_ZK_POLICYVM_WASM"), zkey = System.getenv("PCA_ZK_POLICYVM_ZKEY"), vkeyPath = System.getenv("PCA_ZK_POLICYVM_VKEY");
    boolean have = wasm != null && zkey != null && vkeyPath != null;
    if ("1".equals(System.getenv("PCA_ZK_PROVE_REQUIRED"))) assertTrue(have, "PCA_ZK_POLICYVM_WASM, PCA_ZK_POLICYVM_ZKEY and PCA_ZK_POLICYVM_VKEY must be set");
    assumeTrue(have, "the Policy-VM circuit build is not available");
    List<Map<String, Object>> cs = cases("provePolicyVmCompliance");
    assertEquals(1, cs.size());
    Map<String, Object> c = cs.get(0);
    assertEquals("provePolicyVmCompliance/roundtrip", c.get("name"));
    Map<String, Object> want = m(c.get("out"));
    Map<String, Object> opts = new LinkedHashMap<>();
    opts.put("wasmPath", wasm);
    opts.put("zkeyPath", zkey);
    Map<String, Object> env = Zk.provePolicyVmCompliance(m(((List<?>) c.get("args")).get(0)), opts);
    assertEquals("groth16-bn254", env.get("system"));
    assertEquals(want.get("sampleProofCircuit"), env.get("circuit"));
    List<String> signals = new ArrayList<>();
    for (Object x : (List<?>) env.get("publicSignals")) signals.add(String.valueOf(x));
    List<String> expected = new ArrayList<>();
    for (Object x : (List<?>) want.get("publicSignals")) expected.add(String.valueOf(x));
    assertEquals(expected, signals);
    byte[] vkey = Files.readAllBytes(Path.of(vkeyPath));
    byte[] proof = Json.canonicalize(env.get("proof")).getBytes(StandardCharsets.UTF_8);
    assertTrue(NativeZk.verify(NativeZk.CURVE_BN254, true, vkey, proof, Json.canonicalize(env.get("publicSignals")).getBytes(StandardCharsets.UTF_8)), "the proof verifies under the key of its own setup");
    List<Object> bad = new ArrayList<>(signals);
    bad.set(0, "1");
    assertFalse(NativeZk.verify(NativeZk.CURVE_BN254, true, vkey, proof, Json.canonicalize(bad).getBytes(StandardCharsets.UTF_8)), "a tampered public signal is refused");
  }

  @Test void usageErrorsAreNotVerdicts() {
    byte[] j = "{}".getBytes(StandardCharsets.UTF_8);
    assertThrows(IllegalArgumentException.class, () -> NativeZk.verify(7, true, j, j, j));
    assertThrows(IllegalArgumentException.class, () -> NativeZk.verify(NativeZk.CURVE_BN254, true, null, j, j));
    assertThrows(IllegalArgumentException.class, () -> NativeZk.prove(NativeZk.CURVE_BN254, j, j, j, new byte[31]));
    assertFalse(NativeZk.verify(NativeZk.CURVE_BN254, true, j, j, "[]".getBytes(StandardCharsets.UTF_8)));
    assertFalse(NativeZk.version().isEmpty());
  }
}
