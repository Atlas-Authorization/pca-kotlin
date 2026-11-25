package net.atlasauth.pca.fndsa;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pq;
import net.atlasauth.pca.fndsa.FnDsa.FalconKeyPair;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The real FN-DSA primitive over libfndsa: the keyless known-answer file (keygen and sign byte for byte, verify of every vector), refusals, and the
 * PCA leaf framing and Ed25519 hybrid through the backend seam. Set ATLAS_PCA_LIBFNDSA (or -Dpca.fndsa.lib); ATLAS_PCA_LIBFNDSA_REQUIRED=1 makes a
 * missing library a failure instead of a skip. The 480-case corpus replay (FndsaDiffTest in the core tests) runs on the mock backend and is untouched.
 */
class NativeFnDsaTest {
  private static final HexFormat HEX = HexFormat.of();

  @BeforeAll
  static void lib() {
    boolean ok = NativeFnDsa.available();
    if ("1".equals(System.getenv("ATLAS_PCA_LIBFNDSA_REQUIRED"))) assertTrue(ok, "libfndsa must load (ATLAS_PCA_LIBFNDSA)");
    assumeTrue(ok, "libfndsa not available");
    NativeFnDsa.register();
  }

  @AfterAll
  static void reset() { FnDsa.resetFalconBackend(); }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> kat() throws Exception {
    return (Map<String, Object>) Json.parseLenient(Files.readString(Path.of("test-data/ref-fndsa-kat.json")));
  }

  private static byte[] h(Object o) { return HEX.parseHex((String) o); }

  /** The KAT carries seed labels, not seed bytes: the 32-byte seed is SHAKE256(UTF-8 label) cut to 32 bytes. */
  private static byte[] labelSeed(Object label) {
    org.bouncycastle.crypto.digests.SHAKEDigest d = new org.bouncycastle.crypto.digests.SHAKEDigest(256);
    byte[] in = ((String) label).getBytes(java.nio.charset.StandardCharsets.UTF_8), out = new byte[32];
    d.update(in, 0, in.length);
    d.doFinal(out, 0, 32);
    return out;
  }

  @SuppressWarnings("unchecked")
  @Test void knownAnswers() throws Exception {
    Map<String, Object> k = kat();
    List<Object> wasm = (List<Object>) k.get("wasm_signed"), c = (List<Object>) k.get("c_signed");
    assertFalse(wasm.isEmpty());
    assertFalse(c.isEmpty());
    for (Object o : wasm) {
      Map<String, Object> v = (Map<String, Object>) o;
      String variant = (String) v.get("variant");
      byte[] vk = h(v.get("vk")), msg = h(v.get("msg")), sig = h(v.get("sig"));
      FalconKeyPair kp = NativeFnDsa.keygen(variant, labelSeed(v.get("keygen_seed_label")));
      assertArrayEquals(vk, kp.pk, "keygen " + variant);
      assertArrayEquals(sig, NativeFnDsa.sign(variant, kp.sk, msg, labelSeed(v.get("sign_seed_label"))), "sign " + variant);
      assertTrue(NativeFnDsa.verify(variant, vk, msg, sig), "verify " + variant);
    }
    for (Object o : c) {
      Map<String, Object> v = (Map<String, Object>) o;
      assertTrue(NativeFnDsa.verify((String) v.get("variant"), h(v.get("vk")), h(v.get("msg")), h(v.get("sig"))), "c-signed verify");
    }
  }

  @SuppressWarnings("unchecked")
  @Test void tamperAndRefusals() throws Exception {
    Map<String, Object> v = (Map<String, Object>) ((List<Object>) kat().get("wasm_signed")).get(0);
    String variant = (String) v.get("variant");
    byte[] vk = h(v.get("vk")), msg = h(v.get("msg")), sig = h(v.get("sig"));
    byte[] bs = sig.clone(), bm = Arrays.copyOf(msg.length == 0 ? new byte[1] : msg, Math.max(1, msg.length)), bk = vk.clone();
    bs[bs.length / 2] ^= 1;
    bm[0] ^= 1;
    bk[bk.length / 2] ^= 1;
    assertFalse(NativeFnDsa.verify(variant, vk, msg, bs));
    assertFalse(NativeFnDsa.verify(variant, vk, bm, sig));
    assertFalse(NativeFnDsa.verify(variant, bk, msg, sig));
    assertFalse(NativeFnDsa.verify(variant, Arrays.copyOf(vk, vk.length - 1), msg, sig));
    assertFalse(NativeFnDsa.verify(variant, vk, msg, Arrays.copyOf(sig, sig.length - 1)));
    assertFalse(NativeFnDsa.verify(variant, null, msg, sig));
    assertFalse(NativeFnDsa.verify(variant, vk, null, sig));
    assertFalse(NativeFnDsa.verify(variant, vk, msg, null));
    assertFalse(NativeFnDsa.verify(variant, vk, new byte[8193], sig));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.verify("fn-dsa-768", vk, msg, sig));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.keygen("fn-dsa-768"));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.keygen(variant, new byte[31]));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.keygen(variant, null));
    FalconKeyPair kp = NativeFnDsa.keygen(variant);
    byte[] seed = new byte[32];
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.sign(variant, kp.sk, new byte[8193], seed));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.sign(variant, kp.sk, null, seed));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.sign(variant, null, msg, seed));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.sign(variant, kp.sk, msg, new byte[5]));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.sign("fn-dsa-768", kp.sk, msg, seed));
  }

  @Test void emptyMessageAndRandomRoundTrip() {
    for (String variant : new String[] {"fn-dsa-512", "fn-dsa-1024"}) {
      FalconKeyPair kp = NativeFnDsa.keygen(variant);
      byte[] empty = new byte[0], full = new byte[8192];
      byte[] s1 = NativeFnDsa.sign(variant, kp.sk, empty), s2 = NativeFnDsa.sign(variant, kp.sk, empty);
      assertTrue(NativeFnDsa.verify(variant, kp.pk, empty, s1), variant);
      assertTrue(NativeFnDsa.verify(variant, kp.pk, empty, s2), variant);
      assertFalse(Arrays.equals(s1, s2), "fresh randomness per signature");
      assertTrue(NativeFnDsa.verify(variant, kp.pk, full, NativeFnDsa.sign(variant, kp.sk, full)), variant);
      assertFalse(NativeFnDsa.verify(variant, kp.pk, new byte[] {1}, s1));
    }
  }

  @Test void framingThroughTheSeam() {
    assertSame(NativeFnDsa.BACKEND, FnDsa.getFalconBackend());
    byte[] edSecret = new byte[32];
    Arrays.fill(edSecret, (byte) 7);
    String holder = Keys.edFromSeed(edSecret).id();
    for (String alg : new String[] {"fn-dsa-512", "fn-dsa-1024", "hybrid-ed25519-fn-dsa-512", "hybrid-ed25519-fn-dsa-1024"}) {
      FnDsa.Suite suite = FnDsa.resolveFnDsaAlg(alg);
      FalconKeyPair kp = NativeFnDsa.keygen(suite.variant);
      Map<String, Object> leaf = new LinkedHashMap<>();
      leaf.put("iss", "issuer");
      leaf.put("aud", "audience");
      leaf.put("n", "1");
      Map<String, Object> w = FnDsa.signPcaWithFndsa(alg, leaf, kp.pk, kp.sk, suite.hasEd25519 ? edSecret : null);
      assertEquals(alg, w.get("alg"));
      assertTrue(FnDsa.verifyPcaFndsa(alg, leaf, holder, w.get("pq_pk"), w.get("sig"), w.get("pq_sig")), alg);
      Map<String, Object> other = new LinkedHashMap<>(leaf);
      other.put("n", "2");
      assertFalse(FnDsa.verifyPcaFndsa(alg, other, holder, w.get("pq_pk"), w.get("sig"), w.get("pq_sig")), alg + " tampered leaf");
    }
  }

  /** The KAT signatures verify through the core suite dispatch (raw FN-DSA, pure PQ); tamper / wrong-length pq_pk are denied; sign then core-verify round trips. */
  @SuppressWarnings("unchecked")
  @Test void coreSuiteDispatch() throws Exception {
    assertTrue(Pq.supportedSuites().contains("fn-dsa-512") && Pq.supportedSuites().contains("fn-dsa-1024"));
    for (Object o : (List<Object>) kat().get("c_signed")) {
      Map<String, Object> v = (Map<String, Object>) o;
      String alg = (String) v.get("variant");
      byte[] vk = h(v.get("vk")), msg = h(v.get("msg")), sig = h(v.get("sig"));
      String pk = Keys.b64u(vk);
      assertTrue(Pq.verifyArtifactSignature(alg, null, pk, msg, Keys.b64u(sig), null), alg);
      byte[] bs = sig.clone(), bm = msg.length == 0 ? new byte[1] : msg.clone(), bk = vk.clone();
      bs[bs.length / 2] ^= 1; bm[0] ^= 1; bk[bk.length / 2] ^= 1;
      assertFalse(Pq.verifyArtifactSignature(alg, null, pk, msg, Keys.b64u(bs), null));
      assertFalse(Pq.verifyArtifactSignature(alg, null, pk, bm, Keys.b64u(sig), null));
      assertFalse(Pq.verifyArtifactSignature(alg, null, Keys.b64u(bk), msg, Keys.b64u(sig), null));
      assertFalse(Pq.verifyArtifactSignature(alg, null, Keys.b64u(Arrays.copyOf(vk, vk.length - 1)), msg, Keys.b64u(sig), null));
      assertFalse(Pq.verifyArtifactSignature(alg, null, pk, msg, Keys.b64u(Arrays.copyOf(sig, sig.length - 1)), null));
    }
    for (String alg : new String[] {"fn-dsa-512", "fn-dsa-1024"}) {
      FalconKeyPair kp = NativeFnDsa.keygen(alg);
      byte[] msg = {1, 2, 3};
      byte[] sig = NativeFnDsa.sign(alg, kp.sk, msg);
      assertTrue(Pq.verifyArtifactSignature(alg, null, Keys.b64u(kp.pk), msg, Keys.b64u(sig), null), alg);
      assertFalse(Pq.verifyArtifactSignature(alg, null, Keys.b64u(kp.pk), new byte[] {9}, Keys.b64u(sig), null), alg);
    }
  }

  private static byte[] seedOf(int k) { byte[] b = new byte[32]; for (int i = 0; i < 32; i++) b[i] = (byte) (i * 5 + k); return b; }

  @Test void constantsAndDeterministicKeygenAndSigning() {
    assertEquals(32, NativeFnDsa.SEED_BYTES);
    assertEquals(8192, NativeFnDsa.MSG_CAP);
    for (String variant : new String[] {"fn-dsa-512", "fn-dsa-1024"}) {
      FalconKeyPair a = NativeFnDsa.keygen(variant, seedOf(1)), b = NativeFnDsa.keygen(variant, seedOf(1)), c = NativeFnDsa.keygen(variant, seedOf(2));
      assertArrayEquals(a.pk, b.pk);
      assertArrayEquals(a.sk, b.sk);
      assertFalse(Arrays.equals(a.pk, c.pk));
      assertEquals(a.sk.length, NativeFnDsa.skBytes(variant));
      byte[] msg = {4, 5, 6};
      byte[] s1 = NativeFnDsa.sign(variant, a.sk, msg, seedOf(3)), s2 = NativeFnDsa.sign(variant, a.sk, msg, seedOf(3)), s3 = NativeFnDsa.sign(variant, a.sk, msg, seedOf(4));
      assertArrayEquals(s1, s2);
      assertFalse(Arrays.equals(s1, s3));
      assertTrue(NativeFnDsa.verify(variant, a.pk, msg, s1));
      assertTrue(NativeFnDsa.verify(variant, a.pk, msg, s3));
      assertFalse(NativeFnDsa.verify(variant, c.pk, msg, s1), "a different key");
    }
    assertEquals(FnDsa.FN_DSA_512_PUBLIC_KEY_BYTES, NativeFnDsa.keygen("fn-dsa-512", seedOf(1)).pk.length);
    assertEquals(FnDsa.FN_DSA_1024_PUBLIC_KEY_BYTES, NativeFnDsa.keygen("fn-dsa-1024", seedOf(1)).pk.length);
    assertNotEquals(NativeFnDsa.skBytes("fn-dsa-512"), NativeFnDsa.skBytes("fn-dsa-1024"));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.skBytes("fn-dsa-768"));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.skBytes(null));
  }

  @Test void keysAndSignaturesOfTheOtherVariantAreRefused() {
    FalconKeyPair k512 = NativeFnDsa.keygen("fn-dsa-512", seedOf(1)), k1024 = NativeFnDsa.keygen("fn-dsa-1024", seedOf(1));
    byte[] msg = {1}, seed = seedOf(9);
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.sign("fn-dsa-1024", k512.sk, msg, seed));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.sign("fn-dsa-512", k1024.sk, msg, seed));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.sign("fn-dsa-512", new byte[5], msg, seed));
    assertThrows(IllegalArgumentException.class, () -> NativeFnDsa.sign("fn-dsa-512", k512.sk, msg, new byte[33]));
    byte[] s512 = NativeFnDsa.sign("fn-dsa-512", k512.sk, msg, seed);
    assertFalse(NativeFnDsa.verify("fn-dsa-1024", k512.pk, msg, s512));
    assertFalse(NativeFnDsa.verify("fn-dsa-1024", k1024.pk, msg, s512));
    assertFalse(NativeFnDsa.verify("fn-dsa-512", k1024.pk, msg, s512));
    assertFalse(NativeFnDsa.verify("fn-dsa-512", k512.pk, new byte[8193], s512));
    assertTrue(NativeFnDsa.verify("fn-dsa-512", k512.pk, msg, s512));
    byte[] edge = new byte[8192];
    assertTrue(NativeFnDsa.verify("fn-dsa-512", k512.pk, edge, NativeFnDsa.sign("fn-dsa-512", k512.sk, edge, seed)));
  }

  @Test void theSeamBackendInfersTheVariantFromTheKeyLength() {
    FnDsa.FalconBackend be = NativeFnDsa.BACKEND;
    assertTrue(be.canSign());
    FalconKeyPair k512 = be.keygen("fn-dsa-512", seedOf(1)), k1024 = be.keygen("fn-dsa-1024", seedOf(1));
    assertArrayEquals(NativeFnDsa.keygen("fn-dsa-512", seedOf(1)).pk, k512.pk);
    assertArrayEquals(NativeFnDsa.keygen("fn-dsa-1024", seedOf(1)).sk, k1024.sk);
    assertEquals(FnDsa.FN_DSA_512_PUBLIC_KEY_BYTES, be.keygen().pk.length, "the argument-free seam keygen is FN-DSA-512");
    byte[] msg = {7, 8, 9}, seed = seedOf(5);
    for (FalconKeyPair kp : new FalconKeyPair[] {k512, k1024}) {
      byte[] sig = be.sign(kp.sk, msg);
      assertTrue(be.verify(kp.pk, msg, sig));
      assertFalse(be.verify(kp.pk, new byte[] {7}, sig));
      byte[] d1 = be.sign(kp.sk, msg, seed), d2 = be.sign(kp.sk, msg, seed);
      assertArrayEquals(d1, d2);
      assertTrue(be.verify(kp.pk, msg, d1));
    }
    assertArrayEquals(NativeFnDsa.sign("fn-dsa-512", k512.sk, msg, seed), be.sign(k512.sk, msg, seed));
    assertArrayEquals(NativeFnDsa.sign("fn-dsa-1024", k1024.sk, msg, seed), be.sign(k1024.sk, msg, seed));
    assertFalse(be.verify(null, msg, new byte[10]));
    assertFalse(be.verify(new byte[5], msg, new byte[10]));
    assertFalse(be.verify(new byte[FnDsa.FN_DSA_512_PUBLIC_KEY_BYTES + 1], msg, new byte[10]));
    assertFalse(be.verify(new byte[FnDsa.FN_DSA_1024_PUBLIC_KEY_BYTES - 1], msg, new byte[10]));
    assertThrows(IllegalArgumentException.class, () -> be.sign(null, msg));
    assertThrows(IllegalArgumentException.class, () -> be.sign(new byte[5], msg));
    assertThrows(IllegalArgumentException.class, () -> be.sign(null, msg, seed));
    assertThrows(IllegalArgumentException.class, () -> be.sign(new byte[5], msg, seed));
  }

  private static void assertSame(Object a, Object b) { org.junit.jupiter.api.Assertions.assertSame(a, b); }
}
