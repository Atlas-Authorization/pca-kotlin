package net.atlasauth.pca.zk;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Zk;

/**
 * The Groth16 primitive for {@link Zk}: verification and proving of snarkjs artifacts on BN254 and BLS12-381, reached through JNA over
 * libpcazk (pca_zk.h, built on arkworks). No pairing or field arithmetic is implemented here.
 *
 * <p>The library is found through {@code -Dpca.zk.lib}, else the {@code ATLAS_PCA_LIBPCAZK} environment variable (a full path), else the
 * copy packaged in this jar, else the platform lookup of "pcazk". When it cannot be loaded every call fails with
 * {@link Zk.BackendMissing}; nothing falls back to "invalid". {@link #register()} installs this as the engine of {@link Zk}; the core
 * never depends on this module.
 */
public final class NativeZk {
  private NativeZk() {}

  public static final int CURVE_BN254 = 0, CURVE_BLS12_381 = 1;
  /** Verify only, and only with the snarkjs-compat flag: the library reads the curve from the key's own name, as snarkjs does. */
  public static final int CURVE_FROM_KEY = 2;
  /** Accept what snarkjs accepts (it ignores the key's protocol tag, its nPublic and extra IC entries). */
  public static final int FLAG_SNARKJS_COMPAT = 1;
  private static final int VALID = 1, INVALID = 0, SEED_BYTES = 32;

  /** The prototypes of pca_zk.h (size_t is a Java long on every 64-bit platform, int32_t and uint32_t an int). */
  interface PcaZk extends Library {
    String pca_zk_version();
    String pca_zk_reason_text(int reason);
    int pca_zk_verify(int curve, int flags, byte[] vkey, long vkeyLen, byte[] proof, long proofLen, byte[] signals, long signalsLen, IntByReference reason);
    int pca_zk_prove(int curve, byte[] wasm, long wasmLen, byte[] zkey, long zkeyLen, byte[] input, long inputLen, byte[] seed, long seedLen,
        PointerByReference out, LongByReference outLen);
    void pca_zk_free(Pointer ptr, long len);
  }

  private static volatile PcaZk lib;

  private static String libName() {
    String r = net.atlasauth.pca.NativeLibs.resolve(NativeZk.class, "pcazk", System.getProperty("pca.zk.lib"), System.getenv("ATLAS_PCA_LIBPCAZK"));
    return r != null ? r : "pcazk";
  }

  private static PcaZk lib() {
    PcaZk l = lib;
    if (l != null) return l;
    synchronized (NativeZk.class) {
      if (lib == null) {
        try {
          PcaZk loaded = Native.load(libName(), PcaZk.class);
          String v = loaded.pca_zk_version();
          if (v == null || v.isEmpty()) throw new IllegalStateException("libpcazk reports no version");
          lib = loaded;
        } catch (UnsatisfiedLinkError | RuntimeException e) {
          Zk.BackendMissing m = new Zk.BackendMissing("zk native library unavailable (set ATLAS_PCA_LIBPCAZK or -Dpca.zk.lib): " + e.getMessage());
          m.initCause(e);
          throw m;
        }
      }
      return lib;
    }
  }

  /** True when libpcazk can be loaded (tests skip, or fail when required, on false). */
  public static boolean available() {
    try {
      lib();
      return true;
    } catch (Zk.BackendMissing e) {
      return false;
    }
  }

  /** The version string of the loaded library. */
  public static String version() { return lib().pca_zk_version(); }

  private static void curve(int curve) { curve(curve, false); }

  private static void curve(int curve, boolean fromKeyAllowed) {
    if (curve == CURVE_FROM_KEY && fromKeyAllowed) return;
    if (curve != CURVE_BN254 && curve != CURVE_BLS12_381) throw new IllegalArgumentException("zk: unknown curve " + curve);
  }

  /**
   * The Groth16 pairing check over snarkjs JSON (UTF-8): {@code vkey} the verification key object, {@code proof} the proof object,
   * {@code signals} the array of decimal public signals. {@code snarkjsCompat} false is the strict mode (the key's protocol tag and
   * nPublic are checked, IC must have exactly one entry per signal plus one). True only for a valid proof; a malformed or invalid input
   * is false. A usage error or an internal failure of the library throws, it is never a verdict.
   */
  public static boolean verify(int curve, boolean snarkjsCompat, byte[] vkey, byte[] proof, byte[] signals) {
    curve(curve, snarkjsCompat);
    if (vkey == null || proof == null || signals == null) throw new IllegalArgumentException("zk: vkey, proof and signals are required");
    int rc = lib().pca_zk_verify(curve, snarkjsCompat ? FLAG_SNARKJS_COMPAT : 0, vkey, vkey.length, proof, proof.length, signals, signals.length, new IntByReference());
    if (rc == VALID) return true;
    if (rc == INVALID) return false;
    throw new IllegalStateException("zk: verify failed inside the library (" + rc + ")");
  }

  /** The refusal reason of a proof ({@code pairing_failed}, {@code not_in_subgroup}, ...), or null when it is valid. */
  public static String reason(int curve, boolean snarkjsCompat, byte[] vkey, byte[] proof, byte[] signals) {
    curve(curve, snarkjsCompat);
    if (vkey == null || proof == null || signals == null) throw new IllegalArgumentException("zk: vkey, proof and signals are required");
    PcaZk l = lib();
    IntByReference why = new IntByReference();
    int rc = l.pca_zk_verify(curve, snarkjsCompat ? FLAG_SNARKJS_COMPAT : 0, vkey, vkey.length, proof, proof.length, signals, signals.length, why);
    if (rc == VALID) return null;
    if (rc == INVALID) return l.pca_zk_reason_text(why.getValue());
    throw new IllegalStateException("zk: verify failed inside the library (" + rc + ")");
  }

  /**
   * Proves a circom circuit: {@code wasm} the witness calculator, {@code zkey} the proving key, {@code input} the circuit input (a JSON
   * object, UTF-8). Returns the JSON {@code {"proof": ..., "publicSignals": [...]}}. {@code seed} (exactly 32 bytes) makes the blinding
   * deterministic and is for tests only: pass null. Throws with the library's message when the witness, the key or the input is refused.
   */
  public static String prove(int curve, byte[] wasm, byte[] zkey, byte[] input, byte[] seed) {
    curve(curve);
    if (wasm == null || zkey == null || input == null) throw new IllegalArgumentException("zk: wasm, zkey and input are required");
    if (seed != null && seed.length != SEED_BYTES) throw new IllegalArgumentException("zk: a seed must be exactly " + SEED_BYTES + " bytes");
    PcaZk l = lib();
    PointerByReference out = new PointerByReference();
    LongByReference outLen = new LongByReference();
    int rc = l.pca_zk_prove(curve, wasm, wasm.length, zkey, zkey.length, input, input.length, seed, seed == null ? 0 : seed.length, out, outLen);
    Pointer p = out.getValue();
    String text = null;
    if (p != null) {
      try {
        text = new String(p.getByteArray(0, (int) outLen.getValue()), StandardCharsets.UTF_8);
      } finally {
        l.pca_zk_free(p, outLen.getValue()); // the buffer is the library's: copied above, released exactly once
      }
    }
    if (rc != 0 || text == null) throw new IllegalStateException("zk: prove refused (" + rc + ")" + (text == null ? "" : ": " + text));
    return text;
  }

  private static byte[] json(Object v) { return Json.canonicalize(v).getBytes(StandardCharsets.UTF_8); }

  private static int curveOf(Object name) { return "bn128".equals(name) ? CURVE_BN254 : "bls12381".equals(name) ? CURVE_BLS12_381 : -1; }

  /** The engine: the curve is the key's {@code curve} member, as snarkjs reads it; verification is in snarkjs-compatible mode. */
  public static final Zk.Groth16Engine ENGINE = new Zk.Groth16Engine() {
    @Override public boolean verify(Object vkey, List<?> publicSignals, Object proof) {
      lib(); // a missing library is never a verdict
      byte[] k, p, s;
      try {
        k = json(vkey);
        p = json(proof);
        s = json(publicSignals);
      } catch (RuntimeException e) {
        return false; // not JSON values: no key or proof
      }
      return NativeZk.verify(CURVE_FROM_KEY, true, k, p, s);
    }

    @SuppressWarnings("unchecked")
    @Override public Map<String, Object> fullProve(String curve, Map<String, Object> input, String wasmPath, String zkeyPath) {
      int c = curveOf(curve);
      if (c < 0) throw new IllegalArgumentException("zk: unknown curve '" + curve + "'");
      try {
        return (Map<String, Object>) Json.parseLenient(prove(c, Files.readAllBytes(Path.of(wasmPath)), Files.readAllBytes(Path.of(zkeyPath)), json(input), null));
      } catch (java.io.IOException e) {
        throw new java.io.UncheckedIOException(e);
      }
    }
  };

  /** Installs the native engine in {@link Zk}. Throws {@link Zk.BackendMissing} when libpcazk cannot be loaded. */
  public static Zk.Groth16Engine register() {
    lib();
    Zk.setGroth16Engine(ENGINE);
    return ENGINE;
  }
}
