package net.atlasauth.pca.mpc.lwe;

import com.sun.jna.Library;
import com.sun.jna.Native;

/**
 * The endemic OT's lattice core: Kyber-768 K-PKE keygen, CPA encrypt and decrypt, ring add and subtract, and the hash to a uniform ring vector.
 * Every operation is the audited pqc_kyber reference reached through the C library (pca_lwe_ot.h) over JNA; nothing lattice-related is
 * implemented here. Point {@code -Dpca.lweot.lib} at liblweot. A wrong size is refused before the call and again by the library.
 */
public final class Lattice {
  private Lattice() {}

  public static final int PK_BYTES = 1184, SK_BYTES = 1152, CT_BYTES = 1088, TVEC_BYTES = 1152, SYM_BYTES = 32, HASHIN_CAP = 4096;

  /** The prototypes of pca_lwe_ot.h (size_t is a Java long on every 64-bit platform, int32_t an int). */
  interface Lweot extends Library {
    long lweot_len_pk();
    long lweot_len_sk();
    long lweot_len_ct();
    long lweot_len_tvec();
    long lweot_len_sym();
    long lweot_hashin_cap();
    int lweot_kpke_keygen(byte[] seed, long seedLen, byte[] pk, long pkLen, byte[] sk, long skLen);
    int lweot_kpke_keygen_fips203(byte[] seed, long seedLen, byte[] pk, long pkLen, byte[] sk, long skLen);
    int lweot_kpke_enc(byte[] pk, long pkLen, byte[] msg, long msgLen, byte[] coins, long coinsLen, byte[] ct, long ctLen);
    int lweot_kpke_dec(byte[] sk, long skLen, byte[] ct, long ctLen, byte[] msg, long msgLen);
    int lweot_ring_add(byte[] a, long aLen, byte[] b, long bLen, byte[] out, long outLen);
    int lweot_ring_sub(byte[] a, long aLen, byte[] b, long bLen, byte[] out, long outLen);
    int lweot_hash_to_ring(byte[] in, long inLen, byte[] out, long outLen);
  }

  private static volatile Lweot lib;

  private static Lweot lib() {
    Lweot l = lib;
    if (l == null) {
      synchronized (Lattice.class) {
        if (lib == null) {
          Lweot loaded = Native.load(
              java.util.Optional.ofNullable(net.atlasauth.pca.NativeLibs.resolve(Lattice.class, "lweot", System.getProperty("pca.lweot.lib"))).orElse("lweot"),
              Lweot.class);
          // the sizes this class hard-codes must be the ones the library was built with, or nothing is safe
          if (loaded.lweot_len_pk() != PK_BYTES || loaded.lweot_len_sk() != SK_BYTES || loaded.lweot_len_ct() != CT_BYTES
              || loaded.lweot_len_tvec() != TVEC_BYTES || loaded.lweot_len_sym() != SYM_BYTES || loaded.lweot_hashin_cap() != HASHIN_CAP) {
            throw new IllegalStateException("liblweot reports different Kyber-768 sizes");
          }
          lib = loaded;
        }
        l = lib;
      }
    }
    return l;
  }

  /** True when liblweot can be loaded (tests skip, or fail when required, on false). */
  public static boolean available() {
    try {
      lib();
      return true;
    } catch (UnsatisfiedLinkError | RuntimeException e) {
      return false;
    }
  }

  private static byte[] need(byte[] b, int len, String what) {
    if (b == null || b.length != len) throw new IllegalArgumentException("lattice: " + what + " must be exactly " + len + " bytes");
    return b;
  }

  private static void ok(int rc, String op) {
    if (rc != 0) throw new IllegalStateException("lattice: " + op + " refused (" + rc + ")");
  }

  /** A Kyber-768 K-PKE key pair derived deterministically from a 32-byte seed. */
  public record KeyPair(byte[] publicKey, byte[] secretKey) {}

  /** The key pair exactly as FIPS 203 Algorithm 13 derives it (the derivation the endemic receiver uses). */
  public static KeyPair keygenFips203(byte[] seed) {
    need(seed, SYM_BYTES, "seed");
    byte[] pk = new byte[PK_BYTES], sk = new byte[SK_BYTES];
    ok(lib().lweot_kpke_keygen_fips203(seed, SYM_BYTES, pk, PK_BYTES, sk, SK_BYTES), "keygen (FIPS 203)");
    return new KeyPair(pk, sk);
  }

  public static KeyPair keygen(byte[] seed) {
    need(seed, SYM_BYTES, "seed");
    byte[] pk = new byte[PK_BYTES], sk = new byte[SK_BYTES];
    ok(lib().lweot_kpke_keygen(seed, SYM_BYTES, pk, PK_BYTES, sk, SK_BYTES), "keygen");
    return new KeyPair(pk, sk);
  }

  public static byte[] enc(byte[] publicKey, byte[] message, byte[] coins) {
    need(publicKey, PK_BYTES, "public key");
    need(message, SYM_BYTES, "message");
    need(coins, SYM_BYTES, "coins");
    byte[] ct = new byte[CT_BYTES];
    ok(lib().lweot_kpke_enc(publicKey, PK_BYTES, message, SYM_BYTES, coins, SYM_BYTES, ct, CT_BYTES), "enc");
    return ct;
  }

  public static byte[] dec(byte[] secretKey, byte[] ciphertext) {
    need(secretKey, SK_BYTES, "secret key");
    need(ciphertext, CT_BYTES, "ciphertext");
    byte[] msg = new byte[SYM_BYTES];
    ok(lib().lweot_kpke_dec(secretKey, SK_BYTES, ciphertext, CT_BYTES, msg, SYM_BYTES), "dec");
    return msg;
  }

  public static byte[] ringAdd(byte[] a, byte[] b) {
    need(a, TVEC_BYTES, "a");
    need(b, TVEC_BYTES, "b");
    byte[] out = new byte[TVEC_BYTES];
    ok(lib().lweot_ring_add(a, TVEC_BYTES, b, TVEC_BYTES, out, TVEC_BYTES), "ring add");
    return out;
  }

  public static byte[] ringSub(byte[] a, byte[] b) {
    need(a, TVEC_BYTES, "a");
    need(b, TVEC_BYTES, "b");
    byte[] out = new byte[TVEC_BYTES];
    ok(lib().lweot_ring_sub(a, TVEC_BYTES, b, TVEC_BYTES, out, TVEC_BYTES), "ring sub");
    return out;
  }

  /** SHAKE128 then the FIPS 203 SampleNTT sampler: a uniform ring vector. At most 4096 input bytes. */
  public static byte[] hashToRing(byte[] input) {
    if (input == null || input.length > HASHIN_CAP) throw new IllegalArgumentException("lattice: hash input must be at most " + HASHIN_CAP + " bytes");
    byte[] out = new byte[TVEC_BYTES];
    ok(lib().lweot_hash_to_ring(input, input.length, out, TVEC_BYTES), "hash to ring");
    return out;
  }
}
