package net.atlasauth.pca.fndsa;

import com.sun.jna.Library;
import com.sun.jna.Native;
import java.security.SecureRandom;
import net.atlasauth.pca.fndsa.FnDsa.FalconBackend;
import net.atlasauth.pca.fndsa.FnDsa.FalconKeyPair;

/**
 * The real FN-DSA primitive for {@link FnDsa}: Thomas Pornin's fn-dsa 0.4.0 (a draft best guess at FIPS 206, pinned in lockstep with the
 * TypeScript reference) reached through JNA over libfndsa (pca_fndsa.h). Nothing lattice-related is implemented here. Parameter sets 512 and
 * 1024 only. Not interoperable with round-3 Falcon (liboqs, BouncyCastle, circl).
 *
 * <p>The library is found through {@code -Dpca.fndsa.lib}, else the {@code ATLAS_PCA_LIBFNDSA} environment variable (a full path), else the
 * platform lookup of "fndsa". When it cannot be loaded every call fails loudly with an {@link IllegalStateException}; nothing falls back to
 * "invalid". {@link #register()} installs this as the {@link FnDsa} backend; the core never depends on this module.
 */
public final class NativeFnDsa {
  private NativeFnDsa() {}

  public static final int SEED_BYTES = 32, MSG_CAP = 8192;

  /** The prototypes of pca_fndsa.h (size_t is a Java long on every 64-bit platform, int32_t an int, ptrdiff_t a long). */
  interface Fndsa extends Library {
    long fndsa_len_vk(int tag);
    long fndsa_len_sk(int tag);
    long fndsa_len_sig(int tag);
    long fndsa_len_seed();
    long fndsa_cap_msg();
    int fndsa_c_keygen(int tag, byte[] seed, long seedLen, byte[] sk, long skLen, byte[] vk, long vkLen);
    int fndsa_c_sign(int tag, byte[] sk, long skLen, byte[] msg, long msgLen, byte[] seed, long seedLen, byte[] sig, long sigLen);
    int fndsa_c_verify(int tag, byte[] vk, long vkLen, byte[] sig, long sigLen, byte[] msg, long msgLen);
  }

  private static final SecureRandom RNG = new SecureRandom();
  private static volatile Fndsa lib;

  private static String libName() {
    String r = net.atlasauth.pca.NativeLibs.resolve(NativeFnDsa.class, "fndsa", System.getProperty("pca.fndsa.lib"), System.getenv("ATLAS_PCA_LIBFNDSA"));
    return r != null ? r : "fndsa";
  }

  private static Fndsa lib() {
    Fndsa l = lib;
    if (l != null) return l;
    synchronized (NativeFnDsa.class) {
      if (lib == null) {
        try {
          Fndsa loaded = Native.load(libName(), Fndsa.class);
          // the sizes this class relies on must be the ones the library was built with, or nothing is safe
          if (loaded.fndsa_len_vk(512) != FnDsa.FN_DSA_512_PUBLIC_KEY_BYTES || loaded.fndsa_len_sig(512) != FnDsa.FN_DSA_512_SIGNATURE_BYTES
              || loaded.fndsa_len_vk(1024) != FnDsa.FN_DSA_1024_PUBLIC_KEY_BYTES || loaded.fndsa_len_sig(1024) != FnDsa.FN_DSA_1024_SIGNATURE_BYTES
              || loaded.fndsa_len_seed() != SEED_BYTES || loaded.fndsa_cap_msg() != MSG_CAP) {
            throw new IllegalStateException("libfndsa reports different FN-DSA sizes");
          }
          lib = loaded;
        } catch (UnsatisfiedLinkError | RuntimeException e) {
          throw new IllegalStateException("FN-DSA native library unavailable (set ATLAS_PCA_LIBFNDSA or -Dpca.fndsa.lib): " + e.getMessage(), e);
        }
      }
      return lib;
    }
  }

  /** True when libfndsa can be loaded (tests skip, or fail when required, on false). */
  public static boolean available() {
    try {
      lib();
      return true;
    } catch (IllegalStateException e) {
      return false;
    }
  }

  private static int tag(String variant) {
    if ("fn-dsa-512".equals(variant)) return 512;
    if ("fn-dsa-1024".equals(variant)) return 1024;
    throw new IllegalArgumentException("FN-DSA: unknown variant '" + variant + "'");
  }

  private static byte[] need(byte[] b, int len, String what) {
    if (b == null || b.length != len) throw new IllegalArgumentException("FN-DSA: " + what + " must be exactly " + len + " bytes");
    return b;
  }

  private static void ok(int rc, String op) {
    if (rc != 0) throw new IllegalStateException("FN-DSA: " + op + " refused (" + rc + ")");
  }

  /** The secret-key length of a variant, from the library. */
  public static int skBytes(String variant) { return (int) lib().fndsa_len_sk(tag(variant)); }

  /** Deterministic key generation from a 32-byte seed. */
  public static FalconKeyPair keygen(String variant, byte[] seed) {
    int t = tag(variant);
    need(seed, SEED_BYTES, "seed");
    Fndsa l = lib();
    byte[] sk = new byte[(int) l.fndsa_len_sk(t)], vk = new byte[(int) l.fndsa_len_vk(t)];
    ok(l.fndsa_c_keygen(t, seed, SEED_BYTES, sk, sk.length, vk, vk.length), "keygen");
    return new FalconKeyPair(vk, sk);
  }

  /** Key generation from 32 fresh CSPRNG bytes. */
  public static FalconKeyPair keygen(String variant) {
    byte[] seed = new byte[SEED_BYTES];
    RNG.nextBytes(seed);
    return keygen(variant, seed);
  }

  /** Deterministic signature over a raw message (no pre-hash, no domain) of at most 8192 bytes; a longer one is refused, never truncated. */
  public static byte[] sign(String variant, byte[] sk, byte[] msg, byte[] seed) {
    int t = tag(variant);
    Fndsa l = lib();
    need(sk, (int) l.fndsa_len_sk(t), "secret key");
    need(seed, SEED_BYTES, "seed");
    if (msg == null || msg.length > MSG_CAP) throw new IllegalArgumentException("FN-DSA: message must be 0.." + MSG_CAP + " bytes");
    byte[] sig = new byte[(int) l.fndsa_len_sig(t)];
    ok(l.fndsa_c_sign(t, sk, sk.length, msg.length == 0 ? null : msg, msg.length, seed, SEED_BYTES, sig, sig.length), "sign");
    return sig;
  }

  /** Signature with 32 fresh CSPRNG bytes as the signing seed. */
  public static byte[] sign(String variant, byte[] sk, byte[] msg) {
    byte[] seed = new byte[SEED_BYTES];
    RNG.nextBytes(seed);
    return sign(variant, sk, msg, seed);
  }

  /** True only when the library returns 0; a bad signature, a wrong length, a null or an oversize message give false. */
  public static boolean verify(String variant, byte[] vk, byte[] msg, byte[] sig) {
    int t = tag(variant);
    Fndsa l = lib();
    if (vk == null || sig == null || msg == null || msg.length > MSG_CAP) return false;
    if (vk.length != (int) l.fndsa_len_vk(t) || sig.length != (int) l.fndsa_len_sig(t)) return false;
    return l.fndsa_c_verify(t, vk, vk.length, sig, sig.length, msg.length == 0 ? null : msg, msg.length) == 0;
  }

  private static String variantOfVk(int len) {
    return len == FnDsa.FN_DSA_512_PUBLIC_KEY_BYTES ? "fn-dsa-512" : len == FnDsa.FN_DSA_1024_PUBLIC_KEY_BYTES ? "fn-dsa-1024" : null;
  }

  private static String variantOfSk(int len) {
    for (String v : new String[] {"fn-dsa-512", "fn-dsa-1024"}) if (skBytes(v) == len) return v;
    return null;
  }

  /** The seam backend: the variant is inferred from the key length (the seam carries none); an unknown length is refused or false. */
  public static final FalconBackend BACKEND = new FalconBackend() {
    @Override public boolean verify(byte[] pk, byte[] msg, byte[] sig) {
      String v = pk == null ? null : variantOfVk(pk.length);
      if (v == null) { lib(); return false; }
      return NativeFnDsa.verify(v, pk, msg, sig);
    }
    @Override public boolean canSign() { return true; }
    @Override public byte[] sign(byte[] sk, byte[] msg) {
      String v = sk == null ? null : variantOfSk(sk.length);
      if (v == null) throw new IllegalArgumentException("FN-DSA: secret key length matches no variant");
      return NativeFnDsa.sign(v, sk, msg);
    }
    @Override public byte[] sign(byte[] sk, byte[] msg, byte[] signSeed) {
      String v = sk == null ? null : variantOfSk(sk.length);
      if (v == null) throw new IllegalArgumentException("FN-DSA: secret key length matches no variant");
      return NativeFnDsa.sign(v, sk, msg, signSeed);
    }
    @Override public FalconKeyPair keygen(String variant, byte[] seed) { return NativeFnDsa.keygen(variant, seed); }
    /** The seam has no variant argument: FN-DSA-512. Use {@link NativeFnDsa#keygen(String)} for 1024. */
    @Override public FalconKeyPair keygen() { return NativeFnDsa.keygen("fn-dsa-512"); }
  };

  /** Install the real primitive as {@link FnDsa}'s backend. Throws when libfndsa cannot be loaded. */
  public static FalconBackend register() {
    lib();
    FnDsa.setFalconBackend(BACKEND);
    return BACKEND;
  }
}
