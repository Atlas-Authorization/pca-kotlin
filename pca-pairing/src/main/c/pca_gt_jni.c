/* JNI entry points for net.atlasauth.pca.pairing.Gt over pca_gt.c. Wrong-length input is refused here (null / false). */
#include <jni.h>
#include <stdlib.h>
#include "blst.h"

int pca_gt_mul(byte out[576], const byte a[576], const byte b[576]);
int pca_gt_pow(byte out[576], const byte a[576], const byte k[32]);
int pca_gt_is_element(const byte a[576]);
int pca_gt_pairing(byte out[576], const byte *g1s, const byte *g2s, size_t n);

static int get(JNIEnv *env, jbyteArray arr, jsize len, byte *buf) {
    if (arr == NULL || (*env)->GetArrayLength(env, arr) != len) return 0;
    (*env)->GetByteArrayRegion(env, arr, 0, len, (jbyte *)buf);
    return !(*env)->ExceptionCheck(env);
}

static jbyteArray put(JNIEnv *env, const byte *buf, jsize len) {
    jbyteArray out = (*env)->NewByteArray(env, len);
    if (out != NULL) (*env)->SetByteArrayRegion(env, out, 0, len, (const jbyte *)buf);
    return out;
}

JNIEXPORT jbyteArray JNICALL Java_net_atlasauth_pca_pairing_Gt_mul0(JNIEnv *env, jclass cls, jbyteArray a, jbyteArray b) {
    byte x[576], y[576], z[576];
    (void)cls;
    if (!get(env, a, 576, x) || !get(env, b, 576, y) || !pca_gt_mul(z, x, y)) return NULL;
    return put(env, z, 576);
}

JNIEXPORT jbyteArray JNICALL Java_net_atlasauth_pca_pairing_Gt_pow0(JNIEnv *env, jclass cls, jbyteArray a, jbyteArray k) {
    byte x[576], e[32], z[576];
    (void)cls;
    if (!get(env, a, 576, x) || !get(env, k, 32, e) || !pca_gt_pow(z, x, e)) return NULL;
    return put(env, z, 576);
}

JNIEXPORT jboolean JNICALL Java_net_atlasauth_pca_pairing_Gt_isElement0(JNIEnv *env, jclass cls, jbyteArray a) {
    byte x[576];
    (void)cls;
    return get(env, a, 576, x) && pca_gt_is_element(x) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL Java_net_atlasauth_pca_pairing_Gt_pairing0(JNIEnv *env, jclass cls, jbyteArray g1s, jbyteArray g2s, jint n) {
    byte z[576];
    jbyteArray res = NULL;
    (void)cls;
    if (n <= 0 || n > 4096) return NULL;
    byte *p = malloc((size_t)n * 48), *q = malloc((size_t)n * 96);
    if (p != NULL && q != NULL && get(env, g1s, n * 48, p) && get(env, g2s, n * 96, q) && pca_gt_pairing(z, p, q, (size_t)n))
        res = put(env, z, 576);
    free(p);
    free(q);
    return res;
}
