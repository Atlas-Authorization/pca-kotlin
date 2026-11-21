package net.atlasauth.pca.verifier

/** Small JSON-tree helpers shared by the durable store classes (copying, number boxing). */
internal object StoreJs {
    /** A deep copy of a JSON tree (Map, List, scalars). Stores never hand out or keep a caller's mutable structure. */
    fun deepCopy(v: Any?): Any? = MemoryAtomicKv.copyTree(v)

    /** The JSON number for a long (a safe integer prints as is). */
    fun num(v: Long): Json.Num = Json.Num(v.toString())

    /** The JSON number for a double, printed as JavaScript prints it. */
    fun num(v: Double): Json.Num = Json.Num(AttestUtil.jsNumString(v))

    /** The double of a JSON number, or null. */
    fun dbl(v: Any?): Double? = IntentJs.num(v)

    @Suppress("UNCHECKED_CAST")
    fun map(v: Any?): MutableMap<String, Any?>? = v as? MutableMap<String, Any?>

    /** base64url(sha256(lenient canonical JSON)): the reference's lenient content hash. */
    fun hashLenient(v: Any?): String = Pca.b64(Pca.sha(Json.canonicalize(v).toByteArray(Charsets.UTF_8)))

    fun jsonEq(a: Any?, b: Any?): Boolean = hashLenient(a) == hashLenient(b)
}
