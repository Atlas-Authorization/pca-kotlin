package net.atlasauth.pca.sandbox

import net.atlasauth.pca.jose.Js

/**
 * The reference tool as a component in the WebAssembly text format: no toolchain is needed to see the canonical ABI work. It imports
 * only `pca:act/invoke@0.1.0` and exports `run: func() -> s32`, which calls `invoke(handle)` and returns the first
 * byte of the result (or the negative host code).
 */
object ReferenceComponent {
    private const val TEMPLATE = "" +
        "(component\n" +
        "  (import \"pca:act/invoke@0.1.0\" (instance \$inv\n" +
        "    (export \"handle-count\" (func (result u32)))\n" +
        "    (export \"invoke\" (func (param \"handle\" u32) (result (result (list u8) (error s32)))))))\n" +
        "  @EXTRA@\n" +
        "  (core module \$libc\n" +
        "    (memory (export \"memory\") 1 1)\n" +
        "    (global \$bump (mut i32) (i32.const 1024))\n" +
        "    (func (export \"realloc\") (param \$old i32) (param \$oldsz i32) (param \$align i32) (param \$new i32) (result i32)\n" +
        "      (local \$p i32)\n" +
        "      (local.set \$p (global.get \$bump))\n" +
        "      (global.set \$bump (i32.add (local.get \$p) (local.get \$new)))\n" +
        "      (local.get \$p)))\n" +
        "  (core instance \$libc (instantiate \$libc))\n" +
        "  (alias core export \$libc \"memory\" (core memory \$mem))\n" +
        "  (alias core export \$libc \"realloc\" (core func \$realloc))\n" +
        "  (core func \$count (canon lower (func \$inv \"handle-count\")))\n" +
        "  (core func \$invoke (canon lower (func \$inv \"invoke\") (memory \$mem) (realloc \$realloc)))\n" +
        "  (core module \$main\n" +
        "    (import \"libc\" \"memory\" (memory 1))\n" +
        "    (import \"host\" \"count\" (func \$count (result i32)))\n" +
        "    (import \"host\" \"invoke\" (func \$invoke (param i32 i32)))\n" +
        "    (func (export \"run\") (result i32)\n" +
        "      @BODY@))\n" +
        "  (core instance \$host (export \"count\" (func \$count)) (export \"invoke\" (func \$invoke)))\n" +
        "  (core instance \$main (instantiate \$main (with \"libc\" (instance \$libc)) (with \"host\" (instance \$host))))\n" +
        "  (alias core export \$main \"run\" (core func \$run))\n" +
        "  (func \$lifted (result s32) (canon lift (core func \$run)))\n" +
        "  (export \"run\" (func \$lifted)))\n"

    /** Options: `handle` (the handle `run` invokes, default 1), `spin` (loop forever), `extraImport` (an import the host must refuse). Null means all defaults. */
    @JvmStatic
    fun referenceComponentWat(o: Map<String, Any?>?): String {
        val extraImport = o?.get("extraImport")
        val extra = if (Js.truthy(extraImport)) "(import \"" + Js.template(extraImport) + "\" (instance (export \"get-arguments\" (func (result (list string))))))" else ""
        val body: String
        if (o != null && Js.truthy(o["spin"])) body = "(loop \$l (br \$l)) (i32.const 0)"
        else {
            val h = o?.get("handle")
            body = "(call \$invoke (i32.const " + (if (h == null) "1" else Js.template(h)) + ") (i32.const 16))\n" +
                "       (if (result i32) (i32.load8_u (i32.const 16))\n" +
                "         (then (i32.load (i32.const 20)))\n" +
                "         (else (i32.load8_u (i32.load (i32.const 20)))))"
        }
        return TEMPLATE.replace("@EXTRA@", extra).replace("@BODY@", body)
    }
}
