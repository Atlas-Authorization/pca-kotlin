package net.atlasauth.pca.verifier

import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Deadline tests: Workflow.ancestors (visit recursion) and LessNative.candidates (walk up the directory tree). */
class Kill06DeadlineCWorkflowTest {
    private fun step(id: String, vararg deps: String) = linkedMapOf<String, Any?>("id" to id, "deps" to ArrayList<Any?>(deps.toList()))
    private fun wf(vararg steps: Map<String, Any?>) = linkedMapOf<String, Any?>("steps" to ArrayList<Any?>(steps.toList()), "edges" to ArrayList<Any?>())

    @Test fun ancestorsOfADagListedDependentsFirst() {
        // d is listed before everything it depends on, and c's dependencies a, b are visited again through d
        val b = wf(step("d", "c"), step("c", "a", "b"), step("b", "a"), step("a"))
        val got = Deadline.within { Workflow.ancestors(b) }!!
        assertEquals(setOf("a", "b", "c", "d"), got.keys)
        assertEquals(emptySet<String>(), got["a"])
        assertEquals(setOf("a"), got["b"])
        assertEquals(setOf("a", "b"), got["c"])
        assertEquals(setOf("a", "b", "c"), got["d"])
        assertNull(Deadline.within { Workflow.dagError(b) })
    }

    @Test fun ancestorsOfADiamondAndOfACycle() {
        val diamond = wf(step("top", "l", "r"), step("l", "base"), step("r", "base"), step("base"))
        val got = Deadline.within { Workflow.ancestors(diamond) }!!
        assertEquals(setOf("l", "r", "base"), got["top"])
        assertEquals(setOf("base"), got["l"])
        assertEquals(setOf("base"), got["r"])
        assertNull(Deadline.within { Workflow.ancestors(wf(step("x", "y"), step("y", "z"), step("z", "x"))) })
        assertNull(Deadline.within { Workflow.ancestors(wf(step("s", "s"))) })
        assertEquals("cycle", Deadline.within { Workflow.dagError(wf(step("x", "y"), step("y", "x"))) })
    }

    @Test fun candidatesWalkUpToTheBuildDirOrTheFilesystemRoot() {
        val oldDir = System.getProperty("user.dir")
        val oldLib = System.getProperty("atlas.pca.libless")
        val sep = File.pathSeparator
        val root = Files.createTempDirectory("k06-less")
        try {
            System.setProperty("atlas.pca.libless", "/k06/a${sep}${sep}/k06/b")
            val envSet = !System.getenv("ATLAS_PCA_LIBLESS").isNullOrEmpty()
            // no sdks/pca-less-c/build anywhere above: the walk must reach the filesystem root and stop
            val deep = Files.createDirectories(root.resolve("x").resolve("y"))
            System.setProperty("user.dir", deep.toString())
            val none = Deadline.within { LessNative.candidates() }
            if (!envSet) assertEquals(listOf(Paths.get("/k06/a"), Paths.get("/k06/b")), none) else assertTrue(none.none { it.toString().contains("pca-less-c") })
            // a build dir two levels up is found, its three library names follow the env ones, and the walk stops there
            val build = Files.createDirectories(root.resolve("sdks").resolve("pca-less-c").resolve("build"))
            val withBuild = Deadline.within { LessNative.candidates() }
            val libs = listOf("libatlas_less.so", "libatlas_less.dylib", "atlas_less.dll").map { build.resolve(it) }
            assertEquals(libs, withBuild.takeLast(3))
            assertEquals(none.size + 3, withBuild.size)
        } finally {
            System.setProperty("user.dir", oldDir)
            if (oldLib == null) System.clearProperty("atlas.pca.libless") else System.setProperty("atlas.pca.libless", oldLib)
        }
    }
}
