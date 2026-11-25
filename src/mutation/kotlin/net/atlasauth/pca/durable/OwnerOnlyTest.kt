package net.atlasauth.pca.durable

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import net.atlasauth.pca.ciba.CibaKv
import net.atlasauth.pca.mpc.net.PartyMain
import net.atlasauth.pca.revoke.FileRevocationStore
import net.atlasauth.pca.revoke.RevocationEntry
import net.atlasauth.pca.scitt.FileScittLogStore
import net.atlasauth.pca.verifier.FileMeshWitnessStore
import net.atlasauth.pca.verifier.PcaJdbcStateStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Every writer of private state leaves what it created owner-only, read back from the file system: POSIX mode 0600 (files) / 0700
 * (directories); on Windows every ACL entry is an allow for the current user and no other principal appears (a directory the library creates
 * carries an entry with FILE_INHERIT and DIRECTORY_INHERIT, so what a third party creates inside it is owner-only too). The creating call
 * itself carries the restriction (see OwnerOnly), so there is no window in which the object is wider.
 */
class OwnerOnlyTest {
    private fun root(): Path = OwnerOnly.createTempDirectory("pca-owner-")

    private fun private_(p: Path) = assertNull(p.toString(), OwnerOnly.problem(p))

    private fun privateTree(dir: Path) {
        private_(dir)
        Files.walk(dir).use { s -> s.forEach { if (it != dir) private_(it) } }
    }

    @Test fun primitivesCreateOwnerOnly() {
        val r = root()
        private_(r)
        val f = OwnerOnly.createFile(r.resolve("a"))
        private_(f)
        try {
            OwnerOnly.createFile(f)
            fail("an existing file must not be created again")
        } catch (e: java.nio.file.FileAlreadyExistsException) {
            // exclusive creation holds
        }
        val d = OwnerOnly.createDirectories(r.resolve("x").resolve("y"))
        private_(d)
        private_(d.parent)
        private_(OwnerOnly.createTempFile(r, "t", ".tmp"))
        private_(OwnerOnly.createTempDirectory("pca-owner-t-"))
        OwnerOnly.writeNew(r.resolve("n"), byteArrayOf(1, 2, 3))
        private_(r.resolve("n"))
        assertEquals(3L, Files.size(r.resolve("n")))
    }

    @Test fun replacePublishesOwnerOnly() {
        val r = root()
        val target = File(r.toFile(), "t.json")
        OwnerOnly.writeReplace(target, "one".toByteArray())
        OwnerOnly.writeReplace(target, "two".toByteArray())
        private_(target.toPath())
        assertEquals("two", String(Files.readAllBytes(target.toPath())))
        assertEquals(listOf("t.json"), r.toFile().list()!!.toList()) // no temporary file is left behind
    }

    @Test fun durableStateDirectoryAndFiles() {
        val r = root()
        val dir = r.resolve("state")
        val st = openDurableState(DurableStateOptions(dir.toString()))
        st.set("k", "v")
        st.set("k2", "w")
        assertTrue(Files.list(dir).use { it.count() } > 0)
        privateTree(dir)
    }

    @Test fun revocationFile() {
        val r = root()
        val f = File(r.toFile(), "revocations.json")
        FileRevocationStore(f).add(RevocationEntry("cap", "c1", null, "r", 1.0, null))
        private_(f.toPath())
        assertEquals(listOf("revocations.json"), r.toFile().list()!!.toList())
    }

    @Test fun meshWitnessFile() {
        val r = root()
        val f = File(r.toFile(), "witness.json")
        FileMeshWitnessStore(f).save(linkedMapOf<String, Any?>("seen" to ArrayList<Any?>()))
        private_(f.toPath())
        assertEquals(listOf("witness.json"), r.toFile().list()!!.toList())
    }

    @Test fun approvalKeyValueDirectoryAndFiles() {
        val r = root()
        val dir = File(r.toFile(), "kv")
        val kv = CibaKv.createDirectoryKv(dir)
        assertTrue(kv.putIfEquals("a", null, "one"))
        assertTrue(kv.putIfEquals("a", "one", "two"))
        privateTree(dir.toPath())
        // a directory handed in is restricted in place
        val given = OwnerOnly.createTempDirectory("pca-owner-g-").toFile()
        CibaKv.createDirectoryKv(given)
        private_(given.toPath())
    }

    @Test fun transparencyLogFile() {
        val r = root()
        val f = File(r.toFile(), "log.bin")
        FileScittLogStore.open(f).close()
        private_(f.toPath())
    }

    @Test fun aFileAnotherPartyCreatesInAPrivateDirectoryInheritsOwnerOnly() {
        org.junit.Assume.assumeTrue("ACL inheritance is a Windows file system rule", System.getProperty("os.name", "").lowercase().contains("win"))
        val d = OwnerOnly.createTempDirectory("pca-owner-i-")
        val plain = File(d.toFile(), "journal")
        assertTrue(plain.createNewFile()) // an ordinary create, as a database driver makes its journal
        private_(plain.toPath())
        val sub = File(d.toFile(), "sub")
        assertTrue(sub.mkdir())
        private_(sub.toPath())
    }

    @Test fun databaseFileAndDirectories() {
        val r = root()
        val f = r.resolve("db").resolve("claims.sqlite")
        val made = PcaJdbcStateStore.ensureSqliteFile("jdbc:sqlite:" + f.toString().replace('\\', '/'))
        assertEquals(f.toAbsolutePath(), made!!.toAbsolutePath())
        private_(f)
        private_(f.parent)
    }

    @Test fun keyMaterialFiles() {
        val r = root()
        val dir = File(r.toFile(), "keys")
        assertEquals(0, PartyMain.run(arrayOf("keygen", dir.path, "party-1")))
        assertTrue(File(dir, "key.pem").isFile && File(dir, "cert.pem").isFile)
        privateTree(dir.toPath())
    }
}
