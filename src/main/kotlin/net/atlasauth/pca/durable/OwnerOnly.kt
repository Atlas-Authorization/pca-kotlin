package net.atlasauth.pca.durable

import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryFlag
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.AclFileAttributeView
import java.nio.file.attribute.FileAttribute
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.UserPrincipal
import java.util.EnumSet

/**
 * The one way the library creates private state (approval stores, key-value state, revocation and mesh-witness state, durable state, key
 * material, conformance harness files): owner-only AT CREATION. On POSIX that is mode 0600 (files) / 0700 (directories); on Windows a security
 * descriptor whose DACL holds exactly one entry, full rights for the current user, handed to the create call itself (a chmod does nothing
 * there, and restricting a file after it exists leaves a window in which another process can open it and keep the handle). A file system that
 * offers neither permission model is refused: private state is never written world-readable.
 */
object OwnerOnly {
    private fun views(): Set<String> = FileSystems.getDefault().supportedFileAttributeViews()

    private fun posix(): Boolean = views().contains("posix")

    private fun currentUser(): UserPrincipal {
        val lookup = FileSystems.getDefault().userPrincipalLookupService
        val name = System.getProperty("user.name") ?: throw IOException("the current user is unknown")
        return try {
            lookup.lookupPrincipalByName(name)
        } catch (e: IOException) {
            val domain = System.getenv("USERDOMAIN")
            if (domain.isNullOrEmpty()) throw e
            lookup.lookupPrincipalByName("$domain\\$name")
        }
    }

    /** The flags of a directory's entry: inheritable, so a file or directory made inside it by anyone (a driver's journal, say) is owner-only too. */
    private fun dirFlags(): Set<AclEntryFlag> = EnumSet.of(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT)

    /** The ACL of an owner-only object: one entry, ALLOW, every right, the current user; a directory's entry is inheritable, a file's is not. */
    private fun ownerAcl(dir: Boolean): List<AclEntry> =
        listOf(
            AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(currentUser()).setPermissions(EnumSet.allOf(AclEntryPermission::class.java))
                .setFlags(if (dir) dirFlags() else EnumSet.noneOf(AclEntryFlag::class.java)).build(),
        )

    /** The creation attribute that makes a new file ([dir] false) or directory owner-only on this platform. */
    fun attrs(dir: Boolean): Array<FileAttribute<*>> {
        if (posix()) return arrayOf<FileAttribute<*>>(PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(if (dir) "rwx------" else "rw-------")))
        if (views().contains("acl")) {
            val entries = ownerAcl(dir)
            return arrayOf<FileAttribute<*>>(object : FileAttribute<List<AclEntry>> {
                override fun name(): String = "acl:acl"
                override fun value(): List<AclEntry> = entries
            })
        }
        throw IOException("this file system has neither POSIX permissions nor ACLs: private state cannot be made owner-only")
    }

    /** Create [path] exclusively (it must not exist), owner-only. */
    fun createFile(path: Path): Path = Files.createFile(path, *attrs(false))

    /** Create [path] and any missing parents, each created directory owner-only; an existing directory is left as it is. */
    fun createDirectories(path: Path): Path = Files.createDirectories(path, *attrs(true))

    /** A new, uniquely named, owner-only file in [dir] (the temporary directory when null). */
    fun createTempFile(dir: Path?, prefix: String, suffix: String): Path =
        if (dir == null) Files.createTempFile(prefix, suffix, *attrs(false)) else Files.createTempFile(dir, prefix, suffix, *attrs(false))

    /** A new, uniquely named, owner-only directory in the temporary directory. */
    fun createTempDirectory(prefix: String): Path = Files.createTempDirectory(prefix, *attrs(true))

    /** Create [path] exclusively, owner-only, write [data] and fsync. */
    fun writeNew(path: Path, data: ByteArray) {
        FileChannel.open(path, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), *attrs(false)).use { ch ->
            val buf = ByteBuffer.wrap(data)
            while (buf.hasRemaining()) ch.write(buf)
            ch.force(true)
        }
    }

    /** Publish [data] as [target]: an owner-only temporary file next to it, fsynced, then an atomic move that replaces the target. */
    fun writeReplace(target: File, data: ByteArray) {
        val dir = target.absoluteFile.parentFile.toPath()
        val tmp = createTempFile(dir, target.name + ".", ".tmp")
        try {
            FileChannel.open(tmp, setOf(StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)).use { ch ->
                val buf = ByteBuffer.wrap(data)
                while (buf.hasRemaining()) ch.write(buf)
                ch.force(true)
            }
            Files.move(tmp, target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally {
            Files.deleteIfExists(tmp)
        }
    }

    /**
     * Restrict an object that already exists (a directory the caller handed in). This cannot be atomic with its creation; every object the
     * library creates itself goes through [attrs] instead.
     */
    fun restrictExisting(path: Path) {
        if (posix()) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(if (Files.isDirectory(path)) "rwx------" else "rw-------"))
            return
        }
        val view = Files.getFileAttributeView(path, AclFileAttributeView::class.java) ?: throw IOException("this file system has neither POSIX permissions nor ACLs")
        view.setAcl(ownerAcl(Files.isDirectory(path)))
    }

    /** What an owner-only object looks like read back: null when it is owner-only, else the reason it is not. */
    fun problem(path: Path): String? {
        val dir = Files.isDirectory(path)
        if (posix()) {
            val want = PosixFilePermissions.fromString(if (dir) "rwx------" else "rw-------")
            val got = Files.getPosixFilePermissions(path)
            return if (got == want) null else "mode is " + PosixFilePermissions.toString(got)
        }
        val view = Files.getFileAttributeView(path, AclFileAttributeView::class.java) ?: return "no ACL view"
        val acl = view.acl
        // java.nio cannot mark the DACL protected, so an object made inside an inheritable private directory also carries the inherited entry:
        // the property is that every entry is an allow for the current user and no other principal appears
        if (acl.isEmpty()) return "the ACL has no entries"
        val me = currentUser()
        for (e in acl) {
            if (e.type() != AclEntryType.ALLOW) return "an entry is not an allow entry"
            if (e.principal() != me && e.principal().name != me.name) return "an entry is for " + e.principal().name
        }
        // a directory the library creates carries its own inheritable entry
        if (dir && acl.none { it.flags() == dirFlags() }) return "no entry is inheritable by files and directories"
        return null
    }
}
