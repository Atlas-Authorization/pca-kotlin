package net.atlasauth.pca.connect

import net.atlasauth.pca.jose.Js

/** A stored outbound connection, keyed by agent + provider + connectionId. Mutable fields: stores clone in and out. */
class StoredConnection {
    /** The PCA authority a connection is bound to: which capability may unlock this token. */
    class ConnectionAuthority {
        var provider: String? = null

        /** The trust anchor: the b64u public key the capability chain must be rooted at. */
        var principal: String? = null
        var scopes: List<String> = ArrayList()

        /** When set, the PCActn's signed aud must equal it (null = none). */
        var audience: String? = null

        fun copy(): ConnectionAuthority {
            val a = ConnectionAuthority()
            a.provider = provider
            a.principal = principal
            a.scopes = ArrayList(scopes)
            a.audience = audience
            return a
        }
    }

    var agentId: String = ""
    var provider: String = ""
    var connectionId: String = ""
    var accessToken: String = ""

    /** Null when there is none. */
    var refreshToken: String? = null

    /** Access-token expiry, epoch milliseconds. */
    var expiresAt: Double = 0.0

    /** The scopes the stored access token actually carries. */
    var scopes: List<String> = ArrayList()
    var authority: ConnectionAuthority = ConnectionAuthority()
    var createdAt: Double = 0.0

    /** Null when never used. */
    var lastUsedAt: Double? = null
    var useCount: Long = 0

    fun copy(): StoredConnection {
        val c = StoredConnection()
        c.agentId = agentId
        c.provider = provider
        c.connectionId = connectionId
        c.accessToken = accessToken
        c.expiresAt = expiresAt
        c.scopes = ArrayList(scopes)
        c.authority = authority.copy()
        c.createdAt = createdAt
        c.useCount = useCount
        c.refreshToken = refreshToken
        c.lastUsedAt = lastUsedAt
        return c
    }

    /** The connection as the reference's plain object (members absent when unset). */
    fun toMap(): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["agentId"] = agentId
        m["provider"] = provider
        m["connectionId"] = connectionId
        m["accessToken"] = accessToken
        m["expiresAt"] = Js.jsNum(expiresAt)
        m["scopes"] = ArrayList<Any?>(scopes)
        val a = LinkedHashMap<String, Any?>()
        a["provider"] = authority.provider
        a["principal"] = authority.principal
        a["scopes"] = ArrayList<Any?>(authority.scopes)
        if (authority.audience != null) a["audience"] = authority.audience
        m["authority"] = a
        m["createdAt"] = Js.jsNum(createdAt)
        m["useCount"] = Js.n(useCount)
        if (refreshToken != null) m["refreshToken"] = refreshToken
        if (lastUsedAt != null) m["lastUsedAt"] = Js.jsNum(lastUsedAt!!)
        return m
    }

    companion object {
        /** The reference's `cloneConnection`. */
        @JvmStatic fun cloneConnection(c: StoredConnection): StoredConnection = c.copy()
    }
}

/** CRUD over stored connections. Implementations must round-trip a [StoredConnection] by its key; any exception means the store failed. */
interface ConnectionStore {
    /** The composite key identifying one stored connection. */
    class Key(val agentId: String, val provider: String, val connectionId: String) {
        /** NUL-joined: provider / connectionId / agentId are b64u or opaque tokens, none of which contain NUL. */
        internal fun str(): String = agentId + "\u0000" + provider + "\u0000" + connectionId
    }

    /** The connection, or null. */
    fun get(key: Key): StoredConnection?

    fun set(connection: StoredConnection)

    fun delete(key: Key)

    /** Marks the store as encrypting at rest; [TokenVault] requires it in strict mode. */
    fun encrypted(): Boolean = false
}

/**
 * Process-local [ConnectionStore] (test double: tokens sit in plaintext in process memory, so a [TokenVault] accepts it only
 * with `strict = false`). Connections are cloned in and out so callers cannot mutate vault state through a held reference.
 */
class InMemoryConnectionStore : ConnectionStore {
    private val map = java.util.concurrent.ConcurrentHashMap<String, StoredConnection>()

    override fun get(key: ConnectionStore.Key): StoredConnection? = map[key.str()]?.copy()

    override fun set(connection: StoredConnection) {
        map[ConnectionStore.Key(connection.agentId, connection.provider, connection.connectionId).str()] = connection.copy()
    }

    override fun delete(key: ConnectionStore.Key) { map.remove(key.str()) }
}
