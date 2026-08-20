package kh.zila.ndsecure.vaultsource

import android.app.Activity
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.view.WindowManager
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

@InvokeArg
internal class SourceArgs {
    lateinit var uri: String
}

@TauriPlugin
class VaultSourcePlugin(private val activity: Activity) : Plugin(activity) {
    init {
        activity.runOnUiThread {
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    private val ioScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    @Command
    fun openSource(invoke: Invoke) {
        val args = invoke.parseArgs(SourceArgs::class.java)
        ioScope.launch {
            try {
                val uri = validatedContentUri(args.uri)
                val descriptor = activity.contentResolver.openFileDescriptor(uri, "r")
                    ?: throw IllegalArgumentException("Unable to open selected document")
                var detached = false
                try {
                    val providerSize = activity.contentResolver.query(
                        uri,
                        arrayOf(OpenableColumns.SIZE),
                        null,
                        null,
                        null
                    )?.use { cursor ->
                        if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getLong(0) else -1L
                    } ?: -1L
                    val size = if (descriptor.statSize > 0L) descriptor.statSize else providerSize
                    if (size <= 0L) {
                        invoke.reject("Selected provider did not expose a stable file length")
                        return@launch
                    }

                    val detachedFd = descriptor.detachFd()
                    detached = true
                    val result = JSObject()
                    result.put("fd", detachedFd)
                    result.put("size", size)
                    invoke.resolve(result)
                } finally {
                    if (!detached) descriptor.close()
                }
            } catch (error: Exception) {
                invoke.reject(error.message ?: "Unable to open selected document")
            }
        }
    }

    @Command
    fun deleteSource(invoke: Invoke) {
        val args = invoke.parseArgs(SourceArgs::class.java)
        ioScope.launch {
            try {
                val uri = validatedContentUri(args.uri)
                val deleted = try {
                    if (DocumentsContract.isDocumentUri(activity, uri)) {
                        DocumentsContract.deleteDocument(activity.contentResolver, uri)
                    } else {
                        activity.contentResolver.delete(uri, null, null) > 0
                    }
                } catch (_: UnsupportedOperationException) {
                    activity.contentResolver.delete(uri, null, null) > 0
                }
                val result = JSObject()
                result.put("deleted", deleted)
                invoke.resolve(result)
            } catch (error: Exception) {
                invoke.reject(error.message ?: "Unable to remove selected document")
            }
        }
    }

    private fun validatedContentUri(raw: String): Uri {
        val uri = Uri.parse(raw)
        if (uri.scheme != "content") {
            throw IllegalArgumentException("Only Android content URIs are accepted")
        }
        return uri
    }
}
