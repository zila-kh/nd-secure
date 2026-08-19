package kh.zila.ndsecure.vaultsource

import android.app.Activity
import android.net.Uri
import android.provider.OpenableColumns
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
internal class OpenSourceArgs {
    lateinit var uri: String
}

@TauriPlugin
class VaultSourcePlugin(private val activity: Activity) : Plugin(activity) {
    private val ioScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    @Command
    fun openSource(invoke: Invoke) {
        val args = invoke.parseArgs(OpenSourceArgs::class.java)
        ioScope.launch {
            try {
                val uri = Uri.parse(args.uri)
                if (uri.scheme != "content") {
                    invoke.reject("Only Android content URIs are accepted")
                    return@launch
                }

                val descriptor = activity.contentResolver.openFileDescriptor(uri, "r")
                    ?: throw IllegalArgumentException("Unable to open selected document")
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
                    descriptor.close()
                    invoke.reject("Selected provider did not expose a stable file length")
                    return@launch
                }

                val detachedFd = descriptor.detachFd()
                val result = JSObject()
                result.put("fd", detachedFd)
                result.put("size", size)
                invoke.resolve(result)
            } catch (error: Exception) {
                invoke.reject(error.message ?: "Unable to open selected document")
            }
        }
    }

}
