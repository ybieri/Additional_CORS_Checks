package burp

import java.awt.Toolkit
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.StringSelection
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.util.*
import javax.swing.JMenuItem
import javax.swing.JPopupMenu
import kotlin.collections.ArrayList

class CorsActions(
    private val panel: CorsPanel,
    private val callbacks: IBurpExtenderCallbacks
) : ActionListener {
    private val table = panel.table
    private val actionsMenu = JPopupMenu()
    private val sendToRepeater = JMenuItem("Send request(s) to Repeater")
    private val sendToIntruder = JMenuItem("Send request(s) to Intruder")
    private val copyURLs = JMenuItem("Copy URL(s)")
    private val clearMenu = JMenuItem("Clear Cors Requests")

    init {
        sendToRepeater.addActionListener(this)
        sendToIntruder.addActionListener(this)
        copyURLs.addActionListener(this)
        clearMenu.addActionListener(this)
        actionsMenu.add(sendToRepeater)
        actionsMenu.add(sendToIntruder)
        actionsMenu.add(copyURLs)
        actionsMenu.addSeparator()
        actionsMenu.add(clearMenu)
        actionsMenu.addSeparator()
        actionsMenu.addSeparator()
        panel.table.componentPopupMenu = actionsMenu
    }


    override fun actionPerformed(e: ActionEvent?) {
        if (table.selectedRow == -1) return
        val selectedCorss = getSelectedCors()
        when (val source = e?.source) {

            clearMenu -> {
                panel.model.clearCors()
                panel.requestViewer?.setMessage(ByteArray(0), true)
                panel.responseViewer?.setMessage(ByteArray(0), false)
            }
            copyURLs -> {
                val urls = selectedCorss.map { it.url }.joinToString()
                val clipboard: Clipboard = Toolkit.getDefaultToolkit().systemClipboard
                clipboard.setContents(StringSelection(urls), null)
            }

            else -> {
                for (selectedCors in selectedCorss) {
                    val https = useHTTPs(selectedCors)
                    val url = selectedCors.url
                    when (source) {
                        sendToRepeater -> {
                            var title = "title"
                            if (title.length > 10) {
                                title = title.substring(0, 9) + "+"
                            }

                            callbacks.sendToRepeater(
                                url.host,
                                url.port,
                                https,
                                selectedCors.requestResponse.request,
                                title
                            )
                        }
                        sendToIntruder -> {
                            callbacks.sendToIntruder(
                                url.host, url.port, https,
                                selectedCors.requestResponse.request, null
                            )
                        }

                    }
                }
            }
        }
    }




    private fun getSelectedCors(): MutableList<CorsObj> {
        val selectedBookmarks: MutableList<CorsObj> = ArrayList()
        for (index in table.selectedRows) {
            val row = panel.rowSorter.convertRowIndexToModel(index)
            selectedBookmarks.add(panel.model.displayedCors[row])
        }
        return selectedBookmarks
    }

    private fun useHTTPs(bookmark: CorsObj): Boolean {
        return (bookmark.url.protocol.lowercase(Locale.getDefault()) == "https")
    }
}