package burp

import java.awt.FlowLayout
import javax.swing.*

class CorsOptions(
    private val corsPanel: CorsPanel,
    private val callbacks: IBurpExtenderCallbacks
) {
    val panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
    private val loadPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
    private val filterBar = JTextField("", 20)
    private val filterPanel = JPanel(FlowLayout(FlowLayout.LEFT))
    private val tagComboBox = JComboBox(arrayOf<String>()) // chnge to text field

    init {
        val loadButton = JButton("Load Highlighted Proxy History")
        val clearButton = JButton("Clear Cors Requests")
        val filterLabel = JLabel("URL for CORS:")
        val filterButton = JButton("Filter")
        val resetButton = JButton("Reset")
        tagComboBox.selectedIndex = -1
        tagComboBox.prototypeDisplayValue = "Select tag"
        tagComboBox.addItem("Select tag")
        loadButton.addActionListener { loadHighlightedRequests() }
        clearButton.addActionListener { clearCors() }
        filterPanel.add(filterLabel)
        filterPanel.add(filterBar)
        filterPanel.add(tagComboBox)
        filterPanel.add(filterButton)
        filterPanel.add(resetButton)
        loadPanel.add(clearButton)
        loadPanel.add(loadButton)
        panel.leftComponent = filterPanel
        panel.rightComponent = loadPanel
        panel.dividerSize = 0
    }
    //modify, remove TODO
    private fun loadHighlightedRequests() {
        corsPanel.model.refreshCors()
        SwingUtilities.invokeLater {
            val corsarr = corsPanel.corsarr
            val corsRequestResponse = corsarr.map {
                Pair(
                    callbacks.helpers.bytesToString(it.requestResponse.request),
                    callbacks.helpers.bytesToString(it.requestResponse.response ?: ByteArray(0))
                )
            }
            val proxyHistory = callbacks.proxyHistory.asSequence()
            val corsToAdd = proxyHistory
                .filter { it.highlight != null }
                .filterNot {
                    corsRequestResponse.contains(
                        Pair(
                            callbacks.helpers.bytesToString(it.request),
                            callbacks.helpers.bytesToString(it.response ?: ByteArray(0))
                        )
                    )
                }
                .distinct()
                .toList()
                .toTypedArray()
            corsPanel.addCorsRequestToTable(corsToAdd)

        }
    }


    private fun clearCors() {
        corsPanel.model.clearCors()
        corsPanel.requestViewer?.setMessage(ByteArray(0), true)
        corsPanel.responseViewer?.setMessage(ByteArray(0), false)
    }


}