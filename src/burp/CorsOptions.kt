package burp

import java.awt.FlowLayout
import java.awt.event.ActionListener
import java.util.*
import javax.swing.*

class CorsOptions(
    private val corsPanel: CorsPanel,
    private val callbacks: IBurpExtenderCallbacks
) {
    val panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
    private val loadPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
    val urlTextField = JTextField("www.example.com", 20)
    private val configPanel = JPanel(FlowLayout(FlowLayout.LEFT))
    val inScope = JCheckBox("Only in scope?")
    val isActive = JCheckBox("Activate CORS?")
    val ignoreJSAndImages = JCheckBox("Ignore JS, CSS, images?")
    //private val tagComboBox = JComboBox(arrayOf<String>()) // chnge to text field

    init {
        //val loadButton = JButton("Load Highlighted Proxy History")
        val clearButton = JButton("Clear Cors Requests")
        val urlTextLabel = JLabel("URL for CORS:")
        //val uriButton = JButton("Filter")
        //val resetButton = JButton("Reset")
        //tagComboBox.selectedIndex = -1
        //tagComboBox.prototypeDisplayValue = "Select tag"
        //tagComboBox.addItem("Select tag")
        //loadButton.addActionListener { loadHighlightedRequests() }
        //uriButton.addActionListener( uriButtonAction() )
        clearButton.addActionListener { clearCors() }
        configPanel.add(urlTextLabel)
        configPanel.add(urlTextField)
        configPanel.add(inScope)
        inScope.isSelected = true
        configPanel.add(isActive)
        isActive.isSelected = true
        configPanel.add(ignoreJSAndImages)
        ignoreJSAndImages.isSelected = true
        //configPanel.add(tagComboBox)
        //configPanel.add(uriButton)
        //configPanel.add(resetButton)
        loadPanel.add(clearButton)
        //loadPanel.add(loadButton)
        panel.leftComponent = configPanel
        panel.rightComponent = loadPanel
        panel.dividerSize = 0
    }

    private fun uriButtonAction(): ActionListener? {
        return null
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