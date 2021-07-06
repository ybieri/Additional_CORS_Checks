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
    val isActive = JCheckBox("Activate CORS?")
    val inScope = JCheckBox("Only in scope?")
    val ignoreJSAndImages = JCheckBox("Ignore extensions:")
    val ignoreExtension = JTextField("ico, svg, js, css, png", 30)
    //private val tagComboBox = JComboBox(arrayOf<String>()) // chnge to text field

    init {
        //val loadButton = JButton("Load Highlighted Proxy History")
        val clearButton = JButton("Clear CORS Requests")
        val urlTextLabel = JLabel("URL for CORS Requests:")
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
        configPanel.add(isActive)
        isActive.isSelected = true
        configPanel.add(inScope)
        inScope.isSelected = true
        configPanel.add(ignoreJSAndImages)
        ignoreJSAndImages.isSelected = true
        configPanel.add(ignoreExtension)
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




    private fun clearCors() {
        corsPanel.model.clearCors()
        corsPanel.requestViewer?.setMessage(ByteArray(0), true)
        corsPanel.responseViewer?.setMessage(ByteArray(0), false)
    }


}