package burp

import java.awt.FlowLayout
import javax.swing.*

class CorsOptions(
    private val corsPanel: CorsPanel,
) {
    val panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
    private val loadPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
    val urlTextField = JTextField("www.example.com", 20)
    private val configPanel = JPanel(FlowLayout(FlowLayout.LEFT))
    val isActive = JCheckBox("Activate CORS?")
    val inScope = JCheckBox("Only in scope?")
    val ignoreJSAndImages = JCheckBox("Ignore extensions:")
    val ignoreExtension = JTextField("ico, svg, js, css, png", 30)


    init {
        val clearButton = JButton("Clear CORS requests")
        val urlTextLabel = JLabel("URL for CORS requests:")

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

        loadPanel.add(clearButton)
        panel.leftComponent = configPanel
        panel.rightComponent = loadPanel
        panel.dividerSize = 0
    }


    private fun clearCors() {
        corsPanel.model.clearCors()
        corsPanel.requestViewer?.setMessage(ByteArray(0), true)
        corsPanel.responseViewer?.setMessage(ByteArray(0), false)
    }


}