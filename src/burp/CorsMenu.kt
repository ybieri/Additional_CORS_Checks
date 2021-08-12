package burp

import java.awt.Color
import javax.swing.JMenuItem

class CorsMenu(private val table: CorsPanel) : IContextMenuFactory {
    override fun createMenuItems(invocation: IContextMenuInvocation?): MutableList<JMenuItem> {
        val menuItems: MutableList<JMenuItem> = arrayListOf()
        val requests = invocation?.selectedMessages
        val corsButton = JMenuItem("Add Requests to CORSair")
        val colors = Array<Color?>(requests!!.size) { _ -> null }

        corsButton.addActionListener {
            table.model.refreshCors()
            table.addCorsRequestToTable(requests, colors)
        }

        menuItems.add(corsButton)
        return menuItems
    }

}