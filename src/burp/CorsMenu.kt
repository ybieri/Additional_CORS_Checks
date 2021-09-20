package burp

import java.awt.Color
import javax.swing.JMenuItem

class CorsMenu(private val table: CorsPanel) : IContextMenuFactory {
    override fun createMenuItems(invocation: IContextMenuInvocation?): MutableList<JMenuItem> {
        val menuItems: MutableList<JMenuItem> = arrayListOf()
        val requests = invocation?.selectedMessages
        val corsButton = JMenuItem("Add Requests to CORSA*")
        val colors = requests?.let { Array<Color?>(it.size) { _ -> null } }

        corsButton.addActionListener {
            table.model.refreshCors()
            if (requests != null && colors != null) {
                table.addCorsRequestToTable(requests, colors)
            }
        }

        menuItems.add(corsButton)
        return menuItems
    }

}