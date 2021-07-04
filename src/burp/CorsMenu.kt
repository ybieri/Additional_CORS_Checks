package burp

import javax.swing.JMenuItem

class CorsMenu(private val table: CorsPanel) : IContextMenuFactory {
    override fun createMenuItems(invocation: IContextMenuInvocation?): MutableList<JMenuItem> {
        val menuItems: MutableList<JMenuItem> = arrayListOf()
        val requests = invocation?.selectedMessages
        val corsButton = JMenuItem("Add to CORS")
        corsButton.addActionListener {
            if (requests != null) {
                table.model.refreshCors()
                table.addCorsRequestToTable(requests)
            }
        }

        menuItems.add(corsButton)
        return menuItems
    }

}