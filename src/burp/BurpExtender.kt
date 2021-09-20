package burp

import java.io.PrintWriter


@Suppress("unused") // Remove warning, the class will be used by burp
class BurpExtender : IBurpExtender {


    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {


        //this.callbacks = callbacks
        val tab = CorsTab(callbacks)
        val table = tab.corsTable
        val menuItem = CorsMenu(table)
        HttpListener(callbacks, table)

        callbacks.setExtensionName("CORS*")
        val stdout = PrintWriter(callbacks.stdout, true)
        stdout.println("CORS* loaded!")

        // create new Burp tab
        callbacks.addSuiteTab(tab)
        // create menu item to send to CORS
        callbacks.registerContextMenuFactory(menuItem)
        // init a new HTTP listener
        callbacks.registerHttpListener(HttpListener(callbacks, table))
    }
}