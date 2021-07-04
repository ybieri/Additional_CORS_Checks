package burp
import java.io.PrintWriter

@Suppress("unused") // Remove warning, the class will be used by burp
class BurpExtender : IBurpExtender {

    //lateinit var callbacks : IBurpExtenderCallbacks
    //lateinit var table : CorsPanel

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        // Let's wrap stdout and stderr in PrintWriter with auto flush
        val stdout = PrintWriter(callbacks.stdout, true)
        //val stderr = PrintWriter(callbacks.stderr, true)

        //this.callbacks = callbacks
        val tab = CorsTab(callbacks)
        val table = tab.corsTable
        val menuItem = CorsMenu(table)
        HttpListener(callbacks, table)

        // initialize HttpListener


        callbacks.setExtensionName("CORS")
        stdout.println("CORS loaded!")

        // create new Burp tab
        callbacks.addSuiteTab(tab)
        // create menu item to send to CORS
        callbacks.registerContextMenuFactory(menuItem)
        // init a new HTTP listener
        callbacks.registerHttpListener(HttpListener(callbacks, table))
    }

/*
    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {

        val stdout = PrintWriter(callbacks.stdout, true)
        stdout.println("Entered processHttpMessage")

        val analyzedRequest = callbacks.helpers.analyzeRequest(messageInfo)
        val items = Array<IHttpRequestResponse>(1) { messageInfo }
        table.addCorsRequest(items)

    }
    */
}