package burp
import java.io.PrintWriter


@Suppress("unused") // Remove warning, the class will be used by burp
class BurpExtender : IBurpExtender, IScannerCheck {

    private var callbacks : IBurpExtenderCallbacks? = null
    lateinit var issues : ArrayList<IScannerCheck?>

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        // Let's wrap stdout and stderr in PrintWriter with auto flush
        val stdout = PrintWriter(callbacks.stdout, true)
        //val stderr = PrintWriter(callbacks.stderr, true)

        this.callbacks = callbacks

        //this.callbacks = callbacks
        val tab = CorsTab(callbacks)
        val table = tab.corsTable
        val menuItem = CorsMenu(table)
        HttpListener(callbacks, table)

        callbacks.setExtensionName("CORS")
        stdout.println("CORS loaded!")

        // create new Burp tab
        callbacks.addSuiteTab(tab)
        // create menu item to send to CORS
        callbacks.registerContextMenuFactory(menuItem)
        // init a new HTTP listener
        callbacks.registerHttpListener(HttpListener(callbacks, table))

        //callbacks.registerScannerCheck(this) // TODO: needs some work to see if this is doable
    }

    override fun doPassiveScan(baseRequestResponse: IHttpRequestResponse?): MutableList<IScanIssue>? {

        val stdout = PrintWriter(this.callbacks?.stdout, true)
        stdout.println("Issue stuff")

        val issues = ArrayList<IScanIssue>(1)
        val analyzedRequest = this.callbacks?.helpers?.analyzeRequest(baseRequestResponse)
        val message = Array<IHttpRequestResponse>(1){baseRequestResponse!!}
        val corsIssue = CorsIssue(
            baseRequestResponse!!.httpService,
            analyzedRequest!!.url,
            message,
            "Cors Issue",
            "Detail TODO",
            "High",
            "Certain",
            "Remediation TODO"

        )
        issues.add(corsIssue)
        return issues
    }

    override fun doActiveScan(
        baseRequestResponse: IHttpRequestResponse?,
        insertionPoint: IScannerInsertionPoint?
    ): MutableList<IScanIssue>? {
        return ArrayList()
    }

    override fun consolidateDuplicateIssues(existingIssue: IScanIssue?, newIssue: IScanIssue?): Int {
        return if(existingIssue!!.issueName.equals(newIssue!!.issueName)){
            -1
        } else {
            0
        }
    }
}