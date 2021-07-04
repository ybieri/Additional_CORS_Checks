package burp

import java.io.PrintWriter
import java.util.*

// implement interceptor and modify requests
class HttpListener(private val callbacks: IBurpExtenderCallbacks, private val table: CorsPanel): IHttpListener {
    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {

        val stdout = PrintWriter(callbacks.stdout, true)
        stdout.println("Entered processHttpMessage")
        val helper = CorsHelper(callbacks)

        var requests = ArrayList<IHttpRequestResponse>()

        // avoid infinite loop -> ignore extension requests
        if(toolFlag != IBurpExtenderCallbacks.TOOL_EXTENDER){
            // add original request
            requests.add(messageInfo)

            // add all cors requests
            requests.addAll(helper.generateCorsRequests(messageInfo))
        }

        // process responses
        if (!messageIsRequest){
            table.addCorsRequestToTable(requests.toTypedArray())
        }

    }









}


