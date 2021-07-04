package burp

import java.io.PrintWriter
import java.util.*

// implement interceptor and modify requests
class HttpListener(private val callbacks: IBurpExtenderCallbacks, private val table: CorsPanel): IHttpListener {
    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {

        val stdout = PrintWriter(callbacks.stdout, true)
        val analyzedRequest = callbacks.helpers.analyzeRequest(messageInfo)

        var requests = ArrayList<IHttpRequestResponse>()

        // if deactivated, don't perform any actions
        if(!table.corsOptions.isActive.isSelected){
            return
        }

        if (!messageIsRequest) {
            val analyzedResponse = callbacks.helpers.analyzeResponse(messageInfo.response)

            // ignore JS and images if box is checked
            val ignoredMime = arrayOf("script", "PNG", "JPEG", "CSS")
            val ignoredExtensions = arrayOf("ico", "svg")


            stdout.println(analyzedRequest.url.path.substringAfterLast("."))
            if(analyzedRequest.url.path.substringAfterLast(".") in ignoredExtensions){
                return
            }

            if (table.corsOptions.ignoreJSAndImages.isSelected && analyzedResponse.statedMimeType in ignoredMime){
                return
            }
        }

        // avoid infinite loop -> ignore extension requests
        if(toolFlag != IBurpExtenderCallbacks.TOOL_EXTENDER){

            // ignore if out of scope request and only in scope button selected
            if(table.corsOptions.inScope.isSelected && callbacks.isInScope(analyzedRequest.url) || !table.corsOptions.inScope.isSelected){

                // add original request
                requests.add(messageInfo)

                // add all cors requests
                val url = table.corsOptions.urlTextField.text
                val helper = CorsHelper(callbacks, url)
                requests.addAll(helper.generateCorsRequests(messageInfo))
            }
        }

        // process responses
        if (!messageIsRequest){
            table.addCorsRequestToTable(requests.toTypedArray())
        }

    }
}


