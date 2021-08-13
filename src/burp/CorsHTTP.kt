package burp


import java.awt.Color
import java.io.PrintWriter
import java.net.URL


// implement interceptor and modify requests
class HttpListener(private val callbacks: IBurpExtenderCallbacks, private val table: CorsPanel) : IHttpListener {
    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {

        // only intercept proxy requests
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) {
            return
        }

        // if deactivated, don't perform any actions
        if (!table.corsOptions.isActive.isSelected) {
            return
        }

        // ignore extensions specified if box is checked
        val analyzedRequest = callbacks.helpers.analyzeRequest(messageInfo)
        val extensions = table.corsOptions.ignoreExtension.text.replace(" ", "").split(",").toTypedArray()
        if (analyzedRequest.url.path.substringAfterLast(".").lowercase() in extensions) {
            return
        }

        //ignore responses
        if (!messageIsRequest) {
            // ignore if out of scope request and only in scope button selected
            if (table.corsOptions.inScope.isSelected && callbacks.isInScope(analyzedRequest.url) || !table.corsOptions.inScope.isSelected) {
                val requests = ArrayList<IHttpRequestResponse>()
                val colors = ArrayList<Color?>()

                // add original request
                requests.add(messageInfo)

                // add all cors requests
                val url = table.corsOptions.urlTextField.text
                val helper = CorsHelper(callbacks, url)
                requests.addAll(helper.generateCorsRequests(messageInfo))

                for (req in requests) {
                    val color = helper.evaluateColor(req)
                    colors.add(color)
                    if (color != null) {
                        generateIssue(color, req, analyzedRequest.url)
                    }
                }
                table.addCorsRequestToTable(requests.toTypedArray(), colors.toTypedArray())
            }
        }
    }

    private fun generateIssue(color: Color, requestResponse: IHttpRequestResponse, url: URL) {
        val response = callbacks.helpers.analyzeResponse(requestResponse.response)

        var detail : String? = ""
        val message = Array(1) { requestResponse }
        for (respHeader in response.headers) {
            if (respHeader.startsWith("Access-Control-Allow-Origin:", ignoreCase = true)) {
                detail = respHeader.substringAfter(":").trim()
            }
        }


        if (color == Color.RED) {
            val corsIssue = CorsIssue(
                requestResponse.httpService,
                url,
                message,
                "CORSair: Cross-origin resource sharing issue",
                "The following Origin was reflected: <b>\"$detail\"</b>.<br>Additionally, <b>\"Access-Control-Allow-Credentials: true\"</b> was set.",
                "High",
                "Certain",
                "Rather than programmatically verifying supplied origins, use a whitelist of trusted domains."
            )
            callbacks.addScanIssue(corsIssue)
        } else if (color == Color.YELLOW) {
            val corsIssue = CorsIssue(
                requestResponse.httpService,
                url,
                message,
                "CORSair: Cross-origin resource sharing issue",
                "The following Origin was reflected: <b>\"$detail\"</b>.<br>But, <b>\"Access-Control-Allow-Credentials: true\"<b> was <b>NOT</b> set.",
                "Low",
                "Certain",
                "Rather than programmatically verifying supplied origins, use a whitelist of trusted domains."
            )
            callbacks.addScanIssue(corsIssue)
        }
    }
}


