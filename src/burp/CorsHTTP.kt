package burp


import java.awt.Color

// implement interceptor and modify requests
class HttpListener(private val callbacks: IBurpExtenderCallbacks, private val table: CorsPanel) : IHttpListener {
    private val issueHelper = IssueHelper(callbacks)
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
                val userUrl = table.corsOptions.urlTextField.text
                val helper = CorsHelper(callbacks, userUrl)
                requests.addAll(helper.generateCorsRequests(messageInfo))

                for (req in requests) {
                    val url = analyzedRequest.url
                    val urlWithProto = url.protocol + "://" + url.host
                    val color = helper.evaluateColor(req, urlWithProto)
                    colors.add(color)
                    if (color != null) {
                        issueHelper.generateIssue(color, req, analyzedRequest.url)
                    }
                }
                table.addCorsRequestToTable(requests.toTypedArray(), colors.toTypedArray())
            }
        }
    }
}


