package burp


import java.awt.Color


// implement interceptor and modify requests
class HttpListener(private val callbacks: IBurpExtenderCallbacks, private val table: CorsPanel) : IHttpListener {
    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
        // only intercept proxy requests
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) {
            return
        }

        val analyzedRequest = callbacks.helpers.analyzeRequest(messageInfo)

        val requests = ArrayList<IHttpRequestResponse>()
        val colors = ArrayList<Color?>()

        // if deactivated, don't perform any actions
        if (!table.corsOptions.isActive.isSelected) {
            return
        }

        if (!messageIsRequest) {
            val analyzedResponse = callbacks.helpers.analyzeResponse(messageInfo.response)

            // ignore JS and images if box is checked
            val ignoredMime = arrayOf("script", "PNG", "JPEG", "CSS")
            val extensions = table.corsOptions.ignoreExtension.text.replace(" ", "").split(",").toTypedArray()

            if (analyzedRequest.url.path.substringAfterLast(".").lowercase() in extensions) {
                return
            }

            if (table.corsOptions.ignoreJSAndImages.isSelected && analyzedResponse.statedMimeType in ignoredMime) {
                return
            }
        }


        // ignore if out of scope request and only in scope button selected
        if (table.corsOptions.inScope.isSelected && callbacks.isInScope(analyzedRequest.url) || !table.corsOptions.inScope.isSelected) {

            // add original request
            requests.add(messageInfo)

            // add all cors requests
            val url = table.corsOptions.urlTextField.text
            val helper = CorsHelper(callbacks, url)
            requests.addAll(helper.generateCorsRequests(messageInfo))

            for (req in requests) {
                val color = evaluateColor(req)
                colors.add(color)
                if (color != null) {
                    generateIssue(color, req, analyzedRequest)
                }
            }
        }
        // process responses
        if (!messageIsRequest) {
            table.addCorsRequestToTable(requests.toTypedArray(), colors.toTypedArray())
        }


    }

    private fun generateIssue(color: Color, requestResponse: IHttpRequestResponse, analyzedRequest: IRequestInfo) {
        var detail = ""
        val message = Array(1) { requestResponse }
        for (reqHeader in analyzedRequest.headers) {
            if (reqHeader.startsWith("Origin:", ignoreCase = true)) {
                detail = reqHeader
            }
        }

        if (color == Color.RED) {
            val corsIssue = CorsIssue(
                requestResponse.httpService,
                analyzedRequest.url,
                message,
                "CORSAir: Cross-origin resource sharing issue",
                "The following Origin header was reflected: <b>\"$detail\"</b>.<br>Additionally, \"Access-Control-Allow-Credentials: true\" was set.",
                "High",
                "Certain",
                "Rather than programmatically verifying supplied origins, use a whitelist of trusted domains."
            )
            callbacks.addScanIssue(corsIssue)
        } else if (color == Color.YELLOW) {
            val corsIssue = CorsIssue(
                requestResponse.httpService,
                analyzedRequest.url,
                message,
                "CORSAir: Cross-origin resource sharing issue",
                "The following Origin header was reflected: <b>\"$detail\"</b>.<br>But, \"Access-Control-Allow-Credentials: true\" was NOT set.",
                "Low",
                "Certain",
                "Rather than programmatically verifying supplied origins, use a whitelist of trusted domains."
            )
            callbacks.addScanIssue(corsIssue)
        }
    }

    // returns color of a response
    private fun evaluateColor(requestResponse: IHttpRequestResponse): Color? {
        val request = callbacks.helpers.analyzeRequest(requestResponse.request)
        val response = callbacks.helpers.analyzeResponse(requestResponse.response)

        var acac = false
        var acao = false
        var origin: String? = null

        // get origin
        for (reqHeader in request!!.headers) {
            if (reqHeader.startsWith("Origin:", ignoreCase = true)) {
                origin = reqHeader.substringAfter(":")
            }
        }

        // check if ACAC and/or ACAO are set
        for (respHeader in response!!.headers) {
            if (respHeader.contains("Access-Control-Allow-Credentials: true", ignoreCase = true)) {
                acac = true
            } else if (origin != null && respHeader.replace(" ", "")
                    .contains("Access-Control-Allow-Origin: $origin".replace(" ", ""), ignoreCase = true)
            ) {
                acao = true
            }
        }

        return if (acac && acao) {
            Color.RED
        } else if (acao) {
            Color.YELLOW
        } else {
            null
        }
    }


}


