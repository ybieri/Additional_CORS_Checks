package burp


import java.awt.Color
import java.net.URL

internal class CorsIssue(
    private val httpService: IHttpService,
    private val url: URL,
    private val httpMessages: Array<IHttpRequestResponse>,
    private val name: String,
    private val detail: String,
    private val severity: String,
    private val confidence: String,
    private val remediation: String

) : IScanIssue {
    override fun getUrl(): URL {
        return url
    }

    override fun getIssueName(): String {
        return name
    }

    override fun getIssueType(): Int {
        return 0
    }

    override fun getSeverity(): String {
        return severity
    }

    override fun getConfidence(): String {
        return confidence
    }

    override fun getIssueBackground(): String? {
        return null
    }

    override fun getRemediationBackground(): String? {
        return null
    }

    override fun getIssueDetail(): String {
        return detail
    }

    override fun getRemediationDetail(): String {
        return remediation
    }

    override fun getHttpMessages(): Array<IHttpRequestResponse> {
        return httpMessages
    }

    override fun getHttpService(): IHttpService {
        return httpService
    }
}

class IssueHelper(private val callbacks: IBurpExtenderCallbacks){

    fun getOrigin(response: IResponseInfo): String {
        for (respHeader in response.headers) {
            if (respHeader.startsWith("Access-Control-Allow-Origin:", ignoreCase = true)) {
                return respHeader.substringAfter(":").trim()
            }
        }
        return ""
    }

    fun generateIssue(color: Color, requestResponse: IHttpRequestResponse, url: URL) {
        val response = callbacks.helpers.analyzeResponse(requestResponse.response)

        val reflectedOrigin: String?
        val message = Array(1) { requestResponse }
        reflectedOrigin = getOrigin(response)


        // get current issues to avoid duplicates
        val issues = callbacks.getScanIssues(url.protocol + "://" + url.host)

        if (color == Color.RED) {
            val detail = "The following Origin was reflected: <b>\"$reflectedOrigin\"</b>.<br>Additionally, <b>\"Access-Control-Allow-Credentials: true\"</b> was set."
            val corsIssue = CorsIssue(
                requestResponse.httpService,
                url,
                message,
                "CORS*: Cross-origin resource sharing issue",
                detail,
                "High",
                "Certain",
                "Rather than programmatically verifying supplied origins, use a whitelist of trusted domains."
            )
            for(issue in issues){
                if(issue.issueDetail == detail){
                    return
                }
            }
            callbacks.addScanIssue(corsIssue)
        } else if (color == Color.YELLOW) {
            val detail = "The following Origin was reflected: <b>\"$reflectedOrigin\"</b>.<br>But, <b>\"Access-Control-Allow-Credentials: true\"<b> was <b>NOT</b> set."
            val corsIssue = CorsIssue(
                requestResponse.httpService,
                url,
                message,
                "CORS*: Cross-origin resource sharing issue",
                detail,
                "Low",
                "Certain",
                "Rather than programmatically verifying supplied origins, use a whitelist of trusted domains."
            )
            for(issue in issues){
                if(issue.issueDetail == detail){
                    return
                }
            }
            callbacks.addScanIssue(corsIssue)
        }
    }
}