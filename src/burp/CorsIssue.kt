package burp

import java.io.PrintWriter
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

    val host: String?
        get() = null
    val port: Int
        get() = 0
    val protocol: String?
        get() = null
}


class CorsIssueScanner(private val callbacks: IBurpExtenderCallbacks) : IScannerCheck{
    override fun doPassiveScan(baseRequestResponse: IHttpRequestResponse?): MutableList<IScanIssue>? {

        val stdout = PrintWriter(callbacks.stdout, true)
        stdout.println("Issue stuff")

        val issues = ArrayList<IScanIssue>()
        val analyzedRequest = callbacks.helpers.analyzeRequest(baseRequestResponse)
        val message = Array<IHttpRequestResponse>(1){baseRequestResponse!!}
            val corsIssue = CorsIssue(
                baseRequestResponse!!.httpService,
                analyzedRequest.url,
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