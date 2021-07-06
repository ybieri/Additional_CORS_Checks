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
