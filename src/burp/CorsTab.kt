package burp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext
import java.awt.Color
import java.awt.Component
import java.awt.FlowLayout
import java.net.URL
import javax.swing.*
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.TableRowSorter


class CorsTab(callbacks: IBurpExtenderCallbacks) : ITab {
    val corsTable = CorsPanel(callbacks)
    override fun getTabCaption() = "CORSAir"
    override fun getUiComponent() = corsTable.panel

}

data class CorsObj(
    val requestResponse: IHttpRequestResponse,
    val host: String,
    val url: URL,
    val method: String,
    val statusCode: String,
    val length: String,
    val mimeType: String,
    var color: Color?
)

class CorsPanel(private val callbacks: IBurpExtenderCallbacks) {
    val corsOptions = CorsOptions(this)
    val model = CorsModel()
    val table = JTable(model)

    private val messageEditor = MessageEditor(callbacks)
    val requestViewer: IMessageEditor? = messageEditor.requestViewer
    val responseViewer: IMessageEditor? = messageEditor.responseViewer
    val panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
    val rowSorter = TableRowSorter(model)


    private val repeatInTable = JCheckBox("Add repeated request to table")

    //serious TODO:

    init {

        // black magic with Java Tables
        table.setDefaultRenderer(Any::class.java, object : DefaultTableCellRenderer() {
            override fun getTableCellRendererComponent(
                table: JTable,
                value: Any,
                isSelected: Boolean,
                hasFocus: Boolean,
                row: Int,
                column: Int
            ): Component {
                val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
                if (!isSelected) {
                    c.background = model.getColor(row)
                }
                return c
            }
        })

        CorsActions(this, callbacks)
        table.autoResizeMode = JTable.AUTO_RESIZE_OFF
        table.columnModel.getColumn(0).preferredWidth = 30 // ID
        table.columnModel.getColumn(1).preferredWidth = 245 // Host
        table.columnModel.getColumn(2).preferredWidth = 825 // URL
        table.columnModel.getColumn(3).preferredWidth = 50 // Method
        table.columnModel.getColumn(4).preferredWidth = 50 // Status
        table.columnModel.getColumn(5).preferredWidth = 50 // Length
        table.columnModel.getColumn(6).preferredWidth = 50 // MIME
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        table.rowSorter = rowSorter
        table.autoscrolls = true


        table.selectionModel.addListSelectionListener {
            if (table.selectedRow != -1) {
                val displayedCors = model.displayedCors
                val selectedRow = table.convertRowIndexToModel(table.selectedRow)
                val requestResponse = displayedCors[selectedRow].requestResponse
                messageEditor.requestResponse = requestResponse
                requestViewer?.setMessage(requestResponse.request, true)
                responseViewer?.setMessage(requestResponse.response ?: ByteArray(0), false)
            }
        }

        val repeatPanel = JPanel(FlowLayout(FlowLayout.LEFT))

        val repeatButton = JButton("Send CORS requests for selected entry")
        repeatButton.addActionListener { repeatRequest() }
        repeatInTable.isSelected = true

        repeatPanel.add(repeatButton)
        //repeatPanel.add(repeatInTable)

        val corsTable = JScrollPane(table)
        val reqResSplit =
            JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer?.component, responseViewer?.component)
        reqResSplit.resizeWeight = 0.5

        val repeatReqSplit =
            JSplitPane(JSplitPane.VERTICAL_SPLIT, repeatPanel, reqResSplit)

        val corsOptSplit =
            JSplitPane(JSplitPane.VERTICAL_SPLIT, corsOptions.panel, corsTable)

        panel.topComponent = corsOptSplit
        panel.bottomComponent = repeatReqSplit
        panel.resizeWeight = 0.5
        callbacks.customizeUiComponent(panel)
    }


    fun addCorsRequestToTable(requestsResponses: Array<IHttpRequestResponse>, colors: Array<Color?>) {
        for (i in requestsResponses.indices) {
            createCors(requestsResponses[i], colors[i])
        }
    }

    private fun createCors(
        requestResponse: IHttpRequestResponse, color: Color?
    ) {

        val savedRequestResponse = callbacks.saveBuffersToTempFiles(requestResponse)
        val requestInfo = callbacks.helpers.analyzeRequest(requestResponse)
        val response = if (requestResponse.response != null) {
            callbacks.helpers.analyzeResponse(requestResponse.response)
        } else {
            null
        }
        val host = requestInfo.url.host
        val url = requestInfo.url
        val method = requestInfo?.method ?: ""
        val statusCode = response?.statusCode?.toString() ?: ""
        val length = requestResponse.response?.size?.toString() ?: ""
        val mimeType = response?.inferredMimeType ?: ""

        val cors = CorsObj(
            savedRequestResponse,
            host,
            url,
            method,
            statusCode,
            length,
            mimeType,
            color
        )
        model.addCors(cors)

    }


    private fun repeatRequest() {
        model.refreshCors()

        GlobalScope.launch(Dispatchers.IO) {

            val requestResponse = try {
                callbacks.makeHttpRequest(messageEditor.httpService, requestViewer?.message)
            } catch (e: java.lang.RuntimeException) {
                RequestResponse(requestViewer?.message, null, messageEditor.httpService)
            }

            val url = corsOptions.urlTextField.text
            val helper = CorsHelper(callbacks, url)
            val requests = helper.generateCorsRequests(requestResponse)

            withContext(Dispatchers.Swing) {
                SwingUtilities.invokeLater {
                    for (request in requests) {
                        responseViewer?.setMessage(request.response ?: ByteArray(0), false)
                        createCors(request, Color.ORANGE)// TODO: create func
                    }
                }
            }
        }
    }
}

class MessageEditor(callbacks: IBurpExtenderCallbacks) : IMessageEditorController {
    var requestResponse: IHttpRequestResponse? = null

    val requestViewer: IMessageEditor? = callbacks.createMessageEditor(this, true)
    val responseViewer: IMessageEditor? = callbacks.createMessageEditor(this, false)

    override fun getResponse(): ByteArray = requestResponse?.response ?: ByteArray(0)

    override fun getRequest(): ByteArray? = requestResponse?.request

    override fun getHttpService(): IHttpService? = requestResponse?.httpService
}

class CorsModel : AbstractTableModel() {
    private val columns =
        listOf(
            "ID",
            "Host",
            "URL",
            "Method",
            "Status",
            "Length",
            "MIME"
        )
    private var corsObjArr: MutableList<CorsObj> = ArrayList()
    var displayedCors: MutableList<CorsObj> = ArrayList()
        private set

    override fun getRowCount(): Int = displayedCors.size

    override fun getColumnCount(): Int = columns.size

    override fun getColumnName(column: Int): String {
        return columns[column]
    }

    //TODO change
    override fun getColumnClass(columnIndex: Int): Class<*> {
        return when (columnIndex) {
            0 -> java.lang.Integer::class.java
            1 -> String::class.java
            2 -> String::class.java
            3 -> String::class.java
            4 -> String::class.java
            5 -> String::class.java
            6 -> String::class.java
            else -> throw RuntimeException()
        }
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val cors = displayedCors[rowIndex]

        return when (columnIndex) {
            0 -> rowIndex
            1 -> cors.host
            2 -> cors.url.toString()
            3 -> cors.method
            4 -> cors.statusCode
            5 -> cors.length
            6 -> cors.mimeType
            else -> ""
        }
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean {
        return false
    }
    /*
    override fun setValueAt(value: Any?, rowIndex: Int, colIndex: Int) {
        val cors: Cors = corsarr[rowIndex]
        //refreshCors()
    }
    */

    fun addCors(corsObj: CorsObj) {
        corsObjArr.add(corsObj)
        displayedCors = corsObjArr
        fireTableRowsInserted(displayedCors.lastIndex, displayedCors.lastIndex)
        corsObj.color?.let { setColor(displayedCors.lastIndex, it) }
        refreshCors()
    }

    fun clearCors() {
        corsObjArr.clear()
        refreshCors()
    }

    fun refreshCors() {
        fireTableDataChanged()
    }

    fun getColor(row: Int): Color? {
        return corsObjArr[row].color
    }

    private fun setColor(row: Int, color: Color) {
        corsObjArr[row].color = color
    }

}

class RequestResponse(private var req: ByteArray?, private var res: ByteArray?, private var service: IHttpService?) :
    IHttpRequestResponse {

    override fun getComment(): String? = null

    override fun setComment(comment: String?) {}

    override fun getRequest(): ByteArray? = req

    override fun getHighlight(): String? = null

    override fun getHttpService(): IHttpService? = service

    override fun getResponse(): ByteArray? = res

    override fun setResponse(message: ByteArray?) {
        res = message
    }

    override fun setRequest(message: ByteArray?) {
        req = message
    }

    override fun setHttpService(httpService: IHttpService?) {
        service = httpService
    }

    override fun setHighlight(color: String?) {}
}

