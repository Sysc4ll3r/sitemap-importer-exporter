from burp import IBurpExtender, ITab, IHttpRequestResponse, IHttpService
from javax.swing import JPanel, JButton, JFileChooser, JScrollPane, JTextArea, JCheckBox, JOptionPane
from java.awt import BorderLayout
from java.net import URL
import java.util.Base64 as Base64
import java.io.File as File
from javax.xml.parsers import DocumentBuilderFactory, DocumentBuilder
from javax.xml.transform import TransformerFactory, OutputKeys
from javax.xml.transform.dom import DOMSource
from javax.xml.transform.stream import StreamResult
from org.w3c.dom import Document, Element


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.callbacks.setExtensionName("Sitemap Importer/Exporter")
        self.helper = callbacks.getHelpers()

        self.mainPanel = JPanel(BorderLayout())
        self.textArea = JTextArea()
        scrollPane = JScrollPane(self.textArea)
        self.mainPanel.add(scrollPane, BorderLayout.CENTER)

        self.inScopeCheckBox = JCheckBox("In Scope Only")

        loadButton = JButton(
            "Load Sitemaps", actionPerformed=self.onLoadButtonClick)
        saveButton = JButton(
            "Save Sitemaps", actionPerformed=self.onSaveButtonClick)

        buttonPanel = JPanel()
        buttonPanel.add(loadButton)
        buttonPanel.add(saveButton)
        buttonPanel.add(self.inScopeCheckBox)

        self.mainPanel.add(buttonPanel, BorderLayout.NORTH)
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Sitemap Importer/Exporter"

    def getUiComponent(self):
        return self.mainPanel

    def onLoadButtonClick(self, event):
        fileChooser = JFileChooser()
        fileChooser.setMultiSelectionEnabled(True)
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        returnValue = fileChooser.showOpenDialog(self.mainPanel)

        if returnValue == JFileChooser.APPROVE_OPTION:
            files = fileChooser.getSelectedFiles()
            summaries = []
            for file in files:
                if file.getName().endswith(".xml"):
                    file_path = file.getAbsolutePath()

                    parser = XMLParser(file_path)
                    parser.parse()
                    summaries.append(parser.getSummary())

                    for item in parser.getItems():
                        url = item[0]
                        parsed_url = URL(url)
                        host = parsed_url.getHost()
                        port = parsed_url.getPort() if parsed_url.getPort() != -1 else (
                            443 if parsed_url.getProtocol() == "https" else 80)
                        protocol = parsed_url.getProtocol()

                        if self.inScopeCheckBox.isSelected():
                            if self.callbacks.isInScope(URL(url)):
                                self.addToSiteMap(
                                    url, item[1], item[2], item[3], item[4])
                        else:
                            self.addToSiteMap(
                                url, item[1], item[2], item[3], item[4])

            summary_message = self.createSummaryMessage(summaries)
            JOptionPane.showMessageDialog(
                self.mainPanel, summary_message, "Summary", JOptionPane.INFORMATION_MESSAGE)

    def onSaveButtonClick(self, event):
        fileChooser = JFileChooser()
        returnValue = fileChooser.showSaveDialog(self.mainPanel)

        if returnValue == JFileChooser.APPROVE_OPTION:
            saveFile = fileChooser.getSelectedFile()
            self.saveSiteMapToFile(saveFile.getAbsolutePath())

    def addToSiteMap(self, url, request, response, color="", comment=""):
        requestResponse = HttpRequestResponse(
            Base64.getDecoder().decode(request),
            Base64.getDecoder().decode(response),
            HttpService(url),
            color,
            comment
        )
        self.callbacks.addToSiteMap(requestResponse)

    def saveSiteMapToFile(self, file_path):
        siteMapItems = self.callbacks.getSiteMap("")
        factory = DocumentBuilderFactory.newInstance()
        builder = factory.newDocumentBuilder()
        document = builder.newDocument()

        root = document.createElement("items")
        document.appendChild(root)

        for item in siteMapItems:
            protocol = item.getHttpService().getProtocol()
            host = item.getHttpService().getHost()
            port = str(item.getHttpService().getPort())
            url = protocol + "://" + host
            if (protocol == "https" and port != "443") or (protocol == "http" and port != "80"):
                url += ":{}".format(port)
            if self.inScopeCheckBox.isSelected() and not self.callbacks.isInScope(URL(url)):
                continue
            request = Base64.getEncoder().encodeToString(item.getRequest())
            response = item.getResponse()
            response = Base64.getEncoder().encodeToString(response) if response else ""
            comment = item.getComment()
            color = item.getHighlight()

            itemElement = document.createElement("item")
            root.appendChild(itemElement)

            self.createElementWithText(document, itemElement, "time", "")
            self.createElementWithText(document, itemElement, "url", url)
            hostElement = self.createElementWithText(
                document, itemElement, "host", item.getHttpService().getHost())
            hostElement.setAttribute("ip", "")
            self.createElementWithText(
                document, itemElement, "port", str(item.getHttpService().getPort()))
            self.createElementWithText(
                document, itemElement, "protocol", item.getHttpService().getProtocol())
            self.createElementWithText(document, itemElement, "method", "")
            self.createElementWithText(document, itemElement, "path", "")
            self.createElementWithText(document, itemElement, "extension", "")
            requestElement = self.createElementWithText(
                document, itemElement, "request", request)
            requestElement.setAttribute("base64", "true")
            self.createElementWithText(document, itemElement, "status", "")
            self.createElementWithText(
                document, itemElement, "responselength", str(len(response)))
            self.createElementWithText(document, itemElement, "mimetype", "")
            responseElement = self.createElementWithText(
                document, itemElement, "response", response)
            responseElement.setAttribute("base64", "true")
            self.createElementWithText(
                document, itemElement, "comment", comment)
            self.createElementWithText(document, itemElement, "color", color)

        transformer = TransformerFactory.newInstance().newTransformer()
        transformer.setOutputProperty(OutputKeys.INDENT, "yes")
        transformer.setOutputProperty(
            "{http://xml.apache.org/xslt}indent-amount", "2")
        source = DOMSource(document)
        result = StreamResult(File(file_path))
        transformer.transform(source, result)

        JOptionPane.showMessageDialog(self.mainPanel, "Sitemap saved to {}".format(
            file_path), "Information", JOptionPane.INFORMATION_MESSAGE)

    def createElementWithText(self, document, parent, tag_name, text):
        element = document.createElement(tag_name)
        element.appendChild(document.createTextNode(text))
        parent.appendChild(element)
        return element

    def createSummaryMessage(self, summaries):
        message = "[+] Summary\n"
        for summary in summaries:
            message += "- File: {}\n".format(summary["file_name"])
            message += "+ {} items successfully parsed\n".format(
                summary["item_count"])
            if summary["skip_item_count"] > 0:
                message += "+ {} items skipped due to response size > {} bytes\n".format(
                    summary["skip_item_count"], summary["response_len_limit"])
                for item in summary["skip_items"]:
                    message += "+++ skipped item: {}, response size: {}\n".format(
                        item[0], item[1])
            message += "\n"
        message += "[+] Done\n"
        return message


class XMLParser:
    def __init__(self, file_path, verbose=True):
        self.items = []
        self.skip_items = []
        self.response_len_limit = 2000000
        self.verbose = verbose
        self.file_path = file_path
        self.file_name = File(file_path).getName()

    def getItems(self):
        return self.items

    def getSkipItems(self):
        return self.skip_items

    def getSummary(self):
        return {
            "file_name": self.file_name,
            "item_count": len(self.items),
            "skip_item_count": len(self.skip_items),
            "skip_items": self.skip_items,
            "response_len_limit": self.response_len_limit,
        }

    def _print(self, message, params):
        if self.verbose:
            print(message.format(*params))

    def parse(self):
        try:
            factory = DocumentBuilderFactory.newInstance()
            builder = factory.newDocumentBuilder()
            document = builder.parse(File(self.file_path))

            items = document.getElementsByTagName("item")

            for i in range(items.getLength()):
                item = items.item(i)
                url = self._get_tag_text(item, "url")
                request = self._get_tag_text(item, "request")
                response = self._get_tag_text(item, "response")
                color = self._get_tag_text(item, "color")
                comment = self._get_tag_text(item, "comment")

                response_len_elem = item.getElementsByTagName(
                    "responselength").item(0)
                if response_len_elem:
                    response_len = int(
                        response_len_elem.getTextContent().strip())
                    if response_len > self.response_len_limit:
                        self.skip_items.append((url, response_len))
                        continue

                self.items.append([url, request, response, color, comment])

        except Exception as e:
            print("Error parsing XML file {}: {}".format(self.file_name, str(e)))

    def _get_tag_text(self, element, tag_name):
        tag = element.getElementsByTagName(tag_name).item(0)
        if tag and tag.getFirstChild():
            return tag.getFirstChild().getNodeValue().strip()
        return ""


class HttpService(IHttpService):

    def __init__(self, url):
        x = URL(url)
        self._protocol = x.getProtocol()
        self._host = x.getHost()
        self._port = x.getPort() if x.getPort() != - \
            1 else (80 if self._protocol == "http" else 443)

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol

    def __str__(self):
        return "protocol: {}, host: {}, port: {}".format(self._protocol, self._host, self._port)


class HttpRequestResponse(IHttpRequestResponse):

    def __init__(self, request, response, httpService, color, comment):
        self.setRequest(request)
        self.setResponse(response)
        self.setHttpService(httpService)
        self.setHighlight(color)
        self.setComment(comment)

    def getRequest(self):
        return self.req

    def getResponse(self):
        return self.resp

    def getHttpService(self):
        return self.serv

    def getComment(self):
        return self.cmt

    def getHighlight(self):
        return self.color

    def setHighlight(self, color):
        self.color = color

    def setComment(self, cmt):
        self.cmt = cmt

    def setHttpService(self, httpService):
        self.serv = httpService

    def setRequest(self, message):
        self.req = message

    def setResponse(self, message):
        self.resp = message

