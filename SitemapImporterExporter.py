import xml.dom.minidom as minidom
from burp import IBurpExtender, ITab, IHttpRequestResponse, IHttpService
from javax.swing import JPanel, JButton, JFileChooser, JScrollPane, JTextArea, JCheckBox
from java.awt import BorderLayout
import java.net.URL as URL
import urlparse
import os
import base64
import xml.etree.ElementTree as ET


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

        self.mainPanel.add(buttonPanel, BorderLayout.SOUTH)
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
                        parsed_url = urlparse.urlparse(url)
                        host = parsed_url.hostname
                        port = parsed_url.port if parsed_url.port else (
                            443 if parsed_url.scheme == "https" else 80)
                        protocol = parsed_url.scheme

                        if self.inScopeCheckBox.isSelected():
                            if self.callbacks.isInScope(URL(url)):
                                self.addToSiteMap(url, item[1], item[2], item[3], item[4])
                        else:
                            self.addToSiteMap(url, item[1], item[2], item[3], item[4])

            self.textArea.append("\n[+] Summary\n")
            for summary in summaries:
                self.printSummary(summary)

            self.textArea.append("[+] Done\n")

    def onSaveButtonClick(self, event):
        fileChooser = JFileChooser()
        returnValue = fileChooser.showSaveDialog(self.mainPanel)

        if returnValue == JFileChooser.APPROVE_OPTION:
            saveFile = fileChooser.getSelectedFile()
            self.saveSiteMapToFile(saveFile.getAbsolutePath())

    def addToSiteMap(self, url, request, response, color="", comment=""):
        requestResponse = HttpRequestResponse(
            self.helper.base64Decode(request),
            self.helper.base64Decode(response),
            HttpService(url),
            color,
            comment
        )
        self.callbacks.addToSiteMap(requestResponse)

    def saveSiteMapToFile(self, file_path):
        siteMapItems = self.callbacks.getSiteMap("")
        root = ET.Element("items")

        for item in siteMapItems:

            protocol = item.getHttpService().getProtocol()
            host = item.getHttpService().getHost()
            port = str(item.getHttpService().getPort())
            url = protocol + "://" + host
            if (protocol == "https" and port != "443") or (protocol == "http" and port != "80"):
                url += ":{}".format(port)
            if self.inScopeCheckBox.isSelected() and not self.callbacks.isInScope(URL(url)):
                continue
            request = base64.b64encode(item.getRequest()).decode('utf-8')
            response = item.getResponse()
            response = base64.b64encode(response).decode(
                'utf-8') if response else ""
            comment = item.getComment()
            color = item.getHighlight()

            itemElement = ET.SubElement(root, "item")
            ET.SubElement(itemElement, "time").text = ""
            ET.SubElement(itemElement, "url").text = url
            hostElement = ET.SubElement(itemElement, "host")
            hostElement.text = item.getHttpService().getHost()
            hostElement.set('ip', '')
            ET.SubElement(itemElement, "port").text = str(
                item.getHttpService().getPort())
            ET.SubElement(
                itemElement, "protocol").text = item.getHttpService().getProtocol()
            ET.SubElement(itemElement, "method").text = ""
            ET.SubElement(itemElement, "path").text = ""
            ET.SubElement(itemElement, "extension").text = ""
            requestElement = ET.SubElement(itemElement, "request")
            requestElement.text = request
            requestElement.set('base64', 'true')
            ET.SubElement(itemElement, "status").text = ""
            ET.SubElement(itemElement, "responselength").text = str(
                len(response))
            ET.SubElement(itemElement, "mimetype").text = ""
            responseElement = ET.SubElement(itemElement, "response")
            responseElement.text = response
            responseElement.set('base64', 'true')
            ET.SubElement(itemElement, "comment").text = comment
            ET.SubElement(itemElement, "color").text = color

        tree = ET.ElementTree(root)
        tree.write(file_path)
        self.textArea.append("Sitemap saved to {}\n".format(file_path))

    def printSummary(self, summary):
        self.textArea.append("- File: {}\n".format(summary["file_name"]))
        self.textArea.append(
            "+ {} items successfully parsed\n".format(summary["item_count"]))

        if summary["skip_item_count"] > 0:
            self.textArea.append("+ {} items skipped due to response size > {} bytes\n".format(
                summary["skip_item_count"], summary["response_len_limit"]))
            for item in summary["skip_items"]:
                self.textArea.append(
                    "+++ skipped item: {}, response size: {}\n".format(item[0], item[1]))
        self.textArea.append("\n")


class XMLParser:
    def __init__(self, file_path, verbose=True):
        self.items = []
        self.skip_items = []
        self.response_len_limit = 2000000
        self.verbose = verbose
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)

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
        self._print("Begin parsing {}", [self.file_name])

        try:
            dom = minidom.parse(self.file_path)
            items = dom.getElementsByTagName("item")

            for item in items:
                url = self._get_tag_text(item, "url")
                request = self._get_tag_text(item, "request")
                response = self._get_tag_text(item, "response")
                color = self._get_tag_text(item, "color")
                comment = self._get_tag_text(item, "comment")

                responselength_elem = item.getElementsByTagName("responselength")[0]
                if responselength_elem:
                    response_len = int(
                        responselength_elem.firstChild.data.strip())
                    if response_len > self.response_len_limit:
                        self.skip_items.append((url, response_len))
                        self._print(
                            "+ Skip this item because response size is too large: {} bytes", (response_len))
                        continue

                self.items.append([url, request, response, color, comment])
                self._print("- {}. url: {}", [len(self.items), url])

            self._print("Finish parsing: {}", [self.file_name])

        except Exception as e:
            print("Error parsing XML file {}: {}".format(self.file_name, str(e)))

    def _get_tag_text(self, element, tag_name):
        tag = element.getElementsByTagName(tag_name)[0]
        if tag.firstChild:
            return tag.firstChild.data.strip()
        return ""


class HttpService(IHttpService):

    def __init__(self, url):
        x = urlparse.urlparse(url)
        if x.scheme in ("http", "https"):
            self._protocol = x.scheme
        else:
            raise ValueError()
        self._host = x.hostname if x.hostname else ""
        self._port = x.port if x.port else (
            80 if self._protocol == "http" else 443)

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

