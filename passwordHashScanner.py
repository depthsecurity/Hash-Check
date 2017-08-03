'''
Written by: Brian Berg - www.github.com/xexzy
hashMaker.py is used generate a file of hashes.
the format of the of hashes is [hash]:[algorithm] example: aGFzaGNhdA==:Base64

'''

from burp import IBurpExtender
from burp import ITab
from burp import IScannerCheck
from burp import IScanIssue
#from java.net import URL
from java.awt import Dimension
from javax import swing
import os.path
from array import array
from java.lang import Runnable
#from java.io import PrintWriter

class BurpExtender(IBurpExtender, ITab, IScannerCheck, IScanIssue):
	def registerExtenderCallbacks(self, callbacks):
		self.hashes = {}
		#self._stdout = PrintWriter(callbacks.getStdout(), True)
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		self._callbacks.setExtensionName("Password Hash Scanner")
		self._callbacks.registerScannerCheck(self)
		self._fileLocation = None
		self._jPanel = swing.JPanel()
		boxVertical = swing.Box.createVerticalBox()
		boxHorizontal = swing.Box.createHorizontalBox()
		getFileButton = swing.JButton('Open hashout.txt',actionPerformed=self.getFile)
		self._fileText = swing.JTextArea("", 1, 50)
		boxHorizontal.add(getFileButton)
		boxHorizontal.add(self._fileText)
		boxVertical.add(boxHorizontal)
		boxHorizontal = swing.Box.createHorizontalBox()
		submitQueryButton = swing.JButton('Parse hash file',actionPerformed=self.hashParse)
		boxHorizontal.add(submitQueryButton)
		boxVertical.add(boxHorizontal)
		boxHorizontal = swing.Box.createHorizontalBox()
		boxHorizontal.add(swing.JLabel("Output"))
		boxVertical.add(boxHorizontal)
		boxHorizontal = swing.Box.createHorizontalBox()
		self._resultsTextArea = swing.JTextArea()
		resultsOutput = swing.JScrollPane(self._resultsTextArea)
		resultsOutput.setPreferredSize(Dimension(500,200))
		boxHorizontal.add(resultsOutput)
		boxVertical.add(boxHorizontal)
		self._jPanel.add(boxVertical)
		# add the custom tab to Burp's UI
		self._callbacks.addSuiteTab(self)
		return
	
	#Appends results to the resultsTextArea
	def appendToResults(self, s):
		self._resultsTextArea.append(s)
				
	def getFile(self, button):
		chooser = swing.JFileChooser()
		c = chooser.showOpenDialog(None)
		if chooser is not None:
			if (chooser.currentDirectory and chooser.selectedFile.name) is not None:
				self._fileLocation = str(chooser.currentDirectory) + os.sep + str(chooser.selectedFile.name)
				self._fileText.setText(self._fileLocation)
			else:
				self._fileText.setText("File Not Valid, Try Again")

	def hashParse(self, button):
		hashFile = self._fileLocation
		try: # Attempt to open file
			source = open(hashFile)
			source.close()
		except:
			print "hashout.txt file not found (Check if Path and Filename is Correct)\n"
			return
		with open(hashFile,"r") as hashout:
			for line in hashout:
				hashWord = line.split(":")[0].strip()
				hashType = line.split(":")[1].strip()
				self.hashes[hashWord] = hashType
		
		output = "Parsed hashes\n"
		output += "\n".join(self.hashes.keys())
		output += "\n"
		output += "#"*20
		output += "\n"
		self.appendToResults(output)
		
	def getTabCaption(self):
		return "Hash Check"
	
	def getUiComponent(self):
		return self._jPanel
	
	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
			return -1
		else:
			return 0
		
	def doPassiveScan(self, baseRequestResponse):
		scan_issues = []
		tmp_issues = []
		self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)
		issuename = "Potential password hash match"
		issuelevel = "Information"
		tmp_issues = self._CustomScans.findReflections(issuename, issuelevel, self.hashes)
		scan_issues = scan_issues + tmp_issues
		if len(scan_issues) > 0:
			return scan_issues
		else:
			return None
		
	def doActiveScan(self, baseRequestResponse, insertionPoint):
		scan_issues = []
		tmp_issues = []
		self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)
		issuename = "Potential password hash match"
		issuelevel = "Information"
		tmp_issues = self._CustomScans.findReflections(issuename, issuelevel, self.hashes)
		scan_issues = scan_issues + tmp_issues
		if len(scan_issues) > 0:
			return scan_issues
		else:
			return None
		
class CustomScans:
	
	def __init__(self, requestResponse, callbacks):
		# Set class variables with the arguments passed to the constructor
		self._requestResponse = requestResponse
		self._callbacks = callbacks
		
		# Get an instance of IHelpers, which has lots of useful methods, as a class
		# variable, so we have class-level scope to all the helper methods
		self._helpers = self._callbacks.getHelpers()
		
		# Put the parameters from the HTTP message in a class variable so we have class-level scope
		self._params = self._helpers.analyzeRequest(requestResponse.getRequest()).getParameters()
		return
	
	def findReflections(self, issuename, issuelevel, hashes):
		self.hashes = hashes
		scan_issues = []
		offset = array('i', [0, 0])
		response = self._requestResponse.getResponse()
		request = self._requestResponse.getRequest()
		responseLength = len(response)
		requestLength = len(request)
		for hashWord in self.hashes.keys(): # checks to see if the password hash is in requests and responses
			if hashWord in self._helpers.bytesToString(response):
				offsets = []
				start = self._helpers.indexOf(response, hashWord, False, 0, responseLength)
				#marking the offsets isn't working
				offset[0] = start
				offset[1] = start + len(hashWord)
				issuedetail = "HTTP Response contains this potential hash: {0} ({1})".format(hashWord,self.hashes[hashWord]) 
				scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
					self._helpers.analyzeRequest(self._requestResponse).getUrl(), 
					[self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
					issuename, issuelevel, issuedetail))
				
			if hashWord in self._helpers.bytesToString(request):
				offsets = []
				start = self._helpers.indexOf(request, hashWord, False, 0, requestLength)
				#marking offsets isn't working :(
				offset[0] = start
				offset[1] = start + len(hashWord)
				issuedetail = "HTTP Request contains this potential hash: {0} ({1})".format(hashWord,self.hashes[hashWord]) 
				scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
					self._helpers.analyzeRequest(self._requestResponse).getUrl(), 
					[self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
					issuename, issuelevel, issuedetail))

		return (scan_issues)

class ScanIssue(IScanIssue):
	def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
		self._url = url
		self._httpservice = httpservice
		self._requestresponsearray = requestresponsearray
		self._name = name
		self._severity = severity
		self._detailmsg = detailmsg

	def getUrl(self):
		return self._url

	def getHttpMessages(self):
		return self._requestresponsearray

	def getHttpService(self):
		return self._httpservice 

	def getRemediationDetail(self):
		return None

	def getIssueDetail(self):
		return self._detailmsg

	def getIssueBackground(self):
		return None

	def getRemediationBackground(self):
		return None

	def getIssueType(self):
		return 0

	def getIssueName(self):
		return self._name

	def getSeverity(self):
		return self._severity

	def getConfidence(self):
		return "Certain"