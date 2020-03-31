
print "Loading JWS Tool"
print "https://github.com/t3hbb/JWS_Tool"
print "AutoUpdate Multiple Tokens"
print "Remember to update any neccessary details in the extension!\n"
#A big thank you to @mohammadaskar2 for helping speak parseltongue!
  
from burp import IBurpExtender
from burp import IHttpListener
from burp import ISessionHandlingAction

  
# Regex are used for capturing the token value from the response
import re
import ssl
import urllib2



#In this example, the tokens are passed back in the body of the response
#as part of JSON array - for both they are identified as accesstoken
#If the application token has expired we look for the AppErrorRegex
#If the user has expired, we look for the UserErrorRegex
#I hate regex. It's witchcraft. :)

AccessTokenRegex = re.compile(r"accessToken\"\: \"(.*?)\"")
AppErrorRegex = re.compile(r"APP_TOKEN_EXPIRED")
UserErrorRegex = re.compile(r"USER_TOKEN_EXPIRED")
   
  
class BurpExtender(IBurpExtender, IHttpListener, ISessionHandlingAction):
	# Variables to hold the tokens found so that it can be inserted in the next request
	discoveredAPPToken = ''
	discoveredUSERToken = ''
  
	def registerExtenderCallbacks(self, callbacks):
		 self._callbacks = callbacks
		 self._helpers = callbacks.getHelpers()
		 callbacks.setExtensionName("JWS")
		 callbacks.registerHttpListener(self)
		 print "Extension registered successfully."
		 return
  
	def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
		# Operate on all tools other than the proxy
		if toolFlag != self._callbacks.TOOL_PROXY:
			if messageIsRequest:
				self.processRequest(currentMessage)
			else:
				self.processResponse(currentMessage)
 
	def processResponse(self, currentMessage):
		response = currentMessage.getResponse()
		parsedResponse = self._helpers.analyzeResponse(response)
		respBody = self._helpers.bytesToString(response[parsedResponse.getBodyOffset():])
		token = AppErrorRegex.search(respBody)
		#Search the response for the error message indicating the token has expired
		if token is None:
			print "APP token is valid"
		else:
			print "APP token expired - obtaining new one"
			self.authApp()
			print "AuthAPP Function complete - APPToken : ",BurpExtender.discoveredAPPToken
			
		token = UserErrorRegex.search(respBody)
		if token is None:
			print "User token is valid"
		else:
			print "User token expired, obtaining new one"
			self.authUser()
  
	def processRequest(self, currentMessage):
		request = currentMessage.getRequest()
		requestInfo = self._helpers.analyzeRequest(request)
		headers = requestInfo.getHeaders()
		requestBody = self._helpers.bytesToString(request)[requestInfo.getBodyOffset():])
		#headers is an array list
		#Convert to single string to process (sorry!)
		headerStr=""
		for x in range(len(headers)): 
			headerStr = headerStr + headers[x] +"\n"
		reqBody = currentMessage.getRequest()[requestInfo.getBodyOffset():]
		reqBody = self._helpers.bytesToString(request)
		
		updatedheaders = headerStr
		
		if BurpExtender.discoveredAPPToken != '':
		# Update X-AUTH-APP
			print "Replacing X-AUTH-APP with ",BurpExtender.discoveredAPPToken
			updatedheaders = re.sub(r"X-AUTH-APP\: .*", "X-AUTH-APP: {0}".format(BurpExtender.discoveredAPPToken), headerStr)
		else:
			print "No X-AUTH-APP token to replace."	
		
		if BurpExtender.discoveredUSERToken != '':	
		# Update X-AUTH-USER Token
			updatedheaders = re.sub(r"X-AUTH-USER\: .*", "X-AUTH-USER: {0}".format(BurpExtender.discoveredUSERToken), updatedheaders) 
		else:
			print "No X-AUTH-USER token to replace."
		#convert headers into a list
		headerslist = updatedheaders.splitlines()
		updatedRequest = self._helpers.buildHttpMessage(headerslist, requestBody)
		currentMessage.setRequest(updatedRequest)
		
		
	def authApp(self):
		print "Authing App - visiting URL"
		#Link for app to refresh
		host = "REDACTED"
		req = urllib2.Request(host)
		#Any Extra Headers you require
		req.add_header('X-AUTH-APP', 'REDACTED')
		req.add_header('User-Agent', 'Mozilla/5.0')
		#req.add_header('Accept-Encoding', 'gzip, deflate')

		context = ssl._create_unverified_context()
		resp = urllib2.urlopen(req, context=context)
		content = resp.read()
		
		token = AccessTokenRegex.search(content)
		BurpExtender.discoveredAPPToken=token.group(1)
		print "Actual Token ", BurpExtender.discoveredAPPToken
	
	def authUser(self):
		print "Authing User - visiting URL"
		#Force APP auth to ensure we have good token
		self.authapp()
		#Link for app to refresh
		host = "REDACTED"
		req = urllib2.Request(host)
		#Any Extra Headers you require
		req.add_header('X-AUTH-APP', BurpExtender.discoveredAPPToken)
		req.add_header('X-AUTH-USER', 'REDACTED')
		req.add_header('User-Agent', 'Mozilla/5.0')
		#req.add_header('Accept-Encoding', 'gzip, deflate')

		context = ssl._create_unverified_context()
		resp = urllib2.urlopen(req, context=context)
		content = resp.read()
		
		token = AccessTokenRegex.search(content)
		BurpExtender.discoveredUSERToken=token.group(1)
		print "Actual Token ", BurpExtender.discoveredUSERToken
		
		
		
