# JWS_Tool
Burp Extension to modify headers and maintain JWS validity

Full information is available on my shells.sytems post here (ADDURL).

Recently I was testing a mobile application and it’s interaction with an API backend. It was the first time that I had come across an application that used two different JWT tokens in the headers to authorise against the API end point.

Burp is great at handling cookies, but is not so great on handling JWTs from what I can tell. There are some existing Burp extensions but nothing I could find that would do what I wanted to be able to maintain valid sessions over a longer period of time than the JWT was valid for. 

Once you start working with JWTs of a very short life span, it is difficult to run a long series of automated tests in Burp without running into the problem of the JWT expiring and rendering the rest of the tests useless.

This extension allows you to identify when a session has become invalid and request a new token and use that for the remaining tests.

This is not restricted to JWT or JWS and the code can serve as a basis for any header manipulation/addition/removal, body manipulation including fetching information from different websites to provide data for whichever bits you are manipulating.
