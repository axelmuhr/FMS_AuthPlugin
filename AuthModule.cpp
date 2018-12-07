/*

The main code was taken from the samples provided with the FlashMediaServer (FMS) install.
It was modified by me (Axel Muhr) to provide some (mediocre) sort of stream path 
protection, so that the URL cannot be shared by users.

The added code make the FMS to use a "secret" combined with a timecode and the path, 
put into an md5 hash.
The same hash has to be generated on the calling side (perl example comes with this
code).
If they match the stream is played, else FMS will deliver a "goaway" video.

*/

/*----------------------------------------------------------------------------+
 |       ___     _       _                                                    |
 |      /   |   | |     | |                                                   |
 |     / /| | __| | ___ | |__   ___                                           |
 |    / /_| |/ _  |/ _ \|  _ \ / _ \                                          |
 |   / ___  | (_| | (_) | |_) |  __/                                          |
 |  /_/   |_|\__,_|\___/|____/ \___|                                          |
 |                                                                            |
 |                                                                            |
 |  ADOBE CONFIDENTIAL                                                        |
 |  __________________                                                        |
 |                                                                            |
 |  Copyright (c) 2003 - 2007, Adobe Systems Incorporated.                    |
 |  All rights reserved.                                                      |
 |                                                                            |
 |  NOTICE:  All information contained herein is, and remains the property    |
 |  of Adobe Systems Incorporated and its suppliers, if any. The intellectual |
 |  and technical concepts contained herein are proprietary to Adobe Systems  |
 |  Incorporated and its suppliers and may be covered by U.S. and Foreign     |
 |  Patents, patents in process, and are protected by trade secret or         |
 |  copyright law. Dissemination of this information or reproduction of this  |
 |  material is strictly forbidden unless prior written permission is         |
 |  obtained from Adobe Systems Incorporated.                                 |
 |                                                                            |
 |          Adobe Systems Incorporated       415.832.2000                     |
 |          601 Townsend Street              415.832.2020 fax                 |
 |          San Francisco, CA 94103                                           |
 |                                                                            |
 +----------------------------------------------------------------------------*/


#include "StdAfx.h"
#include "FmsAuthAdaptor.h"
#include "FmsAuthActions.h"
#include "FmsMedia.h"
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

// Includes added by AM
// --- for hash generation
#include <openssl/md5.h>
#include <time.h>
// --- For own configfile


#if defined (WIN32)
#pragma warning(disable : 4996)

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
	return TRUE;
}
#endif


char* createMD5(char* retbuf, time_t* timestring, const char *streamURL);

bool bProtected = false;
bool bRNAuthorized = false;

// --------------------------------------------------------------------------
//IFmsAuthAdaptor

class FmsAuthAdaptor : public IFmsAuthAdaptor
{	
	public:

		FmsAuthAdaptor(IFmsAuthServerContext* pFmsAuthServerContext) 
			: m_pFmsAuthServerContext(pFmsAuthServerContext) {}
		
		virtual ~FmsAuthAdaptor() {}
		
		void authorize(IFmsAuthEvent* pAev);
		void notify(IFmsAuthEvent* pAev);
		void getEvents(I32 aevBitAuth[], I32 aevBitNotf[], unsigned int count);

	private:

		IFmsAuthServerContext* m_pFmsAuthServerContext;

};

//////////////////utils////////////////////////////////////////
/////////////////////////////////////////////////
static char* getStringField(const IFmsAuthEvent* pEv, IFmsAuthEvent::Field prop) 
{
	FmsVariant field;
	if (pEv->getField(prop, field) == IFmsAuthEvent::S_SUCCESS && field.type == field.kString)
	{
		return field.str;
	}
	return 0;
}

static bool getI8Field(const IFmsAuthEvent* pEv, IFmsAuthEvent::Field prop, I8& iValue) 
{
	FmsVariant field;
	if (pEv->getField(prop, field) == IFmsAuthEvent::S_SUCCESS && field.type == field.kI8)
	{
		iValue = field.i8;
		return true;
	}
	return false;
}

static bool getI32Field(const IFmsAuthEvent* pEv, IFmsAuthEvent::Field prop, I32& iValue) 
{
	FmsVariant field;
	if (pEv->getField(prop, field) == IFmsAuthEvent::S_SUCCESS && field.type == field.kI32)
	{
		iValue = field.i32;
		return true;
	}
	return false;
}

static bool getI64Field(const IFmsAuthEvent* pEv, IFmsAuthEvent::Field prop, I64& iValue) 
{
	FmsVariant field;
	if (pEv->getField(prop, field) == IFmsAuthEvent::S_SUCCESS && field.type == field.kI64)
	{
		iValue = field.i64;
		return true;
	}
	return false;
}

static bool getFloatField(const IFmsAuthEvent* pEv, IFmsAuthEvent::Field prop, float& fValue) 
{
	FmsVariant field;
	if (pEv->getField(prop, field) == IFmsAuthEvent::S_SUCCESS && field.type == field.f)
	{
		fValue = field.f;
		return true;
	}
	return false;
}

static bool setStringField(IFmsAuthEvent* pEv, IFmsAuthEvent::Field prop, char* pValue) 
{
	FmsVariant field;
	field.setString(pValue);
	return pEv->setField(prop, field) == IFmsAuthEvent::S_SUCCESS; 
}

static bool setI8Field(IFmsAuthEvent* pEv, IFmsAuthEvent::Field prop, I8 iValue) 
{
	FmsVariant field;
	field.setI8(iValue);	
	return pEv->setField(prop, field) == IFmsAuthEvent::S_SUCCESS; 
}

static bool setI32Field(IFmsAuthEvent* pEv, IFmsAuthEvent::Field prop, I32 iValue) 
{
	FmsVariant field;
	field.setI32(iValue);	
	return pEv->setField(prop, field) == IFmsAuthEvent::S_SUCCESS; 
}

static bool setI64Field(IFmsAuthEvent* pEv, IFmsAuthEvent::Field prop, I64 iValue) 
{
	FmsVariant field;
	field.setI64(iValue);	
	return pEv->setField(prop, field) == IFmsAuthEvent::S_SUCCESS; 
}

static bool setFloatField(IFmsAuthEvent* pEv, IFmsAuthEvent::Field prop, float fValue) 
{
	FmsVariant field;
	field.setFloat(fValue);	
	return pEv->setField(prop, field) == IFmsAuthEvent::S_SUCCESS; 
}


static bool isADPCMSupported(int iAudioCodecs)
{	
	return (iAudioCodecs & SUPPORT_SND_ADPCM) != 0;
}

static bool isVP6Supported(int iVideoCodecs)
{
	int iAllVP6 = ( SUPPORT_VID_VP6ALPHA | SUPPORT_VID_VP6 );
	return (iVideoCodecs & iAllVP6) != 0;
}

static bool isService(int iType)
{
	return (iType & TYPE_SERVICE) != 0;
}

static bool isAMF3(unsigned char uEncod)
{
	return (uEncod == ENCODE_AMF3);
}

//////////////process all events/////////////////
class MyFmsAuthorizeEvent 
{
	public:
		
		MyFmsAuthorizeEvent(IFmsAuthEvent* pAev, IFmsAuthServerContext*	pFmsAuthServerContext)
			: m_pAev(pAev), m_pFmsAuthServerContext(pFmsAuthServerContext) {}
		
		virtual ~MyFmsAuthorizeEvent() {}
		
		void authorize();

	private:
		
		IFmsAuthEvent*			m_pAev;
		IFmsAuthServerContext*	m_pFmsAuthServerContext;

};

//here you can safely process authorization events
void MyFmsAuthorizeEvent::authorize()
{
	//approved
	bool bAuthorized = true;
	int position;
	char *pGetParams;
		
	//proccessing	
	switch(m_pAev->getType())
	{
		case IFmsAuthEvent::E_CONNECT:
		{
			//the following fields can be changed only in connect:
			//F_CLIENT_READ_ACCESS, F_CLIENT_WRITE_ACCESS
			//F_CLIENT_READ_ACCESS_LOCK, F_CLIENT_WRITE_ACCESS_LOCK,
			//F_CLIENT_AUDIO_SAMPLE_ACCESS, F_CLIENT_VIDEO_SAMPLE_ACCESS, 
	                //F_CLIENT_AUDIO_SAMPLE_ACCESS_LOCK, F_CLIENT_VIDEO_SAMPLE_ACCESS_LOCK

			I8 iValue;
			if (getI8Field(m_pAev, IFmsAuthEvent::F_CLIENT_WRITE_ACCESS, iValue))
			{
				bool bRes = setI8Field(m_pAev, IFmsAuthEvent::F_CLIENT_WRITE_ACCESS, iValue);
			}
			//here is a redirect connection case 
			char* pUri = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_URI); 
		}
		break;	

		case IFmsAuthEvent::E_PLAY:
		{			
			char* pStreamName = getStringField(m_pAev, IFmsAuthEvent::F_STREAM_NAME); 
			if (pStreamName)
			{
				setStringField(m_pAev, IFmsAuthEvent::F_STREAM_NAME, pStreamName);
			}			
			
			char* pStreamType = getStringField(m_pAev,IFmsAuthEvent::F_STREAM_TYPE);
			if (pStreamType)
			{
				setStringField(m_pAev,IFmsAuthEvent::F_STREAM_TYPE, pStreamType);
			}			

			char* pStreamQuery = getStringField(m_pAev,IFmsAuthEvent::F_STREAM_QUERY);
			if (pStreamQuery)
			{
				setStringField(m_pAev,IFmsAuthEvent::F_STREAM_QUERY, pStreamQuery);
			}			

			I8 iValue;
			if (getI8Field(m_pAev,IFmsAuthEvent::F_STREAM_RESET, iValue))
			{
				//not 0 means do not add it to play list,
				//false otherwise
				setI8Field(m_pAev,IFmsAuthEvent::F_STREAM_RESET, iValue);	
			}
			if (getI8Field(m_pAev,IFmsAuthEvent::F_STREAM_IGNORE, iValue))
			{
				//not 0 means ignore timestamps, true
				//otherwise
				setI8Field(m_pAev,IFmsAuthEvent::F_STREAM_IGNORE, iValue);	
			}			
		}
		break;

		case IFmsAuthEvent::E_FILENAME_TRANSFORM:
			{
				I64 iValue;
				if (getI64Field(m_pAev, IFmsAuthEvent::F_CLIENT_ID, iValue))
				{
					I64 iClientId = iValue;	
			 		//should be false not allowed to set
					bool bSet = setI64Field(m_pAev, IFmsAuthEvent::F_CLIENT_ID, iValue); 
				}

				char* pStreamName = getStringField(m_pAev, IFmsAuthEvent::F_STREAM_NAME); 
				if (pStreamName)
				{
					//should be false not allowed
					bool bSet = setStringField(m_pAev, IFmsAuthEvent::F_STREAM_NAME, pStreamName); 
				}

				char* pUri = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_URI); 

				// TODO: Read this from config file
/*				char configBuf[1024];
				char *ptr = configBuf;
				int valueLen = m_pFmsAuthServerContext->getConfig("Auth", &ptr, sizeof(configBuf));
				if (valueLen)
				{
					//key found
					char MyBuf[1024];
					sprintf(MyBuf, "AM: _TRANS config=%s", ptr);
					m_pFmsAuthServerContext->log(MyBuf, IFmsServerContext::kInformation, false);
					
				}
*/

				
				char* pTriggerString ="event";
				char* position;
				char* myStreamName;
				char hash[40]; // This is where the timecode.hash will be copied into
				I64 index;     // Memo to myself: Get used to modern stuff! int != 64bit ;-)
				    
				position = strstr(pUri, pTriggerString);
				
				// Find the trigger string in the URL  
				if (position != NULL) {				                    
				        index = pUri - position; // pointer arithmetic!				                        
					if(index < 0) {
						index = -index;  // take the positive value of index 
					}

					bProtected = true; // Flag for "yes, we're protected"
					
					myStreamName = strchr(pStreamName, '/'); // find the next slash
					myStreamName++;				 // and go one char forward
					
					time_t basetime;
					time_t timevar;
					struct tm * timeinfo;
					char myHash[200];		
								
					// TODO: Read those from config-file
					// These are the time offsets in seconds making the hash valid in a
					// certain time-frame. Feel free to adjust...
					int offset [] ={0,60,120,-60,-120,-180,-240,-900,-840,-780,-720,-660,-600,-540,-480,-420,-360,-300};
					int i;
					
					basetime = time(NULL);
					*myHash = 0; // clean out the rubbish... just in case.

					// Get the HTTP-GET params for MD5 calculations
					char* pStreamQuery = getStringField(m_pAev,IFmsAuthEvent::F_STREAM_QUERY);

					char MyBuf[1024];
					sprintf(MyBuf, "AM: _TRANS pStreamName=%s", pStreamName);
					m_pFmsAuthServerContext->log(MyBuf, IFmsServerContext::kInformation, false);

					// create the full string: streamname (incl. some pathes) and GET-params
					char* pNameAndQuery;
					pNameAndQuery = (char *)malloc((strlen(myStreamName) + strlen(pStreamQuery) + 2) *sizeof(char));					
					strcpy(pNameAndQuery, myStreamName);
					strcat(pNameAndQuery, "?");
					strcat(pNameAndQuery, pStreamQuery);

					// go through all time-permutations of the hash					
					for(i=0;i<sizeof(offset)/sizeof(int);i++) {
						timevar=basetime+offset[i];
						createMD5(myHash, &timevar, pNameAndQuery);
						if (strstr(pStreamName, myHash)) { // check the full url for the hash
						  sprintf(MyBuf, "AM: _TRANS Found %i = %s", i, myHash);
						  m_pFmsAuthServerContext->log(MyBuf, IFmsServerContext::kInformation, false);

						  bRNAuthorized = true; // It's a good guy!
						  break;
						}
						*myHash = 0; // "reset" the array pointer						      
					}
						                                    
					free(pNameAndQuery); // NEVER forget that! ;)
					
					bAuthorized = true;
					                                                                                
				} else {
				
					bProtected = false;
					
				} // end-if trigger-found
				                                                
				// Get the current (default) stream-path
				char* pStreamPath = getStringField(m_pAev, IFmsAuthEvent::F_STREAM_PATH); 
				// This is the hidden path on the server
				// TODO: Read those from config file
				char* pProtPath = "/opt/fms/applications/vod/media/supersecret/"; // ADD trailing slash!

				// called lameCode in config file
				char* pDefaultPath ="/opt/fms/applications/vod/media/goaway";
				
				char* pFullPath;

				// Calculate lenght of char * for full path name				
				pFullPath = (char *)malloc((strlen(pProtPath) + strlen(myStreamName) + 1) *sizeof(char));

				// Create full path by concatenating
				strcpy(pFullPath, pProtPath);
				strcat(pFullPath, myStreamName);				                        
				
				if (pStreamPath)
				{
					if (bProtected && bRNAuthorized) { // redir to the protected path
						bool bSet = setStringField(m_pAev, IFmsAuthEvent::F_STREAM_PATH, pFullPath);
						bRNAuthorized = false; // reset the auth-flag			
									                                                                                
					} else if (bProtected && !bRNAuthorized){ // play the "go away" tune

						FmsVariant field;
						// action to notify SSAS by calling "AuthMethod" with U16 variable = 666
						if (m_pAev->getField(IFmsAuthEvent::F_CLIENT_ID, field) == IFmsAuthEvent::S_SUCCESS)
						{
				                        char MyBuf[1024];
                				        sprintf(MyBuf, "AM: _TRANS called SSAS");
		                		        m_pFmsAuthServerContext->log(MyBuf, IFmsServerContext::kInformation, false);

							IFmsNotifyAction* pAction = m_pAev->addNotifyAction("Notified by adaptor");
							pAction->setClientId(field);
							field.setString("AuthMethod");
							pAction->setMethodName(field);
							field.setU16(666);
							pAction->addParam(field);
						}

						bool bSet = setStringField(m_pAev, IFmsAuthEvent::F_STREAM_PATH, pDefaultPath);
					} else { // actually... do nothing.
						bool bSet = setStringField(m_pAev, IFmsAuthEvent::F_STREAM_PATH, pStreamPath);
					}
		                        char MyBuf[1024];
                		        sprintf(MyBuf, "AM: _TRANS Changed StreamPath to %s", getStringField(m_pAev, IFmsAuthEvent::F_STREAM_PATH));
		                        m_pFmsAuthServerContext->log(MyBuf, IFmsServerContext::kInformation, false);
		                        
		                        free(pFullPath);
		                        bAuthorized = true;				
				}				

				char* pStreamType = getStringField(m_pAev, IFmsAuthEvent::F_STREAM_TYPE);
				if (pStreamType)
				{
					setStringField(m_pAev, IFmsAuthEvent::F_STREAM_TYPE, pStreamType);		
				}						
			}
		break;
		case IFmsAuthEvent::E_LOADSEGMENT:
		{
			//read only event substituted PLAY on origin in case of recorded stream
			//bAuthorized = false;	//block it
			
			I64 iValue;	
			if (getI64Field(m_pAev, IFmsAuthEvent::F_SEGMENT_START, iValue))
			{
				I64 iStart = iValue; //segment begin position in bytes
			}			
			if (getI64Field(m_pAev, IFmsAuthEvent::F_SEGMENT_END, iValue))
			{
				I64 iEnd = iValue;	//segment end position in bytes
			}			
		}
		break;
	}

	char buf[1024];
	const char* const action = bAuthorized ? "approved" : "rejected";
	sprintf(buf, "Received authorization type=%d id=%p %s\n", m_pAev->getType(), 
		m_pAev, action);
	//here is a log goes to server log if true also to event log
	m_pFmsAuthServerContext->log(buf, IFmsServerContext::kInformation, false); 
	m_pFmsAuthServerContext->onAuthorize(m_pAev, bAuthorized);
}

class MyFmsNotifyEvent 
{
	public:
		MyFmsNotifyEvent(IFmsAuthEvent* pAev, IFmsAuthServerContext* pFmsAuthServerContext)
			: m_pAev(pAev), m_pFmsAuthServerContext(pFmsAuthServerContext) {}
		
		virtual ~MyFmsNotifyEvent() {}
		
		void notify() const;

	private:
		
		IFmsAuthEvent*	m_pAev;
		IFmsAuthServerContext*	m_pFmsAuthServerContext;
		
};

void MyFmsNotifyEvent::notify() const
{	
	switch(m_pAev->getType())
	{
		case IFmsAuthEvent::E_PLAY:
		{
			//all pointers to buffer are valid in this scope. 
			//kString type look at field.type!
			char* pAppName = getStringField(m_pAev, IFmsAuthEvent::F_APP_NAME);
			char* pAppInst = getStringField(m_pAev, IFmsAuthEvent::F_APP_INST);
			char* pAppUri = getStringField(m_pAev, IFmsAuthEvent::F_APP_URI);
			
			char* pClIp = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_IP);
			char* pClUri = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_URI);
			char* pClNewUri = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_REDIRECT_URI);
			char* pClVhost = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_VHOST);
			char* pClRef = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_REFERRER);
			char* pClPurl = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_PAGE_URL);
			char* pClAgent = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_USER_AGENT);
			char* pClRAccess = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_READ_ACCESS);
			char* pClWAccess = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_WRITE_ACCESS);
			char* pClAudioAccess = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_AUDIO_SAMPLE_ACCESS);
			char* pClVideoAccess = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_VIDEO_SAMPLE_ACCESS);
			char* pClProto = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_PROTO);
			char* pClUstem = getStringField(m_pAev, IFmsAuthEvent::F_CLIENT_URI_STEM);
			
			char* pStreamName = getStringField(m_pAev, IFmsAuthEvent::F_STREAM_NAME);
			char* pStreamType = getStringField(m_pAev, IFmsAuthEvent::F_STREAM_TYPE);
			char* pStreamQuery = getStringField(m_pAev, IFmsAuthEvent::F_STREAM_QUERY);
			char* pStreamPath = getStringField(m_pAev, IFmsAuthEvent::F_STREAM_PATH);

			I32 iValue;
			if (getI32Field(m_pAev, IFmsAuthEvent::F_CLIENT_AUDIO_CODECS, iValue))
			{
				bool bADPCM = isADPCMSupported(iValue);
			}
			if (getI32Field(m_pAev, IFmsAuthEvent::F_CLIENT_VIDEO_CODECS, iValue))
			{
				bool bVP6 = isVP6Supported(iValue);
			}			
			if (getI32Field(m_pAev, IFmsAuthEvent::F_CLIENT_TYPE, iValue))
			{	
				bool bService = isService(iValue);
			}
						
			float fValue;
			if (getFloatField(m_pAev, IFmsAuthEvent::F_STREAM_LENGTH, fValue))
			{
				float fLength = fValue; //in sec
			}
			if (getFloatField(m_pAev, IFmsAuthEvent::F_STREAM_POSITION, fValue))
			{
				float iPosition = fValue; //in sec
			}

			I64 lValue;
			if (getI64Field(m_pAev, IFmsAuthEvent::F_CLIENT_ID, lValue))
			{
				I64 iClientId = lValue;		
			}
						
			I8 sValue;
			if (getI8Field(m_pAev, IFmsAuthEvent::F_CLIENT_SECURE, sValue))
			{
				bool bSecure = sValue != 0;
			}
			if (getI8Field(m_pAev, IFmsAuthEvent::F_CLIENT_AMF_ENCODING, sValue))
			{
				bool bAMF3 = isAMF3(sValue);
			}
			if (getI8Field(m_pAev, IFmsAuthEvent::F_CLIENT_READ_ACCESS_LOCK, sValue))
			{			
				bool bRead = sValue != 0;
			}
			if (getI8Field(m_pAev, IFmsAuthEvent::F_CLIENT_WRITE_ACCESS_LOCK, sValue))
			{
				bool bWrite = sValue != 0;
			}
			if (getI8Field(m_pAev, IFmsAuthEvent::F_CLIENT_AUDIO_SAMPLE_ACCESS_LOCK, sValue))
			{
				bool bAudioRead = sValue != 0;
			}
			if (getI8Field(m_pAev, IFmsAuthEvent::F_CLIENT_VIDEO_SAMPLE_ACCESS_LOCK, sValue))
			{
				bool bVideoRead = sValue != 0;
			}
			if (getI8Field(m_pAev, IFmsAuthEvent::F_STREAM_RESET, sValue))
			{
				bool bReset = sValue != 0;
			}
			if (getI8Field(m_pAev, IFmsAuthEvent::F_STREAM_IGNORE, sValue))
			{
				bool bIgnore = sValue != 0;
			}
		}			
		break;
		
		case IFmsAuthEvent::E_SEEK:
		{
			float fValue;
			if (getFloatField(m_pAev, IFmsAuthEvent::F_STREAM_SEEK_POSITION, fValue))
			{
				float fSeekTime = fValue;
			}

			//action by disconnecting seeking client attached to notifable event 
			FmsVariant field;
			if (m_pAev->getField(IFmsAuthEvent::F_CLIENT_ID, field) == IFmsAuthEvent::S_SUCCESS)
			{
				IFmsDisconnectAction* pAction = 
					const_cast<IFmsAuthEvent*>(m_pAev)->
						addDisconnectAction("Seek is not allowed. Blocked by adaptor");
				pAction->setClientId(field);
			}
		}
	}	
	char buf[1024];
	sprintf(buf, "Received notification type=%d id=%p\n", m_pAev->getType(), m_pAev);
	//here is a log goes to server log if true also to event log
	m_pFmsAuthServerContext->log(buf, IFmsServerContext::kInformation, false); 
	m_pFmsAuthServerContext->onNotify(m_pAev);
}

/*all authorization events are coming here,
please do not modify this function, here MyFmsAppAuthEvent allocated on stack 
but can be also allocated by new and delete and passed to new thread to process,
all processing should be done in authorize function from derived class above.
*/
void FmsAuthAdaptor::authorize(IFmsAuthEvent* pAev)
{
	 MyFmsAuthorizeEvent(pAev, m_pFmsAuthServerContext).authorize();
}

/*all notification events are coming here,
please do not modify this function, here MyFmsAppAuthEvent allocated on stack 
but can be allocated by new and delete and passed to new thread to process,
all processing should be done in notify function from derived class above.
*/
void FmsAuthAdaptor::notify(IFmsAuthEvent* pAev)
{
	 MyFmsNotifyEvent(pAev, m_pFmsAuthServerContext).notify();
}

/*by default bit is 0 allow to receive notification / authorization
to stop receiving event set bit to 1 
Events: FMS_EVENT_APPSTART, FMS_EVENT_APPSTOP, FMS_EVENT_DISCONNECT, FMS_EVENT_PAUSE,
FMS_EVENT_PLAY_STOP, FMS_EVENT_UNPAUSE, FMS_EVENT_UNPUBLISH are excluded
from authorization and ignored
*/
void FmsAuthAdaptor::getEvents(I32 aevBitAuth[], I32 aevBitNotf[], unsigned int count)
{	
	/////////////exclude certain auth events/////////////////////////
	IFmsAuthEvent::EventType authExcludeEvent[] = { IFmsAuthEvent::E_SEEK };
	//m_pFmsAuthServerContext->excludeEvents(aevBitAuth, count, authExcludeEvent, 1);
	/////////////exclude certain notify events/////////////////////////
	IFmsAuthEvent::EventType notifyExcludeEvent[] = { IFmsAuthEvent::E_PAUSE };
	m_pFmsAuthServerContext->excludeEvents(aevBitNotf, count, notifyExcludeEvent, 1);	
	////////////////////////////////////////////////////////////////	
}
// --------------------------------------------------------------------------

// Procedure added by AM

char* createMD5(char *retbuf, time_t* timestring, const char *streamURL) {    

    MD5_CTX context;
    int i;
    unsigned char digest[16];
    
    char tempstring[4];
    char fullPath[512];
    char theHash[32];

    // TODO: Read this from config file
    // The secret word... mind to adjust the size of the array!
    char secret[30] = "some super $ecret L33t 0xBEEF";

    time_t *timetemp; 
    char cbot[200];
    
    timetemp=timestring; // safe the given timestamp into var
    strftime ((char*)cbot,128,"%y%m%d%H%M",gmtime(timetemp)); //convert into desired format
            
    strcpy(fullPath, secret);
    strcat(fullPath, cbot);
    strcat(fullPath, streamURL);
    
    MD5_Init(&context);
    MD5_Update (&context, fullPath, strlen(fullPath));
    MD5_Final(digest, &context);
      
    for (i = 0; i < 16; i++) {
        sprintf (tempstring, "%02x", digest[i]);
        strcat (retbuf, tempstring);
    }
    return retbuf;
}




extern "C" void FCExport FmsCreateAuthAdaptor(IFmsAuthServerContext* pAuthServerCtx, 
	IFmsAuthAdaptor*& pFmsAuthAdaptor)
{
	pFmsAuthAdaptor = new FmsAuthAdaptor(pAuthServerCtx);
	U32 version = pAuthServerCtx->getVersion();
	U16 w2 = LWORD(version);
	U16 w1 = HWORD(version);
	char buf[1024];
	char *ptr = buf;
	int valueLen = pAuthServerCtx->getConfig("Auth", &ptr, sizeof(buf));
	if (!valueLen)
	{
		//key found
		return;
	}
	if (valueLen < 0)
	{
		// failed to find this key
		return; 
	}
	//value length is bigger then a buffer size
	//real adaptor should allocate valueLen + 1 bytes 
	//and call again
}

extern "C" void FCExport FmsDestroyAuthAdaptor(IFmsAuthAdaptor* pAuthAdaptor )
{
	delete pAuthAdaptor;	
}
