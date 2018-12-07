# FMS stream protection plugin

## About

This is a Flash Media Server (aka FMS) plugin to protect stream-URLs from being copied
and shared by users. 

I wrote this back in ca. 2009 and stumbled across the code when cleaning out my home directory.
For whatever reason, I was not feeling like deleting it, so here it is for your
amusement, inspiration or horror.

## How it works

Most of the code was taken from the samples provided with the FMS install.

The added/modified lines make FMS to check in a certain stream-trigger ("events" in this  example) for a md5 hash.
This hash is created by using a "secret" combined with a timecode and the path
to the video/stream.

This is an example calling stream URL:

rtmp://edge4.someserver.com/events/171426.f35d2bc39ee9409a02a29dbba19688f6/protected/axel/mofacam?info.workflow=axel&amp;info.method=protected

* "events" is the trigger for the plugin to kick-in
* "171426.f35d2bc39ee9409a02a29dbba19688f6" is the hash generated on both sides
* "protected/axel/" is the path to the file on the FMS
* "mofacam" is the video file/stream
* for demo purposes some extra parameters had been added

So the same hash has to be generated on the calling side, e.g. cgi (perl example comes with this
code).
If they match the stream is played, else FMS will deliver a "goaway" video.
Additionally a ServerSideActionScript (SSAS) event will be triggered, so you
can handle a client-deny with an additional ActionScript.

## Build

To compile use the provided Makefile. Make sure you have these libraries installed:

* need: libcrypto for MD5 hashes
* need: libinifile for own config file

If you have problems running this code... consider using a more modern Streaming Server
which still has a future :-P
