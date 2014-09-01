#!/usr/bin/python
import socket
import os
import re
import urlparse
import logging
import manager
import threading
import config
import urllib2
import signal
from cgi import escape as esc
from BaseHTTPandICEServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn, BaseServer
from manager import IcyClient
from select import select
from collections import namedtuple


socket.setdefaulttimeout(5.0)
logger = logging.getLogger('server')
MetadataTuple = namedtuple(
    'MetadataTuple',
    ['user', 'source', 'host', 'port', 'mount'])


server_header = u"""
<html>\n<head>\n<title>Icecast Proxy</title>
<style type="text/css">
table {border: 1px solid #999;border-right:0;border-bottom:0;margin-top:4px;}
td, th
{border-bottom:1px solid #ccc;border-right:1px solid #eee;padding: .2em .5em;}
form{margin:0;padding:0;}
</style>\n</head>\n<body>
<h3>Icecast Proxy</h3>

"""

mount_header = u"""
<table width="800px" cellspacing="0" cellpadding="2">
<tr>\n<th align="left" colspan="5">{mount}</th>\n</tr>
<tr>\n<th width="80px">Username</th>
<th>Metadata</th>
<th width="150px">Useragent</th>
<th width="150px">Stream name</th>
<th width="50px">Kick</th>\n</tr>

"""

client_html = u"""
<tr>
<td>{user}</td>
<td>{meta}</td>
<td>{agent}</td>
<td>{stream_name}</td>
<td>
<form action="" method="GET">
<input type="hidden" name="mount" value="{mount}" />
<input type="hidden" name="num" value="{num}" />
<input type="submit" value="Kick" {disabled} />
</form>
</td>
</tr>

"""


class IcyRequestHandler(BaseHTTPRequestHandler):
    manager = manager.IcyManager()

    def _get_login(self):
        try:
            login = self.headers['Authorization'].split()[1]
        except (IndexError, KeyError):
            return (None, None)
        else:
            return login.decode("base64").split(":", 1)

    def _serve_admin(self, url, query, user, password):
        auth = self.manager.login(
            user=user,
            password=password)
        # disabled = u'disabled' if not is_admin else None
        disabled = auth.privileges > 0 and u'disabled' or ''
        send_buf = []
        send_buf.append(server_header)

        for mount in self.manager.context:
            # only include if there is a source on there
            if self.manager.context[mount].sources:
                send_buf.append(mount_header.format(mount=mount))
                for i, source in enumerate(
                        self.manager.context[mount].sources):
                    metadata = self.manager.context[
                        mount].saved_metadata.get(source, u'')
                    send_buf.append(client_html.format(
                        user=source.user,
                        meta=metadata,
                        agent=source.useragent,
                        stream_name=source.stream_name,
                        mount=mount,
                        num=i,
                        disabled=disabled))
                send_buf.append('</table>\n')
        send_buf.append('</body>\n</html>')
        send_buf = u''.join(send_buf)
        send_buf = send_buf.encode('utf-8', 'replace')
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", len(send_buf))
            self.end_headers()
            self.wfile.write(send_buf)
        except IOError as err:
            logger.exception("Error in request handler")

    def _serve_metadata(self, parsed_url, parsed_query, user, password):
        try:
            mount = parsed_query['mount'][0]
        except (KeyError, IndexError):
            mount = ''
        for path in self.manager.lookup_destination(mount):
            client = MetadataTuple(
                user,
                path.source,
                path.host,
                path.port,
                path.mount
            )

            logger.debug("Serving metadata for %s", client)
            song = parsed_query.get('song', None)
            artist = parsed_query.get('artist', None)
            title = parsed_query.get('title', None)
            encoding = parsed_query.get('charset', ['latin1'])
            if not song is None:
                metadata = fix_encoding(song[0], encoding[0])
                self.manager.send_metadata(
                    metadata=metadata,
                    client=client)
            elif title and artist:
                metadata = fix_encoding(
                    "%s - %s" % (artist[0], title[0]),
                    encoding[0])
                self.manager.send_metadata(
                    metadata=metadata,
                    client=client)

        # Send a response... although most clients just ignore this.
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.send_header("Content-Length", "113")
            self.end_headers()

            self.wfile.write(
                '<?xml version="1.0"?>\n<iceresponse>'
                '<message>Metadata update successful</message>'
                '<return>1</return></iceresponse>')
        except IOError as err:
            if hasattr(err, 'errno') and err.errno == 32:
                #logger.warning("Broken pipe exception, ignoring")
                pass
            else:
                logger.exception("Error in request handler")

    def _serve_listclients(self, parsed_url, parsed_query, user, password):
        auth = "{:s}:{:s}".format('source', config.icecast_pass)
        auth = auth.encode('base64')
        url = urlparse.urlparse('http://{:s}:{:d}/'.format(
            config.icecast_host,
            config.icecast_port)
        )
        url = url[:2] + parsed_url[2:]
        url = urlparse.urlunparse(url)

        request = urllib2.Request(url)
        request.add_header('User-Agent', self.useragent)
        request.add_header('Authorization', 'Basic {:s}'.format(auth))

        try:
            result = urllib2.urlopen(request).read()
        except urllib2.HTTPError as err:
            self.send_response(err.code)
            self.end_headers()
            return
        except urllib2.URLError as err:
            self.send_response(501)
            self.end_headers()
            return

        result_length = len(result)

        self.send_response(200)
        self.send_header('Content-Type', 'text/xml')
        self.send_header('Content-Length', str(result_length))
        self.end_headers()

        self.wfile.write(result)

    def do_SOURCE(self):
        logger.debug(self.headers)
        self.useragent = self.headers.get('User-Agent', None)
        self.mount = self.path  # oh so simple
        self.stream_name = self.headers.get('ice-name', '<Unknown>')
        self.source_content = self.headers.get('Content-type', None)
        fmt = re.search("(mpeg|ogg|flac)", self.source_content).groups()[0]

        ice_audio_info = urlparse.parse_qs(
            self.headers.get('ice-audio-info', '')
        )
        self.source_bitrate = self.headers.get(
            'ice-bitrate',
            "".join(ice_audio_info.get('bitrate', ['128'])))

        user, password = self._get_login()
        if user == 'source' and "|" in password:
            user, password = password.split('|')
        auth = self.login(user=user, password=password)
        if auth:
            logger.info("source: User '%s' logged in correctly.", user)
            self.send_response(200)
            self.end_headers()
        else:
            logger.info("source: User '%s' failed to login from %s.",
                        user, str(self.client_address))
            self.send_response(401)
            self.end_headers()
            return

        icy_client = []
        logger.debug('lookup for source mountpoint %s' % self.mount)
        for path in self.manager.lookup_destination(self.mount):
            icy_client.append(
                IcyClient(
                    path.host,
                    path.port,
                    path.source,
                    path.mount,
                    user=auth,
                    password=path.password,
                    useragent=self.useragent,
                    stream_name=self.stream_name,
                    informat=fmt,
                    outformat=path.format,
                    protocol=path.protocol,
                    name=path.name,
                    inbitrate=self.source_bitrate,
                    outbitrate=path.bitrate or self.source_bitrate
                )
            )
            try:
                self.manager.register_source(icy_client[-1])
            except Exception as err:
                logger.error(err)
                icy_client.pop()
                continue
        logger.debug(
            'registered %d mountpoints destinations'
            % len(icy_client))
        try:
            while True:
                rlist, wlist, xlist = select([self.rfile], [], [], 0.5)
                if not len(rlist):
                    continue
                data = self.rfile.read(4096)
                if data == '':
                    break
                for client in icy_client:
                    if client.is_active:
                        client.write(data)
                    else:
                        icy_client.remove(client)
                if not len(icy_client):
                    logger.debug("Thread exiting since no more clients are active")
                    self.rfile.close()
                    return

        except:
            logger.exception("Timeout occured (most likely)")
        finally:
            logger.info("source: User '%s' logged off.", user)
            while len(icy_client):
                client = icy_client.pop()
                self.manager.remove_source(client)

    def do_GET(self):
        self.useragent = self.headers.get('User-Agent', None)
        parsed_url = urlparse.urlparse(self.path)
        parsed_query = urlparse.parse_qs(parsed_url.query)
        logger.debug("Parsed query: %s", parsed_query)
        user, password = self._get_login()
        if user and not password and 'pass' in parsed_query:
            password = parsed_query['pass'][0]
        if user == 'source' and "|" in password:
            user, password = password.split('|')
        auth = self.login(user=user, password=password)
        if auth:
            # Since the user and password are raw at this point we fix them up
            # If user is 'source' it means the actual user is still in the
            # password field.
            if parsed_url.path == "/":
                self._serve_admin(parsed_url, parsed_query, user, password)
            elif parsed_url.path == "/admin/metadata":
                self._serve_metadata(parsed_url, parsed_query, user, password)
            elif parsed_url.path == "/admin/listclients":
                self._serve_listclients(parsed_url, parsed_query, user, password)
        else:
            self.send_response(401)
            self.send_header(
                'WWW-Authenticate',
                'Basic realm="Icecast2 Proxy"')
            self.end_headers()
            # return

    def login(self, user=None, password=None):
        return self.manager.login(user, password)

    def log_message(self, *args, **kwargs):
        """Disable logging, we don't need it"""
        pass


def fix_encoding(metadata, encoding):
    """We get passed a byte string and an encoding and have to figure
    out what to do with it in regards to 'fixing' it.

    when the encoding = latin1 we can safely assume the client send no
    explicit encoding and we apply the old ugly fix.

    when the encoding is anything but latin1 we can safely know the client send
    an explicit encoding and we decode it properly.
    """
    if encoding == 'latin1':
        try:
            try:
                return unicode(metadata, 'utf-8', 'strict').strip()
            except (UnicodeDecodeError):
                return unicode(metadata, 'shiftjis', 'replace').strip()
        except (TypeError):
            return metadata.strip()
    else:
        try:
            return unicode(metadata, encoding).strip()
        except (UnicodeDecodeError):
            # The encoding we got explicitely seems to be wrong
            # We call ourself again with latin1 encoding
            return fix_encoding(metadata, 'latin1')


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    timeout = 0.5

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        try:
            BaseServer.finish_request(self, request, client_address)
        except (IOError) as err:
            if hasattr(err, 'errno') and err.errno == 32:
                logger.warning("Broken pipe exception, ignoring")
            else:
                logger.exception("Error in request handler")


def run(server=ThreadedHTTPServer,
        handler=IcyRequestHandler,
        continue_running=threading.Event()):
    address = (config.server_address, config.server_port)
    icy = server(address, handler)
    while not continue_running.is_set():
        icy.handle_request()
    icy.shutdown()


def start():
    global _server_event, _server_thread
    _server_event = threading.Event()
    _server_thread = threading.Thread(target=run, kwargs={'continue_running':
                                                          _server_event})
    _server_thread.daemon = True
    _server_thread.start()


def close():
    logger.warn("TERM|INT received, shutting down...")
    global _server_event, _server_thread
    _server_event.set()
    logger.warn("Wating threads shuts...")
    _server_thread.join(10.0)


if __name__ == "__main__":
    # Setup logging
    stream = logging.StreamHandler()
    logfile = logging.FileHandler(
        os.path.expanduser('~/logs/proxy.log'),
        encoding='utf-8')

    formatter = logging.Formatter(
        '%(asctime)s:%(name)s:%(levelname)s: %(message)s'
    )

    # Add the formatters for timestamps
    stream.setFormatter(formatter)
    logfile.setFormatter(formatter)

    # And add the handlers to your logger
    logger.addHandler(stream)
    logger.addHandler(logfile)

    logger.setLevel(config.logging_level)

    # Don't forget the audio package logger
    audio_log = logging.getLogger('audio')
    audio_log.addHandler(stream)
    audio_log.addHandler(logfile)
    audio_log.setLevel(config.logging_level)

    import time
    killed = threading.Event()

    def signal_handler(signum, frame):
        close()
        killed.set()
    start()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    while not killed.is_set():
        time.sleep(5)
