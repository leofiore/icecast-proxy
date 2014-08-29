import threading
from cStringIO import StringIO
from subprocess import Popen, PIPE
from select import select
import logging


logger = logging.getLogger('memory')
MAX_BUFFER = 24 * 1024 * 2
# Go about 192kbps (24kB/s) times two for a 2 second buffer


class cStringTranscoder:

    decode_flac = 'flac --totally-silent -s -d --force-raw-format ' \
        '--sign=signed --endian=little -o - -'

    decode_mpeg = 'madplay -q -b 16 -R 44100 -S -o raw:- -'
    encode_mpeg = 'lame --quiet --preset cbr 128 -r -s 44.1 --bitwidth 16 - -'

    decode_ogg = 'oggdec -Q -R -b 16 -e 0 -s 1 -o - -'
    encode_ogg = 'oggenc -Q -r -B 16 -C 2 -R 44100 --raw-endianness 0 -q 1.5 -'

    def __init__(self, infmt, outfmt):
        self.buffer = StringIO()
        self.readpos = 0
        self.writepos = 0
        self.size = MAX_BUFFER
        self.mutex = threading.RLock()
        self.not_empty = threading.Condition(self.mutex)
        self.not_full = threading.Condition(self.mutex)
        self.end = False
        if infmt == outfmt:
            self.decproc = None
            self.encproc = None
        else:
            logger.info("Buffer will activate transcoding")
            dec = getattr(self, 'decode_' + infmt[0])
            enc = getattr(self, 'encode_' + outfmt[0])
            self.decproc = Popen(
                dec.split(),
                stdin=PIPE, stdout=PIPE
            )
            self.encproc = Popen(
                enc.split(),
                stdin=self.decproc.stdout, stdout=PIPE
            )

    def write(self, data_in):
        if self.end:
            return
        with self.not_full:
            while self.writepos - self.readpos == self.size:
                self.not_full.wait()
            if self.decproc and self.encproc:
                data_sent = False
                data = None
                try:
                    while not self.end and not data_sent and not data:
                        logger.debug("Processing encode/decode")
                        rlist, wlist, xlist = select(
                            [self.encproc.stdout, self.decproc.stdout],
                            [self.decproc.stdin],
                            [],
                            0.5
                        )
                        if len(wlist) and not data_sent:
                            self.decproc.stdin.write(data_in)
                            data_sent = True
                            logger.debug("wrote to decoder")
                        if len(rlist) == 2:
                            data = self.encproc.stdout.read(8192)
                            if not len(data):
                                return
                            logger.debug("read from encoder %s", len(data))
                        elif not len(rlist) and data_sent:
                            return
                except IOError as err:
                    logger.error(err)
            else:
                data = data_in
            if not data:
                return
            self.buffer.seek(self.writepos)
            self.buffer.write(data)
            self.writepos = self.buffer.tell()
            if self.writepos > MAX_BUFFER:
                self.size = self.writepos
                self.writepos = 0
            self.not_empty.notify()

    def read(self, size):
        if self.end:
            return
        with self.not_empty:
            while self.writepos - self.readpos == 0:
                self.not_empty.wait()
            while self.writepos < (self.readpos + size) % self.size:
                self.not_empty.wait()
            self.buffer.seek(self.readpos)
            data = self.buffer.read(min(size, self.size - self.readpos))
            oldpos = self.readpos
            self.readpos = self.buffer.tell()
            if self.writepos < oldpos and self.readpos >= self.size:
                self.readpos = 0
            elif oldpos < self.writepos <= self.readpos:
                self.readpos = self.writepos
            self.not_full.notify()
        return data

    def close(self):
        self.end = True
        try:
            self.buffer.close()
            del self.buffer
        except Exception as e:
            logger.error(e)
        try:
            if self.encproc:
                self.encproc.stdout.close()
                self.encproc.kill()
            if self.decproc:
                self.decproc.stdin.close()
                self.decproc.stdout.close()
                self.decproc.kill()
        except Exception as e:
            logger.error(e)
        logger.debug("client closed")
