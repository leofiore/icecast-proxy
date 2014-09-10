import threading
import time
import shout
import logging


logger = logging.getLogger('audio.icecast')


class Icecast(object):
    connecting_timeout = 5.0

    def __init__(self, source, config, audio_info):
        super(Icecast, self).__init__()
        self.config = (config if isinstance(config, IcecastConfig)
                       else IcecastConfig(config))
        self.source = source
        self._saved_audio_info = audio_info

        self._shout = self.setup_libshout()

    def connect(self):
        """Connect the libshout object to the configured server."""
        try:
            self._shout.open()
            logger.info("Connected to Icecast on " + self.config['mount'])
        except (shout.ShoutException) as err:
            logger.exception("Failed to eonnect to Icecast server.")
            raise IcecastError("Failed to connect to icecast server.")

    def connected(self):
        """Returns True if the libshout object is currently connected to
        an icecast server."""
        try:
            return (self._shout.get_connected() == shout.SHOUTERR_CONNECTED)
        except AttributeError:
            return False

    def read(self, size, timeout=None):
        raise NotImplementedError("Icecast does not support reading.")

    def nonblocking(self, state):
        self._shout.nonblocking = state

    def close(self):
        """Closes the libshout object and tries to join the thread if we are
        not calling this from our own thread."""
        self._should_run.set()
        try:
            self._shout.close()
            logger.info("Disconnected from Icecast on " + self.config['mount'])
        except (shout.ShoutException) as err:
            if err[0] == shout.SHOUTERR_UNCONNECTED:
                pass
            else:
                logger.exception("Exception in shout close call.")
                raise IcecastError("Exception in shout close.")
        try:
            self._thread.join(5.0)
        except (RuntimeError) as err:
            pass

    def run(self):
        while not self._should_run.is_set():
            while self.connected():
                if hasattr(self, '_saved_meta'):
                    self.set_metadata(self._saved_meta)
                    del self._saved_meta

                if hasattr(self, '_saved_audio_info'):
                    self.set_audio_info(self._saved_audio_info)
                    del self._saved_audio_info

                buff = self.source.read(8192)
                if buff == b'':
                    # EOF received
                    self.close()
                    logger.error("Source EOF, closing ourself.")
                    break
                else:
                    try:
                        self._shout.send(buff)
                        #self._shout.sync()
                    except (shout.ShoutException) as err:
                        logger.exception("Failed sending stream data.")
                        self.reboot_libshout()

            if not self._should_run.is_set():
                time.sleep(self.connecting_timeout)
                self.reboot_libshout()

    def start(self):
        """Starts the thread that reads from source and feeds it to icecast."""
        if not self.connected():
            self.connect()
        self._should_run = threading.Event()

        self._thread = threading.Thread(target=self.run)
        self._thread.name = "Icecast"
        self._thread.daemon = True
        self._thread.start()

    def switch_source(self, new_source):
        """Tries to change the source without disconnect from icecast."""
        self._should_run.set()  # Gracefully try to get rid of the thread
        try:
            self._thread.join(5.0)
        except RuntimeError as err:
            logger.exception("Got called from my own thread.")
        self.source = new_source  # Swap out our source
        self.start()  # Start a new thread (so roundabout)

    def set_metadata(self, metadata):
        try:
            self._shout.set_metadata(metadata)  # Stupid library
        except (shout.ShoutException) as err:
            logger.exception("Failed sending metadata. No action taken.")
            self._saved_meta = metadata

    def set_audio_info(self, audio_info):
        try:
            self._shout.audio_info = audio_info
        except (shout.ShoutException) as err:
            logger.exception("Failed sending audio_info. No action taken.")
            self._saved_audio_info = audio_info

    def setup_libshout(self):
        """Internal method

        Creates a libshout object and puts the configuration to use.
        """
        _shout = shout.Shout()
        self.config.setup(_shout)
        _shout.audio_info = self._saved_audio_info
        return _shout

    def reboot_libshout(self):
        """Internal method

        Tries to recreate the libshout object.
        """
        try:
            self._shout.close()
            del self._shout
        except:
            logger.exception("Closing failed")
        try:
            self._shout = self.setup_libshout()
        except (IcecastError) as err:
            logger.exception("Configuration failed.")
            self.close()
        try:
            logger.exception("Reopening...")
            self.connect()
        except (IcecastError) as err:
            logger.exception("Connection failure.")


class IcecastConfig(dict):
    """Simple dict subclass that knows how to apply the keys to a
    libshout object.
    """
    def __init__(self, attributes=None):
        super(IcecastConfig, self).__init__(attributes or {})

    def setup(self, _shout):
        """Setup 'shout' configuration by setting attributes on the object.

        'shout' is a shout.Shout object.
        """
        for key, value in self.iteritems():
            try:
                if isinstance(value, unicode):
                    value = str(value)
                setattr(_shout, key, value)
            except shout.ShoutException as err:
                raise IcecastError(("Incorrect configuration option '{:s}' or "
                                   " value '{:s}' used.").format(key, value))
            except Exception as e:
                print "--------------"
                print e
                print key, value
                print "--------------"



class IcecastError(Exception):
    pass
