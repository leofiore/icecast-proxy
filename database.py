from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Enum
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
import config

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    user = Column(String, primary_key=True)
    password = Column(String, nullable=False)
    privileges = Column(Integer)

    def __repr__(self):
        return "<User %s %d>" % (self.user, self.privileges)


class Mount(Base):
    __tablename__ = 'mounts'

    source = Column(String, primary_key=True, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer)
    password = Column(String, nullable=False)
    format = Column(Enum('ogg', 'mpeg', 'aac', 'flac'))
    protocol = Column(String, nullable=False)
    mount = Column(String, primary_key=True, nullable=False)
    name = Column(String, default=config.meta_name)
    url = Column(String, default=config.meta_url)
    genre = Column(String, default=config.meta_genre)
    bitrate = Column(Integer)
    user = Column(String, default='source', nullable=False)

    def __repr__(self):
        return "<Mount %s -> %s:%d%s %s>" % (
            self.source, self.host, self.port, self.mount, self.protocol
        )


engine = create_engine(config.connection)
Base.metadata.create_all(engine)


class SQLManager:
    """an ORM sqlmanager"""
    dosession = scoped_session(sessionmaker(bind=engine))

    def __init__(self):
        self.session = self.dosession()
        self.opened = True

    def __del__(self):
        if self.opened:
            self.session.close()
        self.opened = False

    def __enter__(self):
        if not self.opened:
            self.session = self.dosession()
        self.opened = True
        return self.session

    def __exit__(self, *args):
        if self.opened:
            self.session.close()
        self.opened = False


class Log(object):
    def __init__(self, client):
        super(Log, self).__init__()
        self.client = client

    def login(self):
        """Adds an entry for logon time of client."""
        pass

    def logout(self):
        """Updates logoff time on last logon entry."""
        pass

    def live_on(self):
        """Adds an entry on when client went live."""
        pass

    def live_off(self):
        """Updates end time of live entry"""
        pass

    def metadata(self, metadata):
        """Adds an entry for metadata."""
        pass
