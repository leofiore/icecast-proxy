from setuptools import setup

setup(
    name='icecast-proxy',
    py_modules=['icecast-proxy'],
    version='0.1',
    description='Icecast Proxy',
    author='Leonardo',
    url='https://github.com/radiocicletta/icecast-proxy',
    install_requires=[
        'sqlalchemy',
        'bcrypt'
    ],
    dependency_links=[
        "http://github.com/Wessie/pylibshout/tarball/master#egg=pylibshout"
    ]
)
