from setuptools import setup

setup(
    name='HARryParser',
    version='0.1',
    author='Argelius Labs',
    description='A simple parser for .har files to support privacy data analysis.',
    packages=['harryparser'],
    install_requires=['certifi==2022.12.7', 'charset-normalizer==3.1.0', 'dnspython==2.3.0', 'et-xmlfile==1.1.0',
                      'filelock==3.10.7', 'idna==3.4', 'openpyxl==3.1.2', 'python-dateutil==2.8.2', 'requests==2.31.0',
                      'requests-file==1.5.1', 'six==1.16.0', 'tldextract==3.4.0', 'urllib3==1.26.15', ],
    entry_points={
        'console_scripts': [
            'harryparser=harryparser.harryparser:main',
        ],
    },
)
