from setuptools import setup, find_packages

__version__ = '0.1'

setup(
    name='aiopop3',
    version=__version__,
    description='aiopop3 - asyncio based POP3 server',
    long_description="""This is a server for POP3 protocol""",
    author='https://github.com/kozzztik',
    url='https://github.com/kozzztik/aiopop3',
    keywords='email',
    packages=find_packages(),
    include_package_data=True,
    license='https://github.com/kozzztik/aiopop3/blob/master/LICENSE',
    classifiers=[
        'License :: OSI Approved',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Communications :: Email',
        ],
    )
