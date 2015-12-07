from setuptools import setup, find_packages

setup(
    name='ketum',
    version='0.2',
    packages=find_packages(),
    description="Ketum client application",
    url="https://github.com/ketumproject/ketum",
    author="Yasin Ozel",
    author_email="me@yozel.co",
    license="GPLv3",

    classifiers=[
        "Environment :: Console",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: System :: Filesystems",
    ],

    keywords="encrypted filesystem storagesystem ketum",

    py_modules=['ketumclib'],
    include_package_data=True,
    install_requires=[
        'click',
        'ketumclib',
        'profig',
        'cryptography',
        'validators',
        'tabulate',
        'pycrypto==2.6.1',
        'requests==2.8.1',
    ],

    entry_points='''
        [console_scripts]
        ketum=_ketumcli:cli
    ''',
)
