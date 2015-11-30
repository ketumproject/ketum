from setuptools import setup, find_packages

setup(
    name='ketum',
    version='0.1',
    packages=find_packages(),
    py_modules=['ketum'],
    include_package_data=True,
    install_requires=[
        'click',
        'ketumclib',
        'profig',
        'cryptography',
        'validators',
        'tabulate',
    ],
    entry_points='''
        [console_scripts]
        ketum=_ketumcli:cli
    ''',
)
