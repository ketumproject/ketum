#!/usr/bin/env python
import json
import logging
import os
import base64
import re

import click
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import ketumclib
import profig
from tabulate import tabulate
import validators
from ketum import StorageManager

ketum_path = os.path.join(os.path.expanduser("~"), '.ketum')

if not os.path.exists(ketum_path):
    os.makedirs(ketum_path)
logger = logging.getLogger('ketum')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('spam.log')
fh.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)


class CliCfg(object):
    def __init__(self):
        self.profig = None


pass_cfg = click.make_pass_decorator(CliCfg, ensure=True)


@click.group()
@pass_cfg
def cli(cfg):

    profig_path = os.path.join(ketum_path, 'ketum.conf')

    if not os.path.isdir(ketum_path):
        raise click.ClickException("%s is not a directory!" % ketum_path)
    cfg.profig = profig.Config(profig_path)

    cfg.profig.init('proxy.type', '', str)
    cfg.profig.init('proxy.host', '', str)
    cfg.profig.init('proxy.port', 8080, int)
    cfg.profig.sync()


@cli.group()
def storage():
    pass


@storage.command()
@click.option(
    '--baseurl',
    help='Ketum Server base URL',
    prompt='Ketum Server Base URL',
)
@click.option(
    '--name',
    help='Storage name.',
    prompt='Name',
)
@click.option(
    '--description',
    default='',
    help='Storage description, this will be shown in storage list.',
    prompt='Description',
)
@click.password_option(
    '--passphrase',
    help='Secret key and other informations (except description) '
         'will be encrypted with this passphrase',
    prompt='Passphrase',
    confirmation_prompt=True,
)
@pass_cfg
def new(cfg, baseurl, name, description, passphrase):

    if not validators.url(baseurl):
        raise click.ClickException("Base URL is invalid!")

    if not validators.length(name, min=1):
        raise click.ClickException("Name is empty!")

    if not re.match("^[A-Za-z0-9_-]*$", name):
        raise click.ClickException(
            "Name is invalid! Only [a-Z][0-9]_- accepted")

    if len(passphrase) < 8:
        raise click.ClickException("Passphrase can't be shorter "
                                   "than 8 character!")

    if not all(ord(c) < 128 for c in passphrase):
        raise click.ClickException("Passphrase includes non-ascii chars!")
    passphrase = passphrase.encode()

    storage_manager = StorageManager()

    try:
        storage_manager.new_storage(baseurl, name, description, passphrase)
    except NameError, e:
        raise click.ClickException(e.message)

    click.echo('Storage has been successfully created.')


@storage.command()
@click.option(
    '--pretty',
    help='Print result with fancy table',
    is_flag=True,
)
@pass_cfg
def ls(cfg, pretty):
    storage_manager = StorageManager()
    storage_list = storage_manager.storages()

    if pretty:
        tablefmt = 'psql'
    else:
        tablefmt = 'plain'

    print tabulate(storage_list, ('Name', 'Description'), tablefmt=tablefmt)


@storage.command()
@click.argument(
    'name',
    nargs=1,
)
@click.argument(
    'other_names',
    nargs=-1,
)
@pass_cfg
def rm(cfg, name, other_names):  # TODO: Add remove destroy
    storage_manager = StorageManager()
    all_names = (name, ) + other_names

    if not any([storage_manager.exists(_name) for _name in all_names]):
        raise click.ClickException('No storage found!')
    
    if click.confirm(
            'This will destroy your storage from local. Are you '
            'sure you want to do this?'):
        for _name in filter(lambda x: storage_manager.exists(x), all_names):
            try:
                storage_manager.delete(_name)
            except NameError, e:
                raise click.ClickException(e.message)

            click.echo('Storage %s has been destroyed.' % name)
