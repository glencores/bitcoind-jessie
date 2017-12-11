#!/usr/bin/env python3

#
# sudo pip3 install gnupg psutil clint bs4
# nice to have: dpkg debconf debhelper lintian
#

import requests
import os
import tarfile
from bs4 import BeautifulSoup
from clint.textui import progress
from hashlib import sha256
from gnupg import GPG

host = 'https://bitcoin.org'
session = requests.Session()


def get_href(a):
  l = host + a['href']
  return l


def fetch(u):
  r = session.get(u, stream=True)
  return r


def remove_file_if_exists(f):
  if os.path.exists(f):
    os.remove(f)
  return 0


def save_file(url):
  local_filename = url.split('/')[-1]
  remove_file_if_exists(local_filename)
  print('* Getting file: ' + local_filename)
  response = fetch(url)
  total_length = int(response.headers.get('content-length'))
  with open(local_filename, 'wb') as f:
    for chunk in progress.bar(response.iter_content(chunk_size=1024), expected_size=(total_length/1024) + 1):
      if chunk:
        f.write(chunk)
        f.flush()
  return local_filename


def verify_gpg_signature(f):
  gpg = GPG(homedir='~/.gnupg')
  
  # search public key 0x90C8019E36C2E964
  bitcoin_core_pgp_key_found = False
  keys = gpg.list_keys()
  for key in keys:
    if key['keyid'] == '90C8019E36C2E964':
      bitcoin_core_pgp_key_found = True

  if not bitcoin_core_pgp_key_found == True:
    print('* Warning: bitcoin-core GPG key not found, trying to find and import...')
    import_key = gpg.recv_keys('90C8019E36C2E964', keyserver='hkp://pool.sks-keyservers.net')
    print('* Status: ' + import_key.summary())
    print('* Fingerprint: ' + import_key.fingerprints[0])
  
  with open(f) as fi:
    verif = gpg.verify_file(fi)
  print('* Verifying ' + f + ': ' + verif.status)
  
  if not verif.valid:
    print('* Impossible to compare checksums, quitting!')
    
  return verif.valid


def read_checksum(s, t):
  with open(s) as f:
    for line in f:
      if t in line:
        line = line.split(' ')
        checksum = line[0].rstrip()
        return checksum
  return -1


def untar_binaries(f):
  print('* Extracting ' + f + '...')
  tar = tarfile.open(f, 'r:gz')
  for tar_member in progress.bar(tar.getmembers()):
    tar.extract(tar_member)
  n = tar.members[0].name
  tar.close()
  print('* Removing ' + f + '...')
  os.remove(f)
  return n


def create_deb_control_file(proj_dir):
  project_name = proj_dir.split('-')[0]
  project_version = proj_dir.split('-')[1]
  project_size = str(int(sum(os.path.getsize(project) for project in os.listdir('.') if os.path.isfile(project))/1024))
  os.chdir(proj_dir)
  os.mkdir('DEBIAN')
  os.chdir('DEBIAN')
  f = open('control', 'w')
  f.write('Package: ' + project_name + '\n')
  f.write('Source: ' + project_name + '\n')
  f.write('Version: ' + project_version + '-jessie' + '\n')
  f.write('Architecture: amd64' + '\n')
  f.write('Maintainer: user <user@localhost>' + '\n')
  f.write('Installed-Size: ' + project_size + '\n')
  f.write('Section: utils' + '\n')
  f.write('Priority: optional' + '\n')
  f.write('Homepage: https://bitcoincore.org/' + '\n')
  f.write('Description: peer-to-peer network based digital currency ' + '\n')
  f.write('Pre-Depends: debconf' + '\n')
  f.write('Depends: openssl, libdb4.8, libdb4.8++, miniupnpc, libboost-system-dev, libboost-filesystem-dev,'
          'libboost-chrono-dev, libboost-program-options-dev, libboost-test-dev, libboost-thread-dev, logrotate' + '\n')
  f.write('Build-Depends: build-essential, autoconf, automake, libtool, pkg-config, libboost-all-dev, libaudit-dev,'
          'libssl-dev, libdb4.8-dev, libdb4.8++-dev, libminiupnpc-dev' + '\n')
  f.close()
  print('* Debian control file created.')
  os.chdir('/tmp/')
  return project_name


def main():
  print('* Switching to /tmp')
  os.chdir('/tmp')
  print('* Reading the Download page of ' + host + '/')
  response = fetch(host + '/en/download')

  page = BeautifulSoup(response.text, 'html.parser')
  link_linux_64 = get_href(page.find('a', {'id': 'lin64'}))
  link_signatures = get_href(page.find('a', text='Verify release signatures'))

  tarball = save_file(link_linux_64)
  signatures = save_file(link_signatures)

  signatures_ok = verify_gpg_signature(signatures)
  if not signatures_ok:
    return -1

  original_sha256 = read_checksum(signatures, tarball)
  tarball_sha256 = sha256(open(tarball, 'rb').read()).hexdigest()

  if not original_sha256 == tarball_sha256:
    print('* File ' + tarball + 'is inconsistent , SHA256 verification failed!')
    return -1

  print('* SHA256 checksum of ' + tarball + ' is OK!')
  project = untar_binaries(tarball)
  
  # fix short dir name when version is too long
  if not project == tarball[:-24]:
    os.renames(project, tarball[:-24])
    project = tarball[:-24]
    
  print('* Tarball extracted to ' + project)
  create_deb_control_file(project)
  print('* Preparations are now completed, let\'s build ' + project + '.deb')
  os.system('fakeroot dpkg-deb --build ' + project)
  print('* Package is built, now run sudo dpkg -i /tmp/' + project + '.deb\n'
        '  Or even better, sudo apt-get install gdebi-core && \\ \n'
        '  sudo gdebi /tmp/' + project + '.deb')

if __name__ == '__main__':
  main()

