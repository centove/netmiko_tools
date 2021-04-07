#!/usr/bin/env python3
''' Add/Remove devices from the netmiko device inventory'''
from __future__ import print_function, unicode_literals

import tldextract
import yaml
import ipaddress
import argparse
import os, sys, socket
import logging
import subprocess
import threading

from getpass import getpass

from netmiko import SSHDetect, Netmiko
from paramiko.ssh_exception import SSHException 
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
from netmiko.utilities import load_devices, display_inventory
from netmiko.utilities import obtain_all_devices
from netmiko.utilities import obtain_netmiko_filename, write_tmp_file, ensure_dir_exists
from netmiko.utilities import find_netmiko_dir, find_cfg_file

__version__ = "0.1.0"
device_inventory = load_devices()

def save_devices ():
  device_file = find_cfg_file()
  print ("Saving devices {} ".format(device_file))
  with open(device_file, 'w') as file:
    data = yaml.dump(device_inventory, file)

def my_resolve(device):
    """ The netmiko routines don't seem to take into account the /etc/hosts override so we manually 
    attempt to look things up.
    """ 
    try:
        ip = socket.gethostbyname(device)
    except socket.gaierror as e:
        print("Hostname lookup failed:'{}' {}".format(device, e))
        return None
    return ip

def add_device(device, args):
  '''Add a device to the list of devices to process '''
  ip = my_resolve(device)
  my_dev = dict()
  if ip is not None:
    fqdn = socket.getfqdn(device)
    print ("Add device {} ({})".format(fqdn, ip))
    host = tldextract.extract(fqdn)
    my_dev[host.subdomain] =  {'host': fqdn,
              'ip': ip,
              'device_type': 'autodetect',
              'ssh_config_file': args.sshconf,
              'conn_timeout': args.connection_timeout,
              'global_delay_factor': 5
            }
    return my_dev
  else:
    return None

def get_devices_from_file(device_file, args):
  ''' Read the list of devices from the provided file and return the device inventory list of
      devices to process 
  '''
  dev_list = dict()
  print ("Get devices from file {}".format(device_file))
  with open (device_file, mode='r', newline='\n') as batch:
    for dev in batch:
      dev = dev.strip()
      if dev == '':
        continue
      device = add_device(dev, args)
      if device is None:
        continue
      else:
        dev_list.update(device)
  return dev_list

def detect_device(device, a_device):
  ''' Use the ssh deivce type detection to see what kind of device this is '''
  print ("Attempting to detect device type {} {}".format(a_device['host'], a_device['ip']))
  try:
    guesser = SSHDetect(**a_device)
    best = guesser.autodetect()
    a_device['device_type'] = best
  except NetMikoTimeoutException:
    print ("Connection failed to {} ".format(device['host']))
    return None
  except Exception as e:
    print ("Exception! {}".format(e))
    return None
  return a_device

def get_group_devices(group, args):
  ''' return a list of devices in a group '''
  devices = {}
  try:
    device_group = device_inventory[group]
    if isinstance(device_group, list):
      for dev in device_group:
        devices[dev] = device_inventory[dev]
        devices[dev]['username'] = args.username if args.username else devices[dev]['username']
        devices[dev]['password'] = args.password if args.password else devices[dev]['password']
  except KeyError:
    return None
  return devices  

def parse_arguments(args):
  """Parse command-line arguments """
  description = "Manages the netmiko device inventory"
  parser = argparse.ArgumentParser(description=description)
  parser.add_argument("--username", help="Username", action="store", type=str)
  parser.add_argument("--password", help="Password", action="store", type=str)
  parser.add_argument('--version', help='Display version', action='store_true')
  parser.add_argument('--device-file', help='Add the devices in this file to the inventory', action="store")
  parser.add_argument('--sshconf', help='Use the specified ssh config file for establishing connections.', default="~/.ssh/miko-jump")
  parser.add_argument('--add-group', help='Add provided devices to this group', action="store", type=str)
  parser.add_argument('--connection-timeout', help='Connection timeout when connecting to the devices.', action="store", default=5, type=int)
  parser.add_argument('--list-devices', help='Display the current device inventory', action='store_true')
  parser.add_argument('--list-group', help='Display devices in this group', action="store", type=str)

  cli_args = parser.parse_args(args)
  return cli_args

def main(args):
  cli_args = parse_arguments(args)

  version = cli_args.version
  if version:
    print("netmiko-devices v{}".format(__version__))
    return 0 

  if cli_args.list_group:
    devices = get_group_devices(cli_args.list_group, cli_args)
    if devices is None:
      return ("No such group {0}".format(cli_args.list_group))
    else:
      display_inventory(devices)
      return 0

  if cli_args.list_devices:
    display_inventory(device_inventory)
    return 0
  cli_username = cli_args.username if cli_args.username else 'network'
  cli_password = cli_args.password if cli_args.password else getpass("{} password:".format(cli_username))
  cli_args.password = cli_password

  if cli_args.add_group:
    device_inventory[cli_args.add_group] = list()

  if cli_args.device_file:
    device_list = get_devices_from_file(cli_args.device_file, cli_args)

    print ("Processing device list")
    for device, a_device in device_list.items():
      a_device['username'] = cli_username
      a_device['password'] = cli_password
      a_device['conn_timeout'] = cli_args.connection_timeout
      detect_device(device, a_device)
    for device, a_device in device_list.items():
      a_device.pop('password', None)
      if cli_args.add_group:
        device_inventory[cli_args.add_group].append(device)
      print ("Device {} is {}".format(device, a_device['device_type']))
    device_inventory.update(device_list)
    save_devices()

    display_inventory(device_inventory)
      


if __name__ == "__main__":
  sys.exit(main(sys.argv[1:]))
