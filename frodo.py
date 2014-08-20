#!/usr/bin/env python
# vim: ts=4:sw=4:et
# with regards to remilliard

# required Debian/Ubuntu packages
# smbclient python-daemon cifs-utilsm mailutils

#
# XXX
# if you plan to use cifs mounts then the user you use should be able
# to execute the mount command via sudo *without* a password prompt
#

from subprocess import Popen, PIPE, STDOUT
import sys
import os, os.path
import atexit
import re
import argparse
import daemon
import time
import shutil
from getpass import getpass
from tempfile import NamedTemporaryFile, mkdtemp

import logging
logging.basicConfig(level=logging.DEBUG)

try:
    # not actually used by this script but used by the psexec.py script
    import impacket
except ImportError:
    logging.fatal("missing impacket library " +
"(see http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Impacket")
    sys.exit(1)

# make sure we have the commands we expect
for command in [ 'smbclient', 'mount.cifs', 'mailx' ]:
    which = Popen(['which', command], 
        stdout=open(os.devnull, 'wb'), stderr=STDOUT)
    which.wait()
    if which.returncode != 0:
        logging.fatal("missing command {0}".format(command))
        sys.exit(1)

from psexec import PSEXEC # from the impacket libs

parser = argparse.ArgumentParser()

parser.add_argument('-t', '--target-host', action='store', dest='remote_host', 
    required=True, default=None,
    help="Remote host to LR. Must be FQDN or ipv4")

parser.add_argument('-u', '--user', action='store', dest='user_name', 
    required=True, default=None,
    help="Your domain user name.")

parser.add_argument('-d', '--domain', action='store', dest='domain', 
    required=True, default=None,
    help="The domain if your user account.")

parser.add_argument('-D', '--root-drive', action='store', dest='root_drive', 
    required=False, default="C",
    help="The root (system) drive of the remote system.  Defaults to C:.")

parser.add_argument('--mount-uid', action='store', dest='mount_uid', 
    required=False, default=os.getuid(),
    help="User ID to use when mounting remote filesystems. " + 
    "Defaults to os.getuid()")

parser.add_argument('--mount-gid', action='store', dest='mount_gid', 
    required=False, default=os.getgid(),
    help="Group ID to use when mounting remote filesystems. " +
    "Defaults ot os.getgid()")

parser.add_argument('-m', '--memory', action='store_true', dest='collect_memory', 
    required=False, default=False,
    help="Also collect memory (very large file transfer.)")

parser.add_argument('-f', '--fork', action='store_true', dest='fork',
    required=False, default=False,
    help="Fork off processing into background.")

parser.add_argument('--delete', action='store_true', dest='delete_files',
    required=False, default=False,
    help="Delete LR files on remote system.")

parser.add_argument('-e', '--email-notifications', action='store', 
    dest='email', required=False, default=None,
    help="Whitespace separated list of email addresses to notify " +
    "when processing has completed.")

parser.add_argument('--use-smbclient', action='store_true', dest='use_smbclient',
    required=False, default=False,
    help="Use the smbclient command for file transfers instead of cifs."
    + " Use this when the cifs mounts do not work.")

parser.add_argument('--skip-space-check', action='store_true', 
    dest='skip_space_check',
    required=False, default=False,
    help="Assume the client has enough space for a LR.")

parser.add_argument('--skip-psexec', action='store_true', dest='skip_psexec',
    required=False, default=False,
    help="DEBUG OPTION: skip remote psexec")

parser.add_argument('--lr-prod-dir', action='store', dest='lr_prod_dir',
    required=False, default='win32',
    help="Directory that contains LR tools (starting with win32).")

parser.add_argument('--lr-stage-dir', action='store', dest='lr_stage_dir',
    required=False, default='staging',
    help="Directory to contain collected LR for staging at outpost.")

parser.add_argument('-a', '--analysis-host', action='store', dest='analysis_system',
    required=False, default='localhost',
    help="Host name or ipv4 of analysis system (final destination of LR).")

parser.add_argument('--analysis-user', action='store', dest='analysis_user',
    required=False, default='analysis',
    help="The user account on the analysis server to use.")

parser.add_argument('--analysis-directory', action='store',
    dest='analysis_directory', required=False, default='analysis',
    help="Directory that contains the LRs on the analysis server.")

parser.add_argument('--streamline-script', action='store',
    dest='streamline_script', required=False, 
    default='cd streamline && ./automated_streamline.sh',
    help="Commands to execute to perform the streamline operations.")

args = parser.parse_args()

if args.delete_files and args.use_smbclient:
    logging.error("you cannot --delete and --use-smblient too")
    sys.exit(1)

if not os.path.exists(args.lr_prod_dir):
    logging.error("missing production LR directory: {0}".format(
        args.lr_prod_dir))
    sys.exit(1)

# if we're *not* using smbclient then the mount command should be
# executable via sudo without a password
if not args.use_smbclient:
    pass # TODO do magic here

password = getpass("Enter account password (not echoed to screen): ")

temp_smbclient_authfile = None
temp_cifs_authfile = None
temp_mountpoint = None
tee = None
temp_output_file = None

# fork off at this point
if args.fork:
    if os.fork() != 0:
        print "process running in background"
        sys.exit(0)

# TODO! behave like a good little deamon
#with daemon.DaemonContext():
    #pass

# cleanup files after we're done
def cleanup():
    global temp_smbclient_authfile
    global temp_cifs_authfile
    global temp_mountpoint
    global temp_output_file
    global tee
    global args

    if temp_smbclient_authfile is not None:
        if os.path.exists(temp_smbclient_authfile.name):
            logging.debug("deleting file {0}".format(temp_smbclient_authfile.name))
            os.remove(temp_smbclient_authfile.name)

    if temp_cifs_authfile is not None:
        if os.path.exists(temp_cifs_authfile.name):
            logging.debug("deleting file {0}".format(temp_cifs_authfile.name))
            os.remove(temp_cifs_authfile.name)

    if temp_mountpoint is not None:
        if os.path.exists(temp_mountpoint):
            os.rmdir(temp_mountpoint)

    # send out notification emails
    if args.email is not None:
        mailx = Popen(['mailx', 
            '-s', 'LR for {0} has completed'.format(args.remote_host),
            args.email], stdin=PIPE)

        tee.stdin.close()
        with open(temp_output_file.name, 'rb') as fp:
            shutil.copyfileobj(fp, mailx.stdin)

        os.remove(temp_output_file.name)
        mailx.stdin.close()
        mailx.wait()

# duplicate stdout and stderr to a file we can send in an email
if args.email:
    temp_output_file = NamedTemporaryFile(delete=False)
    tee = Popen(['tee', temp_output_file.name], stdin=PIPE)
    os.dup2(tee.stdin.fileno(), sys.stdout.fileno())
    os.dup2(tee.stdin.fileno(), sys.stderr.fileno())

# make sure our temporary auth file is deleted
atexit.register(cleanup)

# temporary auth file for smb authentication
oldmask = os.umask(077) # keep it safe
try:
    temp_smbclient_authfile = NamedTemporaryFile(delete=False)
    with temp_smbclient_authfile.file:
        temp_smbclient_authfile.file.write(
            'username={0}\\{1}\npassword={2}\n'.format(
            args.domain, args.user_name, password))

    temp_cifs_authfile = NamedTemporaryFile(delete=False)
    with temp_cifs_authfile.file:
        temp_cifs_authfile.file.write(
            'username={0}\npassword={1}\ndomain={2}\n'.format(
            args.user_name, password, args.domain))
except Exception, e:
    logging.error(
"unable to create temporary password file for smb tools: {0}".format(str(e)))
finally:
    os.umask(oldmask)

# watch for the system to come online
logging.info("waiting for host {0} to come online".format(args.remote_host))
while True:
    ping = Popen(['ping', '-c', '1', args.remote_host], stdout=PIPE)
    (stdout, stderr) = ping.communicate()
    if '1 packets transmitted, 1 received, 0% packet loss' in stdout:
        logging.info("host {0} is ONLINE".format(args.remote_host))
        break

    time.sleep(1)

# check remote disk space
if not args.skip_space_check:
    smbclient = Popen([
        'smbclient', 
        '--socket-options=TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072',
        '-A', temp_smbclient_authfile.name, 
        '-c', 'du;',
        '//{0}/{1}$'.format(args.remote_host, args.root_drive)], stdout=PIPE)

    (stdout, stderr) = smbclient.communicate()
    print stdout
    m = re.search(r'blocks of size (\d+)\. (\d+) ', stdout)
    if not m:
        logging.error("unable to determine available disk space")
        sys.exit(1)

    block_size = int(m.group(1))
    blocks_available = int(m.group(2))
    disk_space = blocks_available * block_size

    logging.info("available disk space: {0} bytes".format(disk_space))

    # is there enough space?
    if disk_space < 1024 * 1024 * 1024 * 20: # 20 GB
        logging.error("remote system has less than 20 GB left on device")
        sys.exit(1)

# upload LR package to remote system
logging.info("uploading LR scripts to {0} as {1}".format(
    args.remote_host, args.user_name))

if args.use_smbclient:
    # make sure we can create the lr directory on the remote machine
    smbclient = Popen([
        'smbclient',
        '--socket-options=TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072',
        '-A', temp_smbclient_authfile.name,
        '-c', 'prompt; mkdir \\lr; dir',
        '//{0}/{1}$'.format(args.remote_host, args.root_drive)],
        stdout=PIPE)

    (stdout, stderr) = smbclient.communicate()

    if not re.search(r'\s+lr\s+D\s+0\s+... ... .. ........ ....', stdout):
        logging.error("unable to create lr directory on remote machine")
        sys.exit(1)

    # copy all the files
    smbclient = Popen([
        'smbclient',
        '--socket-options=TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072',
        '-A', temp_smbclient_authfile.name,
        '-c', 'recurse; prompt; cd \\lr; mput {0}'.format(args.lr_prod_dir),
        '//{0}/{1}$'.format(args.remote_host, args.root_drive)])
    smbclient.wait()

else:
    # create a temporary mount point
    temp_mountpoint = mkdtemp(suffix=".mnt")

    mount = Popen([
        'sudo', 
        '/bin/mount', '-t', 'cifs',
        '//{0}/{1}$'.format(args.remote_host, args.root_drive), 
        temp_mountpoint, '--verbose', '-o',
        'credentails={0},rw,uid={1},gid={2},forceuid'.format(
            temp_cifs_authfile.name, args.mount_uid, args.mount_gid)])
    mount.wait()

    if mount.returncode != 0:
        logging.error("unable to mount remote filesystem on {0}".format(
            args.remote_host))
        sys.exit(1)

    # set to True if we're able to transfer the data over
    transfer_ok = False

    while True:

        lr_path = os.path.join(temp_mountpoint, 'lr')
        if not os.path.exists(lr_path):
            try:
                os.mkdir(lr_path)
            except Exception, e:
                logging.error("unable to create lr path {0}: {1}".format(
                    lr_path, str(e)))
                break

        else:
            logging.info("remote lr path {0} already exists".format(lr_path))

        # rsync the lr toolset over
        rsync = Popen(['rsync', '-av', args.lr_prod_dir + '/', lr_path])
        rsync.wait()

        if rsync.returncode != 0:
            logging.error("rsync failed")
            break

        transfer_ok = True
        break

    umount = Popen(['sudo', '/bin/umount', temp_mountpoint])
    umount.wait()

    if umount.returncode != 0:
        logging.error("unable to umount {0}".format(temp_mountpoint))
        sys.exit(1)

    if not transfer_ok:
        sys.exit(1)

# execute psexec.py
# are we collecting memory?
if not args.skip_psexec:

    logging.info("launching LR on {0} username {1} domain {2}".format(
        args.remote_host, args.user_name, args.domain))

    memory_argument = ''
    if args.collect_memory:
        memory_argument = 'mem'

    executer = PSEXEC(
        #'cmd.exe /C test.bat mem', # command
        'cmd.exe /C collect.bat {0}'.format(memory_argument), # command
        '{0}:\\LR\\WIN32\\TOOLS'.format(args.root_drive), # path
        '445/SMB', # protocol XXX hc
        args.user_name, 
        password, 
        args.domain, 
        None # pass the hash? lol
    )
    executer.run(args.remote_host)

logging.info("downloading LR results from {0}".format(args.remote_host))

# make a place to store this result
lr_dest_dir = os.path.join(args.lr_stage_dir, args.remote_host)

# destination already exist?
if os.path.exists(lr_dest_dir):
    try:
        shutil.move(lr_dest_dir, lr_dest_dir + time.strftime('-%Y%m%d%H%M%S'))
    except Exception, e:
        logging.error("unable to move lr_dest_dir: {0}".format(str(e)))
        sys.exit(1)

try:
    os.mkdir(lr_dest_dir)
except Exception,e:
    logging.error("unable to create dir {0}: {1}".format(lr_dest_dir, str(e)))
    sys.exit(1)

if args.use_smbclient:
    smbclient = Popen([
        'smbclient',
        '--socket-options=TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072',
        '-A', temp_smbclient_authfile.name,
        '-c', 'recurse; prompt; lcd "{0}"; cd \\lr\\win32\\output; mget *.7z; {1}'.format(
            lr_dest_dir, 'mget *.hpak;' if args.collect_memory else ''),
        '//{0}/{1}$'.format(args.remote_host, args.root_drive)])
    smbclient.wait()

    if smbclient.returncode != 0:
        logging.error("smbclient failed")
        sys.exit(1)
else:
    # and then... COPY-PASTA  YAY!

    mount = Popen([
        'sudo', 
        '/bin/mount', '-t', 'cifs',
        '//{0}/{1}$'.format(args.remote_host, args.root_drive), 
        temp_mountpoint, '-o',
        'credentails={0},rw,uid={1},gid={2},forceuid'.format(
            temp_cifs_authfile.name, args.mount_uid, args.mount_gid)])
    mount.wait()

    if mount.returncode != 0:
        logging.error("unable to mount remote filesystem on {0}".format(
            args.remote_host))
        sys.exit(1)

    # set to True if we're able to transfer the data over
    transfer_ok = False

    while True:

        output_path = os.path.join(temp_mountpoint, 'lr', 'win32', 'output')
        if not os.path.exists(output_path):
            logging.error("remote missing output path {0}".format(output_path))
            break

        # rsync the results back
        rsync = Popen(['rsync', '-av', output_path + "/", lr_dest_dir])
        rsync.wait()

        if rsync.returncode != 0:
            logging.error("rsync failed")
            break

        transfer_ok = True

        if args.delete_files:
            logging.info("deleting remote lr dir on {0}".format(args.remote_host))
            rm = Popen(['rm', '-rf', os.path.join(temp_mountpoint, 'lr')])
            rm.wait()

            if rm.returncode != 0:
                logging.error("unable to remove remote lr directory")
        
        break

    umount = Popen(['sudo', '/bin/umount', temp_mountpoint])
    umount.wait()

    if umount.returncode != 0:
        logging.error("unable to umount {0}".format(temp_mountpoint))
        sys.exit(1)

    if not transfer_ok:
        sys.exit(1)

# copy the results to the analysis system
ssh_user_spec = '{0}@{1}'.format(args.analysis_user, args.analysis_system)
logging.info("copying {0} to {1}:{2}".format(
    lr_dest_dir, ssh_user_spec, args.analysis_directory))

# TODO use rsync instead of scp
scp = Popen([
    'scp',
    '-r',
    lr_dest_dir,
    "{0}:{1}".format(ssh_user_spec, args.analysis_directory)])
scp.wait()

if scp.returncode != 0:
    logging.error("unable to copy results to analysis server")
    sys.exit(1)

# execute streamline on analysis system
# TODO we might should launch this from the analysis system, eh?
ssh = Popen([
    'ssh',
    ssh_user_spec,
    '{0} {1}'.format(args.streamline_script, args.remote_host)])
ssh.wait()

if ssh.returncode != 0:
    logging.error("unable to process results on analysis server")
    sys.exit(1)

