# FRODO - my little LR helper dude
(with regards to remilliard)

- watches for a host to come online
- uploads your LR stuff to the remote host (with smbclient or cifs mount)
- remotely executes LR using impacket's psexec.py script
- downloads the output of the LR to local directory
- copies local copy of LR results to "analysis system"
- remotely executes some command that processes the LR
- sends email with all the output of the processing
- defeats the armies of Sauron and saves Middle Earth

