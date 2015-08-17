# vncrepeater
VNC Repeater based on UltraVNC Repeater

The code-base was synced from https://code.google.com/p/vncrepeater/ . 

*The goal

The aim of this project is to build a VNC repeater that is compatible with standard VNC viewers. It will work with desktop viewers, iPhone viewers, and any VNC Viewer supporting RFB Protocol 3.3 (That should be any current viewer). The repeater compiles under Windows and LINUX operating systems... Probablly will compile on other POSIX operating systems but I haven't tried this.

*How it works

When you connect from a VNC viewer to the repeater it will ask for a password, the password is the desired repeater ID. Keep in mind that VNC authentication only allows for 8 character passwords, so that is the limit of the repeater ID (right now it only works with digits).

In other words, just connect to the Repeater as if it was an ordinary VNC Server with a password set with the value of the repeater ID. 


1. Linux:

  To build a release version just type "make release", for a debug version type "make debug". 
2. 
