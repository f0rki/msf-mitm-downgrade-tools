#! /usr/bin/python2.6
# -*- coding: utf-8 -*-

from twisted.mail import imap4, maildir
from twisted.internet import reactor, defer, protocol
from twisted.cred import portal, checkers, credentials
from twisted.cred import error as credError
from twisted.python import filepath
from zope.interface import implements
import time, os, random, pickle

import email

class IMAPServerProtocol(imap4.IMAP4Server):
    "Subclass of imap4.IMAP4Server that adds debugging."
    debug = True

    def lineReceived(self, line):
        if self.debug:
            print "CLIENT:", line
        imap4.IMAP4Server.lineReceived(self, line)

    def sendLine(self, line):
        imap4.IMAP4Server.sendLine(self, line)
        if self.debug:
            print "SERVER:", line



class IMAPFactory(protocol.Factory):
    protocol = IMAPServerProtocol

    def buildProtocol(self, address):
        p = self.protocol()
        p.factory = self
        return p

if __name__ == "__main__":
    PORT = 143
    factory = IMAPFactory()
    reactor.listenTCP(PORT, factory)
    reactor.run()

