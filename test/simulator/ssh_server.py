# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from twisted.conch import avatar, recvline
from twisted.conch.interfaces import IConchUser, ISession
from twisted.conch.ssh import factory, keys, session
from twisted.conch.insults import insults
from twisted.cred import portal, checkers
from twisted.internet import reactor
from zope.interface import implements
import sys
import yaml


class SSHDemoProtocol(recvline.HistoricRecvLine):

    def __init__(self, user):
        self.user = user

    def connectionMade(self):
        recvline.HistoricRecvLine.connectionMade(self)
        self.terminal.write("Welcome to my test SSH server.")
        self.terminal.nextLine()
        self.do_help()
        self.showPrompt()

    def showPrompt(self):
        self.terminal.write(get_prompt())

    def getCommandFunc(self, cmd):
        return getattr(self, 'do_' + cmd, None)

    def lineReceived(self, line):
        line = line.strip()
        if line:
            print line
            cmdAndArgs = line.split()
            cmd = cmdAndArgs[0]
            args = cmdAndArgs[1:]
            func = self.getCommandFunc(cmd)
            if func:
                try:
                    func(*args)
                except Exception, e:
                    self.terminal.write("Error: %s" % e)
                    self.terminal.nextLine()
            else:
                self.terminal.write("No such command.")
                self.terminal.nextLine()
        self.showPrompt()

    def do_help(self):
        publicMethods = filter(
                lambda funcname: funcname.startswith('do_'), dir(self))
        commands = [cmd.replace('do_', '', 1) for cmd in publicMethods]
        self.terminal.write("Commands: " + " ".join(commands))
        self.terminal.nextLine()

    def do_echo(self, *args):
        self.terminal.write(" ".join(args))
        self.terminal.nextLine()

    def do_show(self, *args):
        command = 'show' + ' ' + reduce((lambda x, y: x + ' ' + y), args)
        self.terminal.write(get_command_output(command))
        self.terminal.nextLine()

    def do_display(self, *args):
        command = 'display' + ' ' + reduce((lambda x, y: x + ' ' + y), args)
        self.terminal.write(get_command_output(command))
        self.terminal.nextLine()

    def do_whoami(self):
        self.terminal.write(self.user.username)
        self.terminal.nextLine()

    def do_quit(self):
        self.terminal.write("Thanks for playing!")
        self.terminal.nextLine()
        self.terminal.loseConnection()

    def do_exit(self):
        self.do_quit()

    def do_clear(self):
        self.terminal.reset()


class SSHDemoAvatar(avatar.ConchUser):
    implements(ISession)

    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({'session': session.SSHSession})

    def openShell(self, protocol):
        serverProtocol = insults.ServerProtocol(SSHDemoProtocol, self)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))

    def getPty(self, terminal, windowSize, attrs):
        return None

    def execCommand(self, protocol, cmd):
        raise NotImplementedError()

    def closed(self):
        pass


class SSHDemoRealm(object):
    implements(portal.IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        if IConchUser in interfaces:
            return interfaces[0], SSHDemoAvatar(avatarId), lambda: None
        else:
            raise NotImplementedError("No supported interfaces found.")


def getRSAKeys():
    with open(get_id_rsa()) as privateBlobFile:
        privateBlob = privateBlobFile.read()
        privateKey = keys.Key.fromString(data=privateBlob)

    with open(get_id_rsa_pub()) as publicBlobFile:
        publicBlob = publicBlobFile.read()
        publicKey = keys.Key.fromString(data=publicBlob)

    return publicKey, privateKey


def get_id_rsa_pub():
    return 'certs/id_rsa.pub'


def get_prompt():
    return config['prompt']


def get_id_rsa():
    return 'certs/id_rsa'


def get_command_output(command):
    return config[command]


if __name__ == "__main__":
    with open('switch_sample/' + sys.argv[1]) as config:
        config = yaml.load(config)

    sshFactory = factory.SSHFactory()
    sshFactory.portal = portal.Portal(SSHDemoRealm())
    users = {'admin': 'aaa', 'guest': 'bbb'}
    sshFactory.portal.registerChecker(
            checkers.InMemoryUsernamePasswordDatabaseDontUse(**users))
    pubKey, privKey = getRSAKeys()
    sshFactory.publicKeys = {'ssh-rsa': pubKey}
    sshFactory.privateKeys = {'ssh-rsa': privKey}
    reactor.listenTCP(22222, sshFactory)
    reactor.run()
