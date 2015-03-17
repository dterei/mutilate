#!/usr/bin/python
import os
import sys

## Helper Functions

def CheckPkgConfig(context):
    context.Message('Checking for pkg-config... ')
    ret = context.TryAction('pkg-config --version')[0]
    context.Result(ret)
    return ret

def CheckPkg(context, name):
    context.Message('Checking for %s... ' % name)
    ret = context.TryAction('pkg-config --exists \'%s\'' % name)[0]
    context.Result(ret)
    return ret

def CheckPkgMinVersion(context, name, version):
    context.Message('Checking %s-%s or greater... ' % (name, version))
    ret = context.TryAction('pkg-config --atleast-version \'%s\' \'%s\'' % (version, name))[0]
    context.Result(ret)
    return ret

## Configuration

# setup compilation settings
env = Environment(ENV = os.environ)
env['HAVE_POSIX_BARRIER'] = True
env.Append(CPPPATH = ['/usr/local/include', '/opt/local/include'])
env.Append(LIBPATH = ['/opt/local/lib'])
env.Append(CCFLAGS = '-std=c++11 -D_GNU_SOURCE')
if sys.platform == 'darwin':
    env['CC']  = 'clang'
    env['CXX'] = 'clang++'

# configuration
conf = env.Configure(custom_tests = { 'CheckPkgConfig' : CheckPkgConfig,
                                      'CheckPkg' : CheckPkg,
                                      'CheckPkgMinVersion' : CheckPkgMinVersion
                                      },
                    config_h = 'config.h')

conf.Define("__STDC_FORMAT_MACROS")

# check C++11 support
if not conf.CheckCXX():
    print "A compiler with C++11 support is required."
    Exit(1)

# check for gengetopt
print "Checking for gengetopt...",
if env.Execute("@which gengetopt &> /dev/null"):
    print "not found (required)"
    Exit(1)
else: print "found"

# check for pkg-config & libevent2
if not conf.CheckPkgConfig():
    print 'pkg-config not found!'
    Exit(1)

if not conf.CheckPkg('libevent'):
    print 'libevent is not registered in pkg-config'
    Exit(1)
if not conf.CheckPkgMinVersion("libevent", "2.0"):
    print 'libevent version 2.0 or above required'
    Exit(1)
env.ParseConfig('pkg-config --libs --cflags libevent')

if not conf.CheckLibWithHeader("event", "event2/event.h", "C++"):
    print "libevent required"
    Exit(1)

# check if precise timer support in libevent version
conf.CheckDeclaration("EVENT_BASE_FLAG_PRECISE_TIMER", '#include <event2/event.h>', "C++")

# check for pthread
if not conf.CheckLibWithHeader("pthread", "pthread.h", "C++"):
    print "pthread required"
    Exit(1)

if not conf.CheckFunc('pthread_barrier_init'):
    conf.env['HAVE_POSIX_BARRIER'] = False

# check for real-time clock
conf.CheckLib("rt", "clock_gettime", language="C++")

# check for zmq
conf.CheckLibWithHeader("zmq", "zmq.hpp", "C++")

env = conf.Finish()

## Compilation

env.Append(CFLAGS = ' -O3 -Wall -g')
env.Append(CPPFLAGS = ' -O3 -Wall -g')

env.Command(['cmdline.cc', 'cmdline.h'], 'cmdline.ggo', 'gengetopt < $SOURCE')

src = Split("""mutilate.cc cmdline.cc log.cc distributions.cc util.cc
               Connection.cc Protocol.cc Generator.cc""")

if not env['HAVE_POSIX_BARRIER']: # USE_POSIX_BARRIER:
    src += ['barrier.cc']

env.Program(target='mutilate', source=src)
env.Program(target='gtest', source=['TestGenerator.cc', 'log.cc', 'util.cc',
                                    'Generator.cc'])
