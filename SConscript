# -*- mode:python -*-

# Copyright (c) 2018, 2020 ARM Limited
#
# The license below extends only to copyright in the software and shall
# not be construed as granting a license to any other intellectual
# property including but not limited to intellectual property relating
# to a hardware implementation of the functionality of the software
# licensed hereunder.  You may use the software subject to the license
# terms below provided that you ensure that this notice is replicated
# unmodified and in its entirety in all distributions of the software,
# modified or unmodified, in source code or in binary form.
#
# Copyright (c) 2004-2005 The Regents of The University of Michigan
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met: redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer;
# redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution;
# neither the name of the copyright holders nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import bisect
import collections
import distutils.spawn
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import os
import os.path
import re
import sys

import SCons

from gem5_scons import Transform, warning, error, ToValue, FromValue
from gem5_scons.sources import *

Export(SourceFilter.factories)

# This file defines how to build a particular configuration of gem5
# based on variable settings in the 'env' build environment.

Import('*')

# Children need to see the environment
Export('env')

build_env = [(opt, env[opt]) for opt in export_vars]

from code_formatter import code_formatter

def GdbXml(xml_id, symbol, tags=None, add_tags=None):
    cc, hh = env.Blob(symbol, xml_id)
    Source(cc, tags=tags, add_tags=add_tags)

class Source(SourceFile):
    pass

build_tools = Dir('#build_tools')

# Build a small helper that runs Python code using the same version of Python
# as gem5. This is in an unorthodox location to avoid building it for every
# variant.
gem5py_env = gem5py_env.Clone()
gem5py = gem5py_env.File('gem5py')
gem5py_m5 = gem5py_env.File('gem5py_m5')
gem5py_env['GEM5PY'] = gem5py
gem5py_env['GEM5PY_M5'] = gem5py_m5
gem5py_env['OBJSUFFIX'] = '.pyo'
# Inject build_tools into PYTHONPATH for when we run gem5py.
pythonpath = gem5py_env['ENV'].get('PYTHONPATH', '').split(':')
pythonpath.append(build_tools.abspath)
gem5py_env['ENV']['PYTHONPATH'] = ':'.join(pythonpath)

class PySource(SourceFile):
    '''Add a python source file to the named package'''
    modules = {}

    def __init__(self, package, source, tags=None, add_tags=None):
        '''specify the python package, the source file, and any tags'''
        super().__init__(source, tags, add_tags)

        basename = os.path.basename(self.filename)
        modname, ext = os.path.splitext(basename)
        assert ext == '.py'

        if package:
            modpath = package.split('.')
        else:
            modpath = []

        if modname != '__init__':
            modpath += [ modname ]
        modpath = '.'.join(modpath)

        abspath = self.snode.abspath
        if not os.path.exists(abspath):
            abspath = self.tnode.abspath

        self.modname = modname
        self.modpath = modpath
        self.abspath = abspath

        PySource.modules[modpath] = self

        cpp = File(self.filename + '.cc')

        overrides = {
            'PYSOURCE_MODPATH': modpath,
            'PYSOURCE_ABSPATH': abspath,
            'PYSOURCE': File(source),
            'MARSHAL_PY': build_tools.File('marshal.py')
        }
        gem5py_env.Command(cpp,
            [ '${PYSOURCE}', '${GEM5PY}', '${MARSHAL_PY}' ],
            MakeAction('"${GEM5PY}" "${MARSHAL_PY}" "${TARGET}" ' \
                       '"${PYSOURCE}" "${PYSOURCE_MODPATH}" ' \
                       '"${PYSOURCE_ABSPATH}"',
                       Transform("EMBED PY", max_sources=1)),
            **overrides)
        Source(cpp, tags=self.tags, add_tags=['python', 'm5_module'])

class SimObject(PySource):
    '''Add a SimObject python file as a python source object and add
    it to a list of sim object modules'''

    fixed = False

    sim_objects = dict()
    enums = dict()
    tags = dict()

    def __init__(self, source, *, sim_objects=None, enums=None,
            tags=None, add_tags=None):
        '''Specify the source file and any tags (automatically in
        the m5.objects package)'''
        if sim_objects is None:
            if enums is None:
                error(f"SimObject({source}...) must list c++ sim_objects or "
                      "enums (set either to [] if there are none).")
            sim_objects = []
        if enums is None:
            enums = []

        super().__init__('m5.objects', source, tags, add_tags)
        if self.fixed:
            error("Too late to call SimObject now.")

        SimObject.sim_objects[self.modpath] = sim_objects
        SimObject.enums[self.modpath] = enums
        SimObject.tags[self.modpath] = self.tags

# This regular expression is simplistic and assumes that the import takes up
# the entire line, doesn't have the keyword "public", uses double quotes, has
# no whitespace at the end before or after the ;, and is all on one line. This
# should still cover most cases, and a completely accurate scanner would be
# MUCH more complex.
protoc_import_re = re.compile(r'^import\s+\"(.*\.proto)\"\;$', re.M)

def protoc_scanner(node, env, path):
    deps = []
    for imp in protoc_import_re.findall(node.get_text_contents()):
        deps.append(Dir(env['BUILDDIR']).File(imp))
    return deps

env.Append(SCANNERS=Scanner(function=protoc_scanner, skeys=['.proto']))

def protoc_emitter(target, source, env):
    root, ext = os.path.splitext(source[0].get_abspath())
    return [root + '.pb.cc', root + '.pb.h'], source

protoc_action = MakeAction('${PROTOC} --cpp_out ${BUILDDIR} '
        '--proto_path ${BUILDDIR} ${SOURCE.get_abspath()}',
        Transform("PROTOC"))
protobuf_builder = Builder(action=protoc_action, emitter=protoc_emitter,
        src_suffix='.proto')
env.Append(BUILDERS={'ProtoBufCC' : protobuf_builder})

c_file, cxx_file = SCons.Tool.createCFileBuilders(env)
cxx_file.add_action('.proto', protoc_action)
cxx_file.add_emitter('.proto', protoc_emitter)

def ProtoBuf(source, tags=None, add_tags=None):
    '''Add a Protocol Buffer to build'''

    if not env['HAVE_PROTOC'] or not env['HAVE_PROTOBUF']:
        error('Got protobuf to build, but lacks support!')

    '''Specify the source file, and any tags'''
    Source(source, tags, add_tags, append={'CXXFLAGS': '-Wno-array-bounds'})

env['PROTOC_GRPC'] = distutils.spawn.find_executable('grpc_cpp_plugin')
if env['PROTOC_GRPC']:
    env.Append(LIBS=['grpc++'])

def protoc_grpc_emitter(target, source, env):
    root, ext = os.path.splitext(source[0].get_abspath())
    return [root + '.grpc.pb.cc', root + '.grpc.pb.h'], source

protoc_grpc_action=MakeAction('${PROTOC} --grpc_out ${BUILDDIR} '
        '--plugin=protoc-gen-grpc=${PROTOC_GRPC} --proto_path ${BUILDDIR} '
        '${SOURCE.get_abspath()}',
        Transform("PROTOC"))

env.Append(BUILDERS={'GrpcProtoBufCC' : Builder(
            action=protoc_grpc_action,
            emitter=protoc_grpc_emitter
        )})

def GrpcProtoBuf(source, tags=None, add_tags=None):
    '''Add a GRPC protocol buffer to the build'''

    if not env['PROTOC_GRPC']:
        error('No grpc_cpp_plugin found')

    Source(env.GrpcProtoBufCC(source=source)[0], tags=tags, add_tags=add_tags)
    Source(env.ProtoBufCC(source=source)[0], tags=tags, add_tags=add_tags)



date_source = File('base/date.cc')

class TopLevelMeta(type):
    '''Meta class for top level build products, ie binaries and libraries.'''
    all = []

    def __init__(cls, name, bases, d):
        TopLevelMeta.all.append(cls)
        super().__init__(name, bases, d)
        cls.all = []

class TopLevelBase(object, metaclass=TopLevelMeta):
    '''Base class for linked build products.'''

    def __init__(self, target, *srcs_and_filts):
        '''Specify the target name and any sources. Sources that are
        not SourceFiles are evalued with Source().'''
        super().__init__()
        self.all.append(self)
        self.target = target

        isFilter = lambda arg: isinstance(arg, SourceFilter)
        self.filters = filter(isFilter, srcs_and_filts)
        sources = filter(lambda a: not isFilter(a), srcs_and_filts)

        srcs = SourceList()
        for src in sources:
            if not isinstance(src, SourceFile):
                src = Source(src, tags=[])
            srcs.append(src)
        self.srcs = srcs

        self.dir = Dir('.')

    def sources(self, env):
        srcs = self.srcs
        for f in self.filters:
            srcs += Source.all.apply_filter(env, f)
        return srcs

    def srcs_to_objs(self, env, sources):
        return list([ s.static(env) for s in sources ])

    @classmethod
    def declare_all(cls, env):
        return list([ instance.declare(env) for instance in cls.all ])

class StaticLib(TopLevelBase):
    '''Base class for creating a static library from sources.'''

    def declare(self, env):
        objs = self.srcs_to_objs(env, self.sources(env))

        date_obj = env.StaticObject(date_source)
        env.Depends(date_obj, objs)

        return env.StaticLibrary(self.target, [date_obj, objs])[0]

class SharedLib(TopLevelBase):
    '''Base class for creating a shared library from sources.'''

    def srcs_to_objs(self, env, sources):
        return list([ s.shared(env) for s in sources ])

    def declare(self, env):
        objs = self.srcs_to_objs(env, self.sources(env))

        date_obj = env.SharedObject(date_source)
        env.Depends(date_obj, objs)

        return env.SharedLibrary(self.target, [date_obj, objs])[0]

class Executable(TopLevelBase):
    '''Base class for creating an executable from sources.'''

    def path(self, env):
        return self.dir.File(self.target + '.${ENV_LABEL}')

    def declare(self, env, objs=None):
        if objs is None:
            objs = self.srcs_to_objs(env, self.sources(env))

        env = env.Clone()
        env['BIN_RPATH_PREFIX'] = os.path.relpath(
                env['BUILDDIR'], self.path(env).dir.abspath)

        executable = env.Program(self.path(env).abspath, objs)[0]

        if sys.platform == 'sunos5':
            cmd = 'cp $SOURCE $TARGET; strip $TARGET'
        else:
            cmd = 'strip $SOURCE -o $TARGET'
        stripped = env.Command(str(executable) + '.stripped',
                executable, MakeAction(cmd, Transform("STRIP")))[0]

        return [executable, stripped]

class Gem5(Executable):
    '''Base class for the main gem5 executable.'''

    def declare(self, env):
        objs = self.srcs_to_objs(env, self.sources(env))

        date_obj = env.StaticObject(date_source)
        env.Depends(date_obj, objs)
        objs.append(date_obj)

        return super().declare(env, objs)


class GTest(Executable):
    '''Create a unit test based on the google test framework.'''
    all = []
    def __init__(self, *srcs_and_filts, **kwargs):
        if not kwargs.pop('skip_lib', False):
            srcs_and_filts = srcs_and_filts + (with_tag('gtest lib'),)
        super().__init__(*srcs_and_filts)

    @classmethod
    def declare_all(cls, env):
        env = env.Clone()
        env['OBJSUFFIX'] = '.t' + env['OBJSUFFIX'][1:]
        env['SHOBJSUFFIX'] = '.t' + env['SHOBJSUFFIX'][1:]
        env.Append(LIBS=env['GTEST_LIBS'])
        env.Append(CPPFLAGS=env['GTEST_CPPFLAGS'])
        env['GTEST_OUT_DIR'] = \
            Dir(env['BUILDDIR']).Dir('unittests.${ENV_LABEL}')
        return super().declare_all(env)

    def declare(self, env):
        binary, stripped = super().declare(env)

        out_dir = env['GTEST_OUT_DIR']
        xml_file = out_dir.Dir(str(self.dir)).File(self.target + '.xml')
        AlwaysBuild(env.Command(xml_file.abspath, binary,
            "${SOURCES[0]} --gtest_output=xml:${TARGETS[0]}"))

        return binary


# Children should have access
Export('GdbXml')
Export('Source')
Export('PySource')
Export('SimObject')
Export('ProtoBuf')
Export('GrpcProtoBuf')
Export('Executable')
Export('GTest')

########################################################################
#
# Debug Flags
#

debug_flags = set()
def DebugFlagCommon(name, flags, desc, fmt, tags, add_tags):
    if name == "All":
        raise AttributeError('The "All" flag name is reserved')
    if name in debug_flags:
        raise AttributeError(f'Flag {name} already specified')

    debug_flags.add(name)

    hh_file = Dir(env['BUILDDIR']).Dir('debug').File(f'{name}.hh')
    gem5py_env.Command(hh_file,
        [ '${GEM5PY}', '${DEBUGFLAGHH_PY}' ],
        MakeAction('"${GEM5PY}" "${DEBUGFLAGHH_PY}" "${TARGET}" "${NAME}" ' \
                   '"${DESC}" "${FMT}" "${COMPONENTS}"',
        Transform("TRACING", 0)),
        DEBUGFLAGHH_PY=build_tools.File('debugflaghh.py'),
        NAME=name, DESC=desc, FMT=('True' if fmt else 'False'),
        COMPONENTS=':'.join(flags))
    cc_file = Dir(env['BUILDDIR']).Dir('debug').File('%s.cc' % name)
    gem5py_env.Command(cc_file,
            [ "${GEM5PY}", "${DEBUGFLAGCC_PY}" ],
            MakeAction('"${GEM5PY}" "${DEBUGFLAGCC_PY}" "${TARGET}" "${NAME}"',
                Transform("TRACING", 0)),
            DEBUGFLAGCC_PY=build_tools.File('debugflagcc.py'), NAME=name)
    if not add_tags:
        add_tags = set()
    if isinstance(add_tags, str):
        add_tags = { add_tags }
    if not isinstance(add_tags, set):
        add_tags = set(add_tags)
    add_tags.add('gem5 trace')
    Source(cc_file, tags=tags, add_tags=add_tags)

def DebugFlag(name, desc=None, fmt=False, tags=None, add_tags=None):
    DebugFlagCommon(name, (), desc, fmt, tags=tags, add_tags=add_tags)
def CompoundFlag(name, flags, desc=None, tags=None, add_tags=None):
    DebugFlagCommon(name, flags, desc, False, tags=tags, add_tags=add_tags)
def DebugFormatFlag(name, desc=None, tags=None, add_tags=None):
    DebugFlag(name, desc, True, tags=tags, add_tags=add_tags)

Export('DebugFlag')
Export('CompoundFlag')
Export('DebugFormatFlag')

########################################################################
#
# Set some compiler variables
#

# Include file paths are rooted in this directory.  SCons will
# automatically expand '.' to refer to both the source directory and
# the corresponding build directory to pick up generated include
# files.
env.Append(CPPPATH=Dir('.'))

for extra_dir in extras_dir_list:
    env.Append(CPPPATH=Dir(extra_dir))

########################################################################
#
# Walk the tree and execute all SConscripts in subdirectories
#

here = Dir('.').srcnode().abspath
for root, dirs, files in os.walk(base_dir, topdown=True):
    if root == here:
        # we don't want to recurse back into this SConscript
        continue

    if 'SConscript' in files:
        build_dir = os.path.join(env['BUILDDIR'], root[len(base_dir) + 1:])
        SConscript(os.path.join(root, 'SConscript'), variant_dir=build_dir)

for extra_dir in extras_dir_list:
    prefix_len = len(os.path.dirname(extra_dir)) + 1

    # Also add the corresponding build directory to pick up generated
    # include files.
    env.Append(CPPPATH=Dir(env['BUILDDIR']).Dir(extra_dir[prefix_len:]))

    for root, dirs, files in os.walk(extra_dir, topdown=True):
        # if build lives in the extras directory, don't walk down it
        if 'build' in dirs:
            dirs.remove('build')

        if 'SConscript' in files:
            build_dir = os.path.join(env['BUILDDIR'], root[prefix_len:])
            SConscript(os.path.join(root, 'SConscript'), variant_dir=build_dir)

for opt in export_vars:
    env.ConfigFile(opt)

def makeTheISA(source, target, env):
    isas = sorted(set(env.Split('${ALL_ISAS}')))
    target_isa = env['TARGET_ISA']
    is_null_isa = '1' if (target_isa.lower() == 'null') else '0'

    def namespace(isa):
        return isa[0].upper() + isa[1:].lower() + 'ISA'


    code = code_formatter()
    code('''\
#ifndef __CONFIG_THE_ISA_HH__
#define __CONFIG_THE_ISA_HH__

#define IS_NULL_ISA ${{is_null_isa}}
#define TheISA ${{namespace(target_isa)}}

#endif // __CONFIG_THE_ISA_HH__''')

    code.write(str(target[0]))

env.Command('config/the_isa.hh', [],
            MakeAction(makeTheISA, Transform("CFG ISA", 0)))

def makeTheGPUISA(source, target, env):
    gpu_isa = env['TARGET_GPU_ISA']

    namespace = gpu_isa[0].upper() + gpu_isa[1:].lower() + 'ISA'

    code = code_formatter()
    code('''\
#ifndef TheGpuISA
#define TheGpuISA ${namespace}
#endif // TheGpuISA''')

    code.write(str(target[0]))

env.Command('config/the_gpu_isa.hh', [],
            MakeAction(makeTheGPUISA, Transform("CFG ISA", 0)))

########################################################################
#
# Prevent any SimObjects from being added after this point, they
# should all have been added in the SConscripts above
#
SimObject.fixed = True

class SimpleModuleLoader(importlib.abc.Loader):
    '''A simple wrapper which delegates setting up a module to a function.'''
    def __init__(self, executor):
        super().__init__()
        self.executor = executor
    def create_module(self, spec):
        return None

    def exec_module(self, module):
        self.executor(module)

class M5MetaPathFinder(importlib.abc.MetaPathFinder):
    def __init__(self, modules):
        super().__init__()
        self.modules = modules
        self.installed = set()

    def unload(self):
        import sys
        for module in self.installed:
            del sys.modules[module]
        self.installed = set()

    def find_spec(self, fullname, path, target=None):
        spec = None

        # If this isn't even in the m5 package, ignore it.
        if fullname.startswith('m5.'):
            if fullname.startswith('m5.objects'):
                # When imported in this context, return a spec for a dummy
                # package which just serves to house the modules within it.
                # This is subtley different from "import * from m5.objects"
                # which relies on the __init__.py in m5.objects. That in turn
                # indirectly relies on the c++ based _m5 package which doesn't
                # exist yet.
                if fullname == 'm5.objects':
                    dummy_loader = SimpleModuleLoader(lambda x: None)
                    spec = importlib.machinery.ModuleSpec(
                            name=fullname, loader=dummy_loader,
                            is_package=True)
                    spec.loader_state = self.modules.keys()

                # If this is a module within the m5.objects package, return a
                # spec that maps to its source file.
                elif fullname in self.modules:
                    source = self.modules[fullname]
                    spec = importlib.util.spec_from_file_location(
                            name=fullname, location=source.abspath)

            # The artificial m5.defines subpackage.
            elif fullname == 'm5.defines':
                def build_m5_defines(module):
                    module.__dict__['buildEnv'] = dict(build_env)

                spec = importlib.util.spec_from_loader(name=fullname,
                        loader=SimpleModuleLoader(build_m5_defines))

        # If we're handling this module, write it down so we can unload it
        # later.
        if spec is not None:
            self.installed.add(fullname)

        return spec

import m5.SimObject
import m5.params

m5.SimObject.clear()
m5.params.clear()

# install the python importer so we can grab stuff from the source
# tree itself.  We can't have SimObjects added after this point or
# else we won't know about them for the rest of the stuff.
importer = M5MetaPathFinder(PySource.modules)
sys.meta_path[0:0] = [ importer ]

import_globals = globals().copy()
# import all sim objects so we can populate the all_objects list
# make sure that we're working with a list, then let's sort it
gem5_lib_simobjects = SimObject.all.with_tag(env, 'gem5 lib')
gem5_lib_modnames = sorted(map(lambda so: so.modname, gem5_lib_simobjects))
for modname in gem5_lib_modnames:
    exec('from m5.objects import %s' % modname, import_globals)

# we need to unload all of the currently imported modules so that they
# will be re-imported the next time the sconscript is run
importer.unload()
sys.meta_path.remove(importer)

sim_objects = m5.SimObject.allClasses
all_enums = m5.params.allEnums

########################################################################
#
# calculate extra dependencies
#
module_depends = ["m5", "m5.SimObject", "m5.params"]
depends = [ PySource.modules[dep].snode for dep in module_depends ]
depends.sort(key = lambda x: x.name)

########################################################################
#
# Commands for the basic automatically generated python files
#

# Generate Python file containing a dict specifying the current
# buildEnv flags.
def makeDefinesPyFile(target, source, env):
    code = code_formatter()
    code("buildEnv = $0", FromValue(source[0]))
    code.write(target[0].abspath)

# Generate a file with all of the compile options in it
env.Command('python/m5/defines.py', ToValue(dict(build_env)),
            MakeAction(makeDefinesPyFile, Transform("DEFINES", 0)))
PySource('m5', 'python/m5/defines.py')

# Generate a file that wraps the basic top level files
gem5py_env.Command('python/m5/info.py',
            [ File('#/COPYING'), File('#/LICENSE'), File('#/README'),
                "${GEM5PY}", "${INFOPY_PY}" ],
            MakeAction('"${GEM5PY}" "${INFOPY_PY}" "${TARGET}" '
                       '${SOURCES[:-2]}',
                Transform("INFO", 3)),
            INFOPY_PY=build_tools.File('infopy.py'))
PySource('m5', 'python/m5/info.py')

gem5py_m5_env = gem5py_env.Clone()
gem5py_env.Append(CPPPATH=env['CPPPATH'])
gem5py_env.Append(LIBS='z')
gem5py_env.Program(gem5py, 'python/gem5py.cc')[0]
m5_module_source = \
        Source.all.with_all_tags(env, 'm5_module', 'gem5 lib')
m5_module_static = list(map(lambda s: s.static(gem5py_env), m5_module_source))
gem5py_env.Program(gem5py_m5, [ 'python/gem5py.cc' ] + m5_module_static)

########################################################################
#
# Create all of the SimObject param headers and enum headers
#

# Generate all of the SimObject param C++ struct header files

for module, simobjs in sorted(SimObject.sim_objects.items()):
    tags = SimObject.tags[module]
    for simobj in simobjs:
        gem5py_env.Command([ "${PARAMS_HH}" ],
                [ Value(module), Value(simobj),
                    "${GEM5PY_M5}", "${PARAMSTRUCT_PY}" ],
                MakeAction('"${GEM5PY_M5}" "${PARAMSTRUCT_PY}" "${MODULE}" ' \
                        '"${PARAMS_HH}"',
                    Transform("SO Param", 2)),
                MODULE=module,
                SIMOBJ=simobj,
                PARAMSTRUCT_PY=build_tools.File(
                    'sim_object_param_struct_hh.py'),
                PARAMS_HH=File(f'params/{simobj}.hh'))
        cc_file = File(f'python/_m5/param_{simobj}.cc')
        gem5py_env.Command([ "${PARAMS_CC}" ],
                [ Value(module), Value(simobj),
                    "${GEM5PY_M5}", "${PARAMSTRUCT_PY}" ],
                MakeAction('"${GEM5PY_M5}" "${PARAMSTRUCT_PY}" "${MODULE}" ' \
                        '"${PARAMS_CC}" "${USE_PYTHON}"',
                    Transform("SO Param", 2)),
                PARAMSTRUCT_PY=build_tools.File(
                    'sim_object_param_struct_cc.py'),
                MODULE=module,
                SIMOBJ=simobj,
                PARAMS_CC=cc_file,
                USE_PYTHON=env['USE_PYTHON'])
        Source(cc_file, tags=tags, add_tags='python')

# C++ parameter description files
if GetOption('with_cxx_config'):
    def createSimObjectCxxConfig(is_header):
        def body(target, source, env):
            assert len(target) == 1 and len(source) == 1

            name = source[0].get_contents().decode('utf-8')
            obj = sim_objects[name]

            code = code_formatter()
            obj.cxx_config_param_file(code, is_header)
            code.write(target[0].abspath)
        return body

    for name,simobj in sorted(sim_objects.items()):
        py_source = PySource.modules[simobj.__module__]
        extra_deps = [ py_source.tnode ]

        cxx_config_hh_file = File('cxx_config/%s.hh' % name)
        cxx_config_cc_file = File('cxx_config/%s.cc' % name)
        env.Command(cxx_config_hh_file, Value(name),
                    MakeAction(createSimObjectCxxConfig(True),
                    Transform("CXXCPRHH")))
        env.Command(cxx_config_cc_file, Value(name),
                    MakeAction(createSimObjectCxxConfig(False),
                    Transform("CXXCPRCC")))
        env.Depends(cxx_config_hh_file, depends + extra_deps)
        env.Depends(cxx_config_cc_file, depends + extra_deps)
        Source(cxx_config_cc_file)

    cxx_config_init_cc_file = File('cxx_config/init.cc')

    def createCxxConfigInitCC(target, source, env):
        assert len(target) == 1

        code = code_formatter()

        for name,simobj in sorted(sim_objects.items()):
            if not hasattr(simobj, 'abstract') or not simobj.abstract:
                code('#include "cxx_config/${name}.hh"')
        code()
        code('namespace gem5')
        code('{')
        code()
        code('void cxxConfigInit()')
        code('{')
        code.indent()
        for name,simobj in sorted(sim_objects.items()):
            not_abstract = not hasattr(simobj, 'abstract') or \
                not simobj.abstract
            if not_abstract and 'type' in simobj.__dict__:
                code('cxx_config_directory["${name}"] = '
                     '${name}CxxConfigParams::makeDirectoryEntry();')
        code.dedent()
        code('}')
        code('')
        code('} // namespace gem5')
        code.write(target[0].abspath)

    env.Command(cxx_config_init_cc_file, [],
        MakeAction(createCxxConfigInitCC, Transform("CXXCINIT")))
    Source(cxx_config_init_cc_file)

# Generate all enum header files
def createEnumStrings(target, source, env):
    assert len(target) == 1 and len(source) == 2

    name = source[0].get_text_contents()
    use_python = source[1].read()
    obj = all_enums[name]

    code = code_formatter()
    obj.cxx_def(code)
    if use_python:
        obj.pybind_def(code)
    code.write(target[0].abspath)

def createEnumDecls(target, source, env):
    assert len(target) == 1 and len(source) == 1

    name = source[0].get_text_contents()
    obj = all_enums[name]

    code = code_formatter()
    obj.cxx_decl(code)
    code.write(target[0].abspath)

for name,enum in sorted(all_enums.items()):
    py_source = PySource.modules[enum.__module__]
    extra_deps = [ py_source.tnode ]

    cc_file = File('enums/%s.cc' % name)
    env.Command(cc_file, [Value(name), Value(env['USE_PYTHON'])],
                MakeAction(createEnumStrings, Transform("ENUM STR")))
    env.Depends(cc_file, depends + extra_deps)
    Source(cc_file)

    hh_file = File('enums/%s.hh' % name)
    env.Command(hh_file, Value(name),
                MakeAction(createEnumDecls, Transform("ENUMDECL")))
    env.Depends(hh_file, depends + extra_deps)


# version tags
tags = \
env.Command('sim/tags.cc', None,
            MakeAction('util/cpt_upgrader.py --get-cc-file > $TARGET',
                       Transform("VER TAGS")))
env.AlwaysBuild(tags)

########################################################################
#
# Define binaries.  Each different build type (debug, opt, etc.) gets
# a slightly different build environment.
#

env['SHOBJSUFFIX'] = '${OBJSUFFIX}s'

envs = {
    'debug': env.Clone(ENV_LABEL='debug', OBJSUFFIX='.do'),
    'opt': env.Clone(ENV_LABEL='opt', OBJSUFFIX='.o'),
    'fast': env.Clone(ENV_LABEL='fast', OBJSUFFIX='.fo'),
}

envs['debug'].Append(CPPDEFINES=['DEBUG', 'TRACING_ON=1'])
envs['opt'].Append(CCFLAGS=['-g'], CPPDEFINES=['TRACING_ON=1'])
envs['fast'].Append(CPPDEFINES=['NDEBUG', 'TRACING_ON=0'])

# For Link Time Optimization, the optimisation flags used to compile
# individual files are decoupled from those used at link time
# (i.e. you can compile with -O3 and perform LTO with -O0), so we need
# to also update the linker flags based on the target.
if env['GCC']:
    if sys.platform == 'sunos5':
        envs['debug'].Append(CCFLAGS=['-gstabs+'])
    else:
        envs['debug'].Append(CCFLAGS=['-ggdb3'])
    envs['debug'].Append(LINKFLAGS=['-O0'])
    # opt and fast share the same cc flags, also add the optimization to the
    # linkflags as LTO defers the optimization to link time
    for target in ['opt', 'fast']:
        envs[target].Append(CCFLAGS=['-O3', '${LTO_CCFLAGS}'])
        envs[target].Append(LINKFLAGS=['-O3', '${LTO_LINKFLAGS}'])

elif env['CLANG']:
    envs['debug'].Append(CCFLAGS=['-g', '-O0'])
    # opt and fast share the same cc flags
    for target in ['opt', 'fast']:
        envs[target].Append(CCFLAGS=['-O3'])
else:
    error('Unknown compiler, please fix compiler options')


# To speed things up, we only instantiate the build environments we need. We
# try to identify the needed environment for each target; if we can't, we fall
# back on instantiating all the environments just to be safe.

# A set of all the extensions on targets.
target_exts = set({ os.path.splitext(t)[1] for t in BUILD_TARGETS })
needed_envs = set()
for ext in target_exts:
    match = next((e for e in envs.values() if ext in (
                    '.' + e['ENV_LABEL'], e['OBJSUFFIX'])), None)
    if match:
        needed_envs.add(match['ENV_LABEL'])
    else:
        needed_envs |= set(envs.keys())
        break


# SCons doesn't know to append a library suffix when there is a '.' in the
# name. Use '_' instead.
lib_name = 'gem5_${ENV_LABEL}'

lib_filter = with_tag('gem5 lib')

# Without Python, leave out all Python content from the library builds. The
# option doesn't affect gem5 built as a program.
if GetOption('without_python'):
    lib_filter = lib_filter & without_tag('python')

StaticLib(lib_name, lib_filter)
SharedLib(lib_name, lib_filter)

Gem5('gem5', with_any_tags('gem5 lib', 'main'))


# Function to create a new build environment as clone of current
# environment 'env' with modified object suffix and optional stripped
# binary.
for env in (envs[e] for e in needed_envs):
    for cls in TopLevelMeta.all:
        cls.declare_all(env)
