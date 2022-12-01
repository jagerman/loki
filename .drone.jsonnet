local default_deps_nocxx = [
  'libboost-program-options-dev',
  'libboost-serialization-dev',
  'libboost-thread-dev',
  'libcurl4-openssl-dev',
  'libevent-dev',
  'libgtest-dev',
  'libhidapi-dev',
  'libreadline-dev',
  'libsodium-dev',
  'libsqlite3-dev',
  'libssl-dev',
  'libsystemd-dev',
  'libunbound-dev',
  'libunwind8-dev',
  'libusb-1.0-0-dev',
  'nettle-dev',
  'pkg-config',
  'python3',
  'qttools5-dev',
];
local default_deps = ['g++'] + default_deps_nocxx;  // g++ sometimes needs replacement

local gtest_filter = '-AddressFromURL.Failure:DNSResolver.DNSSEC*';

local docker_base = 'registry.oxen.rocks/lokinet-ci-';

local submodules_commands = ['git fetch --tags', 'git submodule update --init --recursive --depth=1 --jobs=4'];
local submodules = {
  name: 'submodules',
  image: 'drone/git',
  commands: submodules_commands,
};

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';

local cmake_options(opts) = std.join(' ', [' -D' + o + '=' + (if opts[o] then 'ON' else 'OFF') for o in std.objectFields(opts)]) + ' ';

// Regular build on a debian-like system:
local debian_pipeline(name,
                      image,
                      arch='amd64',
                      deps=default_deps,
                      build_type='Release',
                      lto=false,
                      werror=false,  // FIXME
                      build_tests=true,
                      test_oxend=true,  // Simple oxend offline startup test
                      run_tests=false,  // Runs full test suite
                      cmake_extra='',
                      extra_cmds=[],
                      extra_steps=[],
                      jobs=6,
                      kitware_cmake_distro='',
                      allow_fail=false) = {
  kind: 'pipeline',
  type: 'docker',
  name: name,
  platform: { arch: arch },
  steps: [
    submodules,
    {
      name: 'build',
      image: image,
      pull: 'always',
      [if allow_fail then 'failure']: 'ignore',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' }, GTEST_FILTER: gtest_filter },
      commands: [
        'echo "Building on ${DRONE_STAGE_MACHINE}"',
        apt_get_quiet + ' update',
        apt_get_quiet + ' install -y eatmydata',
        'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
      ] + (
        if kitware_cmake_distro != '' then
          [
            'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y curl ca-certificates',
            'curl https://apt.kitware.com/keys/kitware-archive-latest.asc | gpg --dearmor - >/etc/apt/trusted.gpg.d/kitware.gpg',
            'echo deb https://apt.kitware.com/ubuntu/ ' + kitware_cmake_distro + ' main >/etc/apt/sources.list.d/kitware.list',
            apt_get_quiet + ' update',
          ] else []
      ) + [
        'eatmydata ' + apt_get_quiet + ' install -y --no-install-recommends cmake git ninja-build ccache '
        + (if test_oxend then 'gdb ' else '') + std.join(' ', deps),
        'mkdir build',
        'cd build',
        'cmake .. -G Ninja -DCMAKE_CXX_FLAGS=-fdiagnostics-color=always -DCMAKE_BUILD_TYPE=' + build_type + ' ' +
        '-DLOCAL_MIRROR=https://builds.lokinet.dev/deps '
        + cmake_options({ USE_LTO: lto, WARNINGS_AS_ERRORS: werror, BUILD_TESTS: build_tests || run_tests })
        + cmake_extra,
      ] + (
        if arch == 'arm64' && jobs > 1 then
          // The wallet code is too bloated to be compiled at -j2 with only 4GB ram, so do
          // the huge bloated jobs at -j1 and the rest at -j2
          ['ninja -j1 rpc wallet -v', 'ninja -j2 daemon -v', 'ninja -j1 wallet_rpc_server -v', 'ninja -j2 -v']
        else
          ['ninja -j' + jobs + ' -v']
      ) + (
        if test_oxend then [
          '(sleep 3; echo "status\ndiff\nexit") | TERM=xterm ../utils/build_scripts/drone-gdb.sh ./bin/oxend --offline --data-dir=startuptest',
        ] else []
      ) + (
        if run_tests then [
          'mkdir -v -p $$HOME/.oxen',
          'GTEST_COLOR=1 ctest --output-on-failure -j' + jobs,
        ] else []
      ) + extra_cmds,
    },
  ] + extra_steps,
};

local clang(version, lto=false) = debian_pipeline(
  'Debian sid/clang-' + version + ' (amd64)',
  docker_base + 'debian-sid-clang',
  deps=['clang-' + version] + default_deps_nocxx,
  cmake_extra='-DCMAKE_C_COMPILER=clang-' + version + ' -DCMAKE_CXX_COMPILER=clang++-' + version + ' ',
  lto=lto
);

// Macos build
local mac_builder(name,
                  build_type='Release',
                  lto=false,
                  werror=false,  // FIXME
                  build_tests=true,
                  run_tests=false,
                  cmake_extra='',
                  extra_cmds=[],
                  extra_steps=[],
                  jobs=6,
                  allow_fail=false) = {
  kind: 'pipeline',
  type: 'exec',
  name: name,
  platform: { os: 'darwin', arch: 'amd64' },
  steps: [
    { name: 'submodules', commands: submodules_commands },
    {
      name: 'build',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' }, GTEST_FILTER: gtest_filter },
      commands: [
        // If you don't do this then the C compiler doesn't have an include path containing
        // basic system headers.  WTF apple:
        'export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"',
        'mkdir build',
        'cd build',
        'cmake .. -G Ninja -DCMAKE_CXX_FLAGS=-fcolor-diagnostics -DCMAKE_BUILD_TYPE=' + build_type + ' ' +
        '-DLOCAL_MIRROR=https://builds.lokinet.dev/deps -DUSE_LTO=' + (if lto then 'ON ' else 'OFF ') +
        (if werror then '-DWARNINGS_AS_ERRORS=ON ' else '') +
        (if build_tests || run_tests then '-DBUILD_TESTS=ON ' else '') +
        cmake_extra,
        'ninja -j' + jobs + ' -v',
      ] + (
        if run_tests then [
          'mkdir -v -p $$HOME/.oxen',
          'GTEST_COLOR=1 ctest --output-on-failure -j' + jobs,
        ] else []
      ) + extra_cmds,
    },
  ] + extra_steps,
};

local static_check_and_upload = [
  '../utils/build_scripts/drone-check-static-libs.sh',
  'ninja strip_binaries',
  'ninja create_tarxz',
  '../utils/build_scripts/drone-static-upload.sh',
];

local static_build_deps = [
  'autoconf',
  'automake',
  'file',
  'gperf',
  'libtool',
  'make',
  'openssh-client',
  'patch',
  'pkg-config',
  'qttools5-dev',
];


local android_build_steps(android_abi, android_platform=21, jobs=6, cmake_extra='') = [
  'mkdir build-' + android_abi,
  'cd build-' + android_abi,
  'cmake .. -DCMAKE_CXX_FLAGS=-fdiagnostics-color=always -DCMAKE_C_FLAGS=-fdiagnostics-color=always ' +
  '-DCMAKE_BUILD_TYPE=Release ' +
  '-DCMAKE_TOOLCHAIN_FILE=/usr/lib/android-sdk/ndk-bundle/build/cmake/android.toolchain.cmake ' +
  '-DANDROID_PLATFORM=' + android_platform + ' -DANDROID_ABI=' + android_abi + ' ' +
  cmake_options({ MONERO_SLOW_HASH: true, WARNINGS_AS_ERRORS: false, BUILD_TESTS: false }) +
  '-DLOCAL_MIRROR=https://builds.lokinet.dev/deps ' +
  '-DBUILD_STATIC_DEPS=ON -DSTATIC=ON -G Ninja ' + cmake_extra,
  'ninja -j' + jobs + ' -v wallet_merged',
  'cd ..',
];

local gui_wallet_step(image, wine=false) = {
  name: 'GUI Wallet (dev)',
  platform: { arch: 'amd64' },
  image: image,
  pull: 'always',
  environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
  commands: (if wine then ['dpkg --add-architecture i386'] else []) + [
    apt_get_quiet + ' update',
    apt_get_quiet + ' install -y eatmydata',
    'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
    'eatmydata ' + apt_get_quiet + ' install -y --no-install-recommends git ssh curl ca-certificates binutils make' + (if wine then ' wine32 wine sed' else ''),
    'curl -sSL https://deb.nodesource.com/setup_14.x | bash -',
    'eatmydata ' + apt_get_quiet + ' update',
    'eatmydata ' + apt_get_quiet + ' install -y nodejs',
    'git clone https://github.com/loki-project/loki-electron-gui-wallet.git',
    'cp -v build/bin/oxend' + (if wine then '.exe' else '') + ' loki-electron-gui-wallet/bin',
    'cp -v build/bin/oxen-wallet-rpc' + (if wine then '.exe' else '') + ' loki-electron-gui-wallet/bin',
    'cd loki-electron-gui-wallet',
    'eatmydata npm install',
    'sed -i -e \'s/^\\\\( *"version": ".*\\\\)",/\\\\\\\\1-${DRONE_COMMIT_SHA:0:8}",/\' package.json',
  ] + (if wine then ['sed -i -e \'s/^\\\\( *"build": "quasar.*\\\\)",/\\\\\\\\1 --target=win",/\' package.json'] else []) + [
    'eatmydata npm run build',
    '../utils/build_scripts/drone-wallet-upload.sh',
  ],
};
local gui_wallet_step_darwin = {
  name: 'GUI Wallet (dev)',
  platform: { os: 'darwin', arch: 'amd64' },
  environment: { SSH_KEY: { from_secret: 'SSH_KEY' }, CSC_IDENTITY_AUTO_DISCOVERY: 'false' },
  commands: [
    'git clone https://github.com/loki-project/loki-electron-gui-wallet.git',
    'cp -v build/bin/{oxend,oxen-wallet-rpc} loki-electron-gui-wallet/bin',
    'cd loki-electron-gui-wallet',
    'sed -i -e \'s/^\\\\( *"version": ".*\\\\)",/\\\\1-${DRONE_COMMIT_SHA:0:8}",/\' package.json',
    'npm install',
    'npm run build',
    '../utils/build_scripts/drone-wallet-upload.sh',
  ],
};


[

  // Macos builds:
  mac_builder('macOS (Static)',
              cmake_extra='-DBUILD_STATIC_DEPS=ON -DARCH=core2 -DARCH_ID=amd64',
              build_tests=false,
              lto=true,
              extra_cmds=static_check_and_upload,/*extra_steps=[gui_wallet_step_darwin]*/),


]
