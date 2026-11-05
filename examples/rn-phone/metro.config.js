const path = require('path');
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

// react-native-tailpocket and tailpocket-client are linked from this repository's sdk/
// (file: dependencies); Metro has to watch them and resolve their imports from this app.
const sdk = path.resolve(__dirname, '../../sdk');

/** @type {import('@react-native/metro-config').MetroConfig} */
const config = {
  watchFolders: [path.join(sdk, 'react-native'), path.join(sdk, 'js')],
  resolver: { nodeModulesPaths: [path.join(__dirname, 'node_modules')] },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
