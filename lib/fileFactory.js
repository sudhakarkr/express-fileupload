'use strict';

const path = require('path');
const {
  isFunc,
  debugLog,
  moveFile,
  promiseCallback,
  checkAndMakeDir,
  saveBufferToFile
} = require('./utilities');

/**
 * Sanitize the filename to prevent directory traversal vectors.
 * @param {string} name 
 * @returns {string}
 */
const safeFilename = (name) => {
  if (typeof name !== 'string') return '';
  return path.basename(name);
};

/**
 * Validate the caller-supplied destination path for mv(). This is a defense
 * in depth check on top of the filename sanitization performed at parse time:
 * it rejects obviously malicious values (non-strings, empty strings, NUL bytes).
 * The library cannot know the intended upload directory of the calling
 * application, so we only reject clearly invalid inputs here rather than
 * attempting to constrain to a base directory.
 * @param {*} filePath
 * @returns {Error|null}
 */
const validateDestinationPath = (filePath) => {
  if (typeof filePath !== 'string' || filePath.length === 0) {
    return new Error('mv() destination path must be a non-empty string');
  }
  if (filePath.indexOf('\0') !== -1) {
    return new Error('mv() destination path must not contain NUL bytes');
  }
  // Prevent directory traversal sequences in the destination path
  const normalized = path.normalize(filePath);
  if (normalized.split(path.sep).includes('..')) {
    return new Error('mv() destination path must not contain directory traversal sequences');
  }
  return null;
};

/**
 * Returns Local function that moves the file to a different location on the filesystem
 * which takes two function arguments to make it compatible w/ Promise or Callback APIs
 * @param {String} filePath - destination file path.
 * @param {Object} options - file factory options.
 * @param {Object} fileUploadOptions - middleware options.
 * @returns {Function}
 */
const moveFromTemp = (filePath, options, fileUploadOptions) => (resolve, reject) => {
  debugLog(fileUploadOptions, `Moving temporary file ${options.tempFilePath} to ${filePath}`);
  moveFile(options.tempFilePath, filePath, promiseCallback(resolve, reject));
};

/**
 * Returns Local function that moves the file from buffer to a different location on the filesystem
 * which takes two function arguments to make it compatible w/ Promise or Callback APIs
 * @param {String} filePath - destination file path.
 * @param {Object} options - file factory options.
 * @param {Object} fileUploadOptions - middleware options.
 * @returns {Function}
 */
const moveFromBuffer = (filePath, options, fileUploadOptions) => (resolve, reject) => {
  debugLog(fileUploadOptions, `Moving uploaded buffer to ${filePath}`);
  saveBufferToFile(options.buffer, filePath, promiseCallback(resolve, reject));
};

module.exports = (options, fileUploadOptions = {}) => {
  // see: https://github.com/richardgirges/express-fileupload/issues/14
  // firefox uploads empty file in case of cache miss when f5ing page.
  // resulting in unexpected behavior. if there is no file data, the file is invalid.
  // if (!fileUploadOptions.useTempFiles && !options.buffer.length) return;

  // Create and return file object.
  return {
    name: safeFilename(options.name),
    data: options.buffer,
    size: options.size,
    encoding: options.encoding,
    tempFilePath: options.tempFilePath,
    truncated: options.truncated,
    mimetype: options.mimetype,
    md5: options.hash,
    mv: (filePath, callback) => {
      // Validate destination path at the sink to defend against invalid or
      // malicious values reaching the underlying fs calls.
      const validationError = validateDestinationPath(filePath);
      if (validationError) {
        debugLog(fileUploadOptions, `mv() rejected invalid destination: ${validationError.message}`);
        if (isFunc(callback)) {
          return callback(validationError);
        }
        return Promise.reject(validationError);
      }
      // Normalize the destination to collapse any redundant components. This
      // does not resolve against a base directory (the library does not know
      // what that should be), but it ensures a consistent target for the
      // filesystem call.
      const normalizedPath = path.normalize(filePath);
      // Define a propper move function.
      const moveFunc = fileUploadOptions.useTempFiles
        ? moveFromTemp(normalizedPath, options, fileUploadOptions)
        : moveFromBuffer(normalizedPath, options, fileUploadOptions);
      // Create a folder for a file.
      checkAndMakeDir(fileUploadOptions, normalizedPath);
      // If callback is passed in, use the callback API, otherwise return a promise.
      return isFunc(callback) ? moveFunc(callback) : new Promise(moveFunc);
    }
  };
};
