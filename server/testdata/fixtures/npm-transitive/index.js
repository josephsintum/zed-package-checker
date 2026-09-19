// `minimist@1.2.0` is the vulnerable package here, and nothing in package.json
// names it: the project depends on `tar`, which depends on `mkdirp`, which
// depends on it. The diagnostic has to land on the `tar` line, because that is
// the only one of the four a reader of this project can edit.
const tar = require("tar");

console.log(typeof tar.extract);
