// Opening this file is the Stage 1 gate: it is a JavaScript source file, so it
// starts the language server, and package.json stays closed. A diagnostic must
// still appear on package.json in the project diagnostics panel.
const _ = require("lodash");

console.log(_.VERSION);
