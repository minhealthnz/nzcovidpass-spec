# New Zealand Covid Pass Specification

[Latest Published Version](https://nzcp.covid19.health.nz/)

This directory contains the source files for the NZ COVID Specification, used to build the published technical specification at [nzcp.covid19.health.nz](https://nzcp.covid19.health.nz/).

# Contributing

The specification text is defined in markdown format in [this file](./spec/main.md). The tool [spec-up](https://github.com/decentralized-identity/spec-up) is used to render the markdown to HTML. The resulting spec text is hosted via [github pages](https://pages.github.com/).

In order to preview changes locally run the following

NOTE - to do this you must have [NodeJS](https://nodejs.org/) installed.

```bash
# install spec-up dependency using NPM
npm i

# start spec-up with file watcher
npm run spec:edit
```

Now open [this file](./www/index.html) in your web browser to preview your changes. 

NOTE - updating the markdown version does not automatically reload the HTML file you must reload this in browser to see changes that are made.
