# nvd-repo
A ruby gem for creating a static NVD filesystem repository
Currently it only supports parsing of the v1.2.1 XML feed format.

## Features

1. Populate a file system tree with all existing NVD/CVE entries.
2. Provide entry files in JSON and XML format.
3. Track history of modifications.
4. Provide concise summaries of changes since last update.
5. Simple bash scripts to get entry and search.

## Motivation

The goal of this project is to have a filesystem structure that
contains a repository of NVD/CVE entries.  It's a setup
that doesn't require rails or a database.  A Rails developer
using a service like Heroku can use this gem offline to get daily NVD
updates, then commit and push.  The Rails app can then provide quick
access to CVE entries and change with minimal or no load on the database.

Example files for an entry that has history.
<pre>
./data/nvd/2015/CVE-2015-5343/
- entry.json
- entry.xml
- entry-2016-04-14.json
- entry-2016-04-14.xml
</pre>

## setup
To populate the initial filesystem, run:
<pre>
rake nvd:populate
</pre>

## update
<pre>
rake nvd:update
</pre>

## Scripts
TODO
