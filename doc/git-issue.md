# Embedded issue tracking using git #

## Creating issues ##

Create an *issue* commit, usually in a new brach. The commit may:

 * be empty: git commit --allow-empty
 * contain source inline bug description, comments
 * directly include a fix

The issue is identified by the issue git commit id. This means issue-opening
commits should never been rebased, unless all references get updated.

## Issue keywords ##

A commit may contain one or more _issue-*:_ keywords. If any issue keywords
are used, the first keyword MUST be either _issue:_ to open a new issue,
or an _issue-id:_ to reference a previously opened issue. Issue keywords MUST
start at the beginning of a line.

### issue: _title_ ###
Creates a new issue named _title_. The issue will be tracked by the commit id
containing the _issue:_ keyword. The _issue_ keyword is used in the first
line (subject) of the commit only.

### issue-id: _git commit id_ ###
References an issue using the commit id of the commit with the _issue:_ keyword.

### issue-status: _status_ ###
Updates the status of the issue. _status_ is one of:

* _open_: Issue is open, valid, and should get fixed
* _fixed_: Issue has been fixed
* _wontfix_: Issue can't/won't get fixed for whatever reason
* _invalid_: Issue is not considered valid anymore

### issue-type: _type_ ###
Updates the type of the issue. _type_ is one of:

* _feature_: new functionality
* _minor_: a non-critical bugfix affecting some setups
* _major_: a more critical bugfix affecting more setups
* _security_: a security related bugfix, a vulnerability

### issue-keyword: _keyword, keyword_ ###
Add a set of keywords to the issue. May contain type of bug, but also affected
components (charon, libstrongswan, openssl, etc).

### issue-redmine: _option_ ###
Redmine issue referencing and control: refs #7, fixes #8 etc.

### issue-affected: _commit_ ###
Since when this issue exists, commit which introduced this issue. If this
keyword is missing, all version before the "fixing" commit are considered
affected.

### issue-assigned: _email_ ###
Developer issue has been assigned. If not given, the author of the issue
opening commit is assigned.

## git-issue helper tool ##

The git-issue helper script can be installed to the git tools, allowing
a tight integration of issue management to the git workflow.

After installation, invoke _git issue_ for a usage summary.