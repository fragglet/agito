#!/usr/bin/env python
#
# Copyright (C) 2012 Simon Howard
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA
#
# --
#
# Agito, a Subversion to Git conversion tool.
#

from dulwich.repo import Repo
from dulwich.objects import Blob, Commit, Tag, Tree

import os
import pysvn
import re
import shelve
import sys
import time
import urllib
from urlparse import urlparse, urlunparse

DATE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

MERGEINFO_LINE_RE = re.compile(r'([\w/\-]+):.*-(\d+)')
WORD_MATCH = re.compile(r'(\s*)(\S+)')
BULLET_POINT_RE = re.compile(r'(\s*[\*\+]\s*)')

# Maximum characters per line in a Git commit message:

GIT_MAX_LINE_LEN = 72

class Directory(object):
	"""Wrapper for Tree objects to make updating easier."""

	def __init__(self, id=None):
		"""Create a new Directory object to mutate the specified tree.

		Args:
		  id: ID of the tree to mutate.
		"""
		if id is not None:
			self.tree = gitrepo.get_object(id)
			self.dirty = False
		else:
			self.tree = Tree()
			self.dirty = True

		self.subdirs = {}

	def __get_subdir(self, name):
		if name in self.subdirs:
			return self.subdirs[name]

		# Lazily create subdirectory objects as they are needed.
		_, sha = self.tree[name]
		subdir = Directory(sha)
		self.subdirs[name] = subdir

		return subdir

	def __contains__(self, path):
		components = path.split("/", 1)

		if len(components) == 2:
			dirname = components[0]
			if dirname not in self.tree:
				return False
			mode, _ = self.tree[dirname]
			if (mode & 040000) == 0:
				return False
			subdir = self.__get_subdir(dirname)
			return components[1] in subdir
		else:
			return components[0] in self.tree

	def __getitem__(self, path):
		components = path.split("/", 1)

		if len(components) == 2:
			subdir = self.__get_subdir(components[0])
			return subdir[components[1]]
		else:
			return self.tree[path]

	def __setitem__(self, path, value):
		components = path.split("/", 1)

		if len(components) == 2:
			subdir = self.__get_subdir(components[0])
			subdir[components[1]] = value
		else:
			self.tree[path] = value

		self.dirty = True

	def __delitem__(self, path):
		components = path.split("/", 1)

		if len(components) == 2:
			subdir = self.__get_subdir(components[0])
			del subdir[components[1]]
		else:
			filename = components[0]
			if filename in self.subdirs:
				del self.subdirs[filename]
			if filename not in self.tree:
				print "Doh..."
				for i in self.tree.items():
					print i
			del self.tree[filename]

		self.dirty = True

	def mkdir(self, path):
		components = path.split("/", 1)

		if len(components) == 2:
			subdir = self.__get_subdir(components[0])
			subdir.mkdir(components[1])
		else:
			self.subdirs[components[0]] = Directory()
			self.tree[components[0]] = (040000, '')

		self.dirty = True

	def save(self):
		# Commit all dirty subdirectories:

		for filename, subdir in self.subdirs.items():
			if subdir.dirty:
				subdir_id = subdir.save()
				mode, _ = self.tree[filename]
				self.tree[filename] = (mode, subdir_id)

		self.dirty = False
		gitrepo.object_store.add_object(self.tree)

		return self.tree.id

def svn_revision(revision):
	"""Get Subversion revision object for the specified revision
	   number.

	Args:
	  revision: Subversion revision number.
	Returns:
	  pysvn.Revision object.
	"""
	if revision is None:
		return pysvn.Revision(pysvn.opt_revision_kind.head)
	else:
		return pysvn.Revision(pysvn.opt_revision_kind.number,
		                      revision)

def get_commit(path, revision):
	"""Check the commits database to find the specified commit.

	Args:
	  path: String containing Subversion path.
	  revision: Subversion revision number.
	Returns:
	  ID of commit, or None if not stored yet.
	"""
	key = str("%s@%s" % (path, revision))
	if key not in commits:
		return None
	else:
		return commits[key]

def store_commit(path, revision, id):
	key = str("%s@%s" % (path, revision))
	commits[key] = id

def svn_path(path):
	"""Convert a Subversion path to a full URL."""

	# First, convert path to be a relative path (from the root of
	# the repository). eg. "/x/y/z" -> "x/y/z"

	while len(path) > 0 and path[0] == '/':
		path = path[1:]

	# Parse the repository's URL, join the paths and then reassemble
	# back into a full URL.

	repo_url = urlparse(config["SVN_REPO"])
	full_path = os.path.join(urllib.unquote(repo_url.path), path)

	return urlunparse((repo_url.scheme, repo_url.netloc,
	                   urllib.quote(full_path), '', '', ''))

def create_blob_from_svn(path, revision):
	"""Add a blob for the given Subversion file.

	Args:
	  path: Path to the file in the Subversion repository.
	  revision: Subversion revision number.
	  of the file to add.
	Returns:
	  ID (hash) of the blob that was added.
	"""
	data = svnclient.cat(svn_path(path), svn_revision(revision))
	blob = Blob.from_string(data)
	gitrepo.object_store.add_object(blob)
	return blob.id

def svn_file_type(path, revision):
	"""Given a path to a Subversion file or directory, get the type
	   of thing it is.

	Args:
	  path: Path within the Subversion repository.
	  revision: Subversion revision number.
	Returns:
	  Subversion node_kind object.
	"""
	info_list = svnclient.info2(svn_path(path), svn_revision(revision),
	                            recurse=False)
	assert len(info_list) == 1
	name, info = info_list[0]
	return info.kind

def propget(path, revision, prop):
	"""Get the value of the given property.

	Args:
	  path: The path of the file/directory being queried.
	  revision: The Subversion revision number at which to read.
	  prop: Name of the property.
	Returns:
	  String containing the property value or 'None' if not set.
	"""
	prop = svnclient.propget(prop, svn_path(path),
	                         svn_revision(revision), recurse=False)
	if len(prop) > 0:
		return prop.items()[0][1]
	else:
		return None

def add_to_tree_from_svn(treedir, filepath, svnpath, revision):
	blob_id = create_blob_from_svn(svnpath, revision)
	perms = 0100644

	# If the executable property is set, set the permissions accordingly.
	if propget(svnpath, revision, 'svn:executable') is not None:
		perms |= 0111

	treedir[filepath] = (perms, blob_id)

def update_gitignore(treedir, filepath, svnpath, revision):
	ignore = propget(svnpath, revision, 'svn:ignore') or ""

	# Include the svn default ignore set in the root .gitignore file.

	if filepath == "":
		ignore += config.get("SVN_DEFAULT_IGNORES", "")

	ignore_file = os.path.join(filepath, ".gitignore")

	if ignore != '':
		blob = Blob.from_string(ignore)
		gitrepo.object_store.add_object(blob)
		treedir[ignore_file] = (0100644, blob.id)

		print "\t    <- %s" % ignore_file
	elif ignore_file in treedir:
		del treedir[ignore_file]

def path_within_path(needle, haystack):
	"""Returns True if 'needle' is within 'haystack'."""

	haystack = haystack.rstrip('/')

	return (haystack == needle
	     or needle.startswith(haystack + '/'))

def recursive_copy(treedir, filepath, changed_path):
	svnpath = svn_path(changed_path.copyfrom_path)
	files = svnclient.info2(svnpath, changed_path.copyfrom_revision,
	                        recurse=True)

	for _, info in files:
		assert path_within_path(info.URL, svnpath)
		subpath = info.URL[len(svnpath) + 1:]

		if subpath == '':
			continue

		newpath = str(os.path.join(filepath, subpath))
		print "\t    <- %s" % newpath

		src_path = os.path.join(changed_path.copyfrom_path, subpath)
		src_revision = changed_path.copyfrom_revision.number

		if info.kind == pysvn.node_kind.dir:
			treedir.mkdir(newpath)
			update_gitignore(treedir, newpath,
			                 src_path, src_revision)
		elif info.kind == pysvn.node_kind.file:

			# TODO: The blob representing this file is probably
			# already in the git repository. Look up the
			# existing blob ID if possible.
			add_to_tree_from_svn(treedir, newpath,
			                     src_path, src_revision)

def process_add_modify(treedir, filepath, log, changed_path):
	revision = log.revision.number
	filetype = svn_file_type(changed_path.path, revision)

	if filetype == pysvn.node_kind.file:
		add_to_tree_from_svn(treedir, filepath, changed_path.path,
		                     revision)
	elif filetype == pysvn.node_kind.dir:
		if changed_path.action in ('A', 'R') and filepath != '':
			treedir.mkdir(filepath)
			if changed_path.copyfrom_path:
				recursive_copy(treedir, filepath, changed_path)

		update_gitignore(treedir, filepath, changed_path.path,
		                 revision)

def process_delete(treedir, filepath, log, changed_path):
	del treedir[filepath]

def mutate_tree_from_log(treedir, path, log):
	"""Given an existing tree, mutate it like in the given Subversion
	   log entry.

	Args:
	  treedir: Reference to a Directory object representing the tree.
	  path: The root of the Subversion branch within the repository.
	  log: The Subversion log entry to apply.
	"""

	# The list of changed paths does not seem to be in any sensible
	# order. It is important that they are in order, because there
	# are corner cases, eg. a recursive copy followed by a delete of
	# some of the copied files.

	changed_paths = sorted(log.changed_paths,
	                       lambda x, y: cmp(x.path, y.path))

	print "% 8i:" % log.revision.number

	for changed_path in changed_paths:
		if not path_within_path(changed_path.path, path):
			continue

		filepath = changed_path.path[len(path) + 1:]
		action = changed_path.action

		print "\t%s %s" % (action, filepath)

		if action in ('A', 'M', 'R'):
			process_add_modify(treedir, filepath,
			                   log, changed_path)
		elif action == 'D':
			process_delete(treedir, filepath, log, changed_path)

def parse_mergeinfo(mergeinfo):
	"""Parse the given mergeinfo property contents.

	Args:
	  mergeinfo: Value of a mergeinfo property.
	Returns:
	  Dictionary mapping from path name to 'latest merge' revision
	  number.
	"""
	mergeinfo = mergeinfo or ""
	result = {}
	for line in mergeinfo.split("\n"):
		match = MERGEINFO_LINE_RE.match(line)
		if match:
			result[match.group(1)] = int(match.group(2))

	return result

def diff_mergeinfo(before, after):
	"""Compare the two mergeinfo dictionaries and identify differences.

	Args:
	  before: Mergeinfo dictionary before change
	  after: Mergeinfo dictionary after change
	Returns:
	  List of tuples containing changes, where each tuple contains
	  the path and revision number before and after the change.
	"""
	result = []

	# Only check values in after: a branch is never "unmerged".

	for path, after_revision in after.items():
		if path in before:
			before_revision = before[path]
		else:
			before_revision = 0

		if before_revision != after_revision:
			result.append((path, before_revision, after_revision))

	return result

def log_entry_get_path(entry, path):
	"""Given a Subversion log entry, look up a particular changed path."""

	for changed_path in entry.changed_paths:
		if changed_path.path == path:
			return changed_path
	else:
		return None

def mergeinfo_callback(path, entry, change):
	"""Find merge parents when mergeinfo is changed.

	This is a callback invoked when the svn:mergeinfo property is
	changed.

	Args:
	  path: Location of the branch within the repository.
	  entry: The Subversion log entry structure.
	  change: Tuple containing svn:mergeinfo value before and after
	      change.
	Returns:
	  Tuple containing Subversion path and revision number of merged
	  branch, or None for no merge.
	"""
	before, after = change
	diff = diff_mergeinfo(parse_mergeinfo(before), parse_mergeinfo(after))

	# No change?

	if len(diff) == 0:
		return None

	# There has been some change to the mergeinfo property, so we can
	# assume a merge has been performed. But a merge from path A might
	# introduce a merge from path B as well. So how do we know which
	# is the branch we've actually merged from? Well, we can assume that
	# the merge revision number for path A will be higher than path B -
	# the reverse can never be true.

	merged_branch = max(diff, key=lambda d: d[2])

	return (merged_branch[0], merged_branch[2])

def get_merge_parents(path, entry):
	"""Find the 'merge parents' of the given Subversion log entry.

	If the root of the branch path has been modified, the svn:mergeinfo
	property is checked to see if a merge has been performed. If so, the
	head of the branch being merged is returned.
	"""
	# Check that the branch root was modified.
	changed_path = log_entry_get_path(entry, path)
	if changed_path is None or changed_path.action != 'M':
		return []

	parents = {}

	# Read the value of the properties before and after this revision.

	for name, callback in merge_callbacks.items():
		before = propget(path, entry.revision.number-1, name)
		after = propget(path, entry.revision.number, name)

		if before == after:
			continue

		# Invoke the callback. If multiple callbacks suggest the
		# same merge, the revision numbers might be slightly
		# different, so use the highest numbered.

		parent = callback(path, entry, (before, after))
		if parent is not None:
			parent_path, parent_rev = parent
			if parent_rev > parents.get(parent_path, 0):
				parents[parent_path] = parent_rev

	# Convert all parents to merge heads.

	parent_commits = []

	for parent_path, revision in parents.items():
		print "Merge from %s@%s..." % (parent_path, revision)
		print

		mergehead = get_history_for_path(parent_path, revision)

		print "Head of merged branch: %s" % mergehead

		parent_commits.append(mergehead)

	if len(parent_commits) > 0:
		print "Continuing %s@%s..." % (path, entry.revision.number)
		print

	return parent_commits

def username_to_author(username):
	"""Given a Subversion user name, get a Git author string.

	Args:
	  username: Subversion user, or 'None' for no user.
	Returns:
	  Tuple containing author name and email address, eg.
	  ('Bob Dobbs', 'bob@example.com')
	"""
	authors = config.get("AUTHORS", {})
	default_author = config.get("DEFAULT_AUTHOR", ("%", "%@localhost"))

	if username in authors:
		name, email = authors[username]
	else:
		username = username or "nobody"
		name_pattern, email_pattern = default_author
		name = name_pattern.replace('%', username)
		email = email_pattern.replace('%', username)

	return (name, email)

def reflow_line(line):
	"""Reflow the text of a single line onto multiple short lines.

	Args:
	  line: String containing line to reflow.
	Returns:
	  String containing reflowed line.
	"""
	match = BULLET_POINT_RE.match(line)
	if match:
		current_line = match.group(1)
		indent_len = len(current_line)
		offset = indent_len
	else:
		current_line = ""
		indent_len = 0
		offset = 0

	result = []

	while True:
		match = WORD_MATCH.match(line, offset)
		if not match:
			break

		space = match.group(1)
		word = match.group(2)
		if len(current_line + space + word) > GIT_MAX_LINE_LEN:
			result.append(current_line)
			current_line = " " * indent_len
		else:
			current_line += space

		current_line += word
		offset = match.end(0)

	result.append(current_line)
	return "\n".join(result)

def reflow_text(path, entry, message):
	"""Re-arrange the text of a commit message to a maximum line length.

	This ensures that lines of a commit message do not exceed the Git
	standard maximum of 72 columns.

	Args:
	  path: Path of the branch within Subversion.
	  entry: Log entry with the details of this commit.
	  message: The commit message text.
	Returns:
	  Reflowed commit message text.
	"""
	result = []

	for line in message.split("\n"):
		result.append(reflow_line(line))

	return "\n".join(result)

def append_branch_info(path, entry, message):
	"""Appends Subversion branch info to Git commit messages.

	Args:
	  path: Path of the branch within Subversion.
	  entry: Log entry with the details of this commit.
	  message: The commit message text.
	Returns:
	  Altered commit message text with branch info appended.
	"""
	return message.rstrip() + "\n\n" \
	     + ("Subversion-branch: %s\n" % str(path)) \
	     + ("Subversion-revision: %i\n" % entry.revision.number)

def utc_time_string(seconds):
	"""Convert epoch seconds to a time string."""
	return time.strftime(DATE_TIME_FORMAT, time.gmtime(seconds))

def utc_time_from_string(timestr):
	"""Convert time string to epoch seconds."""
	# Parse time string and convert to epoch seconds by subtracting
	# time.timezone (difference between local time and UTC). There's
	# a slight issue here in that timetuple needs to be the time in
	# the regular (non-DST) timezone.
	timetuple = time.strptime(timestr, DATE_TIME_FORMAT)
	timetuple = (
		timetuple.tm_year, timetuple.tm_mon, timetuple.tm_mday,
		timetuple.tm_hour, timetuple.tm_min, timetuple.tm_sec,
		0, 0, 0
	)
	return int(time.mktime(timetuple) - time.timezone)

def commit_metadata_from_entry(path, entry):
	"""Create a metadata dictionary for the given Subversion commit.

	This encapsulates the metadata to be used to construct the
	equivalent Git commit, and can be rewritten, as with
	'git filter-branch'

	Args:
	  path: Path to the Subversion branch.
	  entry: The Subversion log entry for this commit.
	Returns:
	  Dictionary mapping from names to values; the names match those
	  used by 'git filter-branch'.
	"""
	# Get author name and email address:
	username = None
	if 'author' in entry:
		username = entry['author']

	name, email = username_to_author(username)

	# Convert Subversion commit message into Git commit message:
	message = entry.message
	for message_filter in config.get('COMMIT_MESSAGE_FILTERS', []):
		message = message_filter(path, entry, message)

	return {
		"MESSAGE": message,
		"GIT_AUTHOR_NAME": name,
		"GIT_AUTHOR_EMAIL": email,
		"GIT_AUTHOR_DATE": utc_time_string(entry.date),
		"GIT_COMMITTER_NAME": name,
		"GIT_COMMITTER_EMAIL": email,
		"GIT_COMMITTER_DATE": utc_time_string(entry.date),
	}

def create_commit(metadata, parents, tree_id):
	"""Create a new Git commit object, and add it to the object store.

	Args:
	  metadata: Dictionary containing metadata to construct the commit,
	      including commit message and author data.
	  parents: The parents of this commit.
	  tree: The tree of files to use for this commit.
	Returns:
	  New commit object.
	"""
	commit = Commit()
	commit.tree = tree_id
	commit.author = "%s <%s>" % (metadata["GIT_AUTHOR_NAME"],
	                             metadata["GIT_AUTHOR_EMAIL"])
	commit.author_time = \
	    utc_time_from_string(metadata["GIT_AUTHOR_DATE"])
	commit.author_timezone = 0

	commit.committer = "%s <%s>" % (metadata["GIT_COMMITTER_NAME"],
	                                metadata["GIT_COMMITTER_EMAIL"])
	commit.commit_time = \
	    utc_time_from_string(metadata["GIT_COMMITTER_DATE"])
	commit.commit_timezone = 0

	commit.encoding = "UTF-8"
	commit.message = metadata["MESSAGE"]
	commit.parents = parents
	gitrepo.object_store.add_object(commit)

	return commit

def follow_parent_branch(path, entry):
	"""Given the tail of a branch's history, find its parent commit.

	If a branch is copied from a parent branch using svn cp, it is possible
	to follow the history back onto the parent branch. Get the Git commit
	ID corresponding to the point on the parent branch from which it was
	branched off, constructing the parent branch's history if necessary.

	Args:
	  path: The Subversion path of the branch (the child branch)
	  entry: Log entry that is the tail of the branch (last log entry
	      returned in 'svn log').
	Returns:
	  Git commit ID corresponding to the starting point of the new branch,
	  or 'None' if the branch was started from scratch.
	"""
	# The log entry may affect several paths, so find the one that created
	# the branch ('path').
	# This is complicated, because there's a tricky corner case: the branch
	# may have been created by a parent directory being copied. So we have
	# to cope with this corner case, and reconstruct the 'actual'
	# copyfrom_path.
	for changed_path in entry.changed_paths:
		if changed_path.action != 'A':
			continue
		if changed_path.path == path:
			subdir = None
			break
		if path.startswith(changed_path.path + '/'):
			subdir = os.path.relpath(path, changed_path.path)
			break
	else:
		assert False, "Source of copied parent branch not found."

	# Branch copied from a parent branch? Follow the history.

	if (changed_path.copyfrom_path is not None
	and changed_path.copyfrom_revision is not None):
		copy_path = changed_path.copyfrom_path
		if subdir is not None:
			copy_path = os.path.join(copy_path, subdir)

		return get_history_for_path(copy_path,
		                            changed_path.copyfrom_revision.number)
	else:
		return None

def construct_history(path, commit_id, log):
	"""Construct a revision history from the given Subversion log entries.

	Args:
	  path: The path of the branch where we are constructing history.
	  commit_id: parent commit of the first log entry in the chain,
	      or 'None' if there is no parent.
	  log: List of Subversion log entries to convert to Git commits.
	Returns:
	  ID of the commit at the head of the constructed history.
	"""

	if len(log) == 0:
		return commit_id

	# Find the tree corresponding to the starting commit, so that we
	# can mutate it with each commit we process. If there is no previous
	# history, create an empty tree and start from there.

	if commit_id is not None:
		commit = gitrepo.get_object(commit_id)
		treedir = Directory(commit.tree)
	else:
		treedir = Directory()

	print "Constructing history from %s for %s..%s" % \
	    (path, log[-1].revision.number, log[0].revision.number)

	if commit_id is not None:
		print " - continuing from commit %s..." % (commit_id)

	for entry in reversed(log):

		mutate_tree_from_log(treedir, path, entry)

		# If this is a filtered revision, skip to the next revision
		# without creating a commit.

		if entry.revision.number in config.get("FILTER_REVISIONS", []):
			continue

		# Allow trees and commit metadata to be rewritten by a
		# callback before saving, like 'git filter-branch':

		metadata = commit_metadata_from_entry(path, entry)

		if "FILTER_BRANCH_CALLBACK" in config:
			config["FILTER_BRANCH_CALLBACK"](path, entry,
			                                 metadata, treedir)

		tree_id = treedir.save()

		# Identify parents of this commit:

		parents = []
		if commit_id is not None:
			parents.append(commit_id)
			parents += get_merge_parents(path, entry)

		newcommit = create_commit(metadata, parents, tree_id)
		store_commit(path, entry.revision.number, newcommit.id)
		print "\tcommit %s" % newcommit.id
		print

		commit_id = newcommit.id

	return commit_id

def get_history_for_path(path, revision=None):
	"""Get the git history for the given Subversion path/revision,
	   constructing it if necessary.

	Args:
	  path: String containing Subversion path.
	  revision: Revision number to start from, or 'None' for the
	      revision at HEAD.
	Returns:
	  Object ID representing the commit at the head of the chain.
	"""
	commit_id = get_commit(path, revision)

	if commit_id is not None:
		return commit_id

	# We haven't built this commit yet; instead, we need to construct
	# the history. Do an SVN log, and we will turn the log entries
	# into commits.

	log = svnclient.log(svn_path(path),
	                    discover_changed_paths=True,
	                    peg_revision=svn_revision(revision),
	                    revision_start=svn_revision(revision),
	                    strict_node_history=True)

	# We may have made some of the commits in the history already.
	# Scan through the commit log and cut the list down to the commits
	# that have not yet been processed.

	commit_id = None

	for index, entry in enumerate(log):
		commit_id = get_commit(path, entry.revision.number)
		if commit_id is not None:
			log = log[:index]
			break

	else:
		# We have not made any of the commits yet, so we have to
		# start from scratch. If the branch began as a copy from
		# another path, we need to follow the history back onto
		# the parent branch.

		commit_id = follow_parent_branch(path, log[-1])

	# Build the missing part of the history.

	return construct_history(path, commit_id, log)

def create_tag_object(name, head):
	"""Create an annotated tag object from the given history.

	This rewrites a 'tag creation' history so that the head is a tag
	instead of a commit. This relies on the fact that in Subversion,
	tags are created using a 'svn cp' copy.

	Args:
	  name: Name of the tag.
	  head: Object ID of the head commit of a chain to be tagged.
	Returns:
	  The object ID of an annotated tag object, or the value of 'head'
	  if the tag could not be created.
	"""
	head_commit = gitrepo.get_object(head)

	# The tree of the commit should exactly match the tree of its parent.
	# If not, then is not a pure 'tagging' commit.
	if len(head_commit.parents) != 1:
		return head
	head_hat_commit = gitrepo.get_object(head_commit.parents[0])
	if head_commit.tree != head_hat_commit.tree:
		return head

	tag = Tag()
	tag.name = name
	tag.message = head_commit.message
	tag.tag_time = head_commit.commit_time
	tag.tag_timezone = head_commit.commit_timezone
	tag.object = (Commit, head_hat_commit.id)
	tag.tagger = head_commit.committer
	gitrepo.object_store.add_object(tag)

	return tag.id

def parse_config(filename):
	"""Parse configuration file.

	Args:
	  filename: Path to the configuration file to parse.
	Returns:
	  Dictionary of values defined in the file.
	"""
	with open(filename) as f:
		data = f.read()
		compiled = compile(data, filename, "exec")
		result = { 'agito': sys.modules[__name__] }
		eval(compiled, result)
		return result

def parse_svn_path(path, git_name):
	"""Given a Subversion path to convert, expand to actual paths.

	This is used in the BRANCHES and TAGS configuration dictionaries,
	where '%' wildcards can be specified to expand all matching paths.

	Args:
	  path: The Subversion path, possibly containing a '%' as a wildcard.
	  git_name: The name of the Git tag or branch, possibly also
	      containing a '%' to match the Subversion path.
	Returns:
	  List of tuples, each tuple containing an expanded Subversion path
	  and git name.
	"""
	if '%' not in path:
		return [(path, git_name)]

	svn_dir = os.path.dirname(path)
	svn_filepattern = os.path.basename(path)
	filename_re = re.escape(svn_filepattern).replace('\\%', '(.*)') + '$'
	filename_re = re.compile(filename_re)

	# List that directory and find entries that match.
	entries = svnclient.ls(svn_path(svn_dir), recurse=False)
	results = []
	for entry in entries:
		_, filename = entry.name.rsplit('/', 1)
		match = filename_re.match(filename)
		if match:
			x = match.group(1)
			results.append((path.replace('%', x),
			                git_name.replace('%', x)))

	return results

def parse_svn_path_map(pathmap):
	"""Parse a Subversion "path map" dictionary.

	These are used for the BRANCHES and TAGS configuration. Expand
	the path map into a concrete list of Subversion paths and
	corresponding Git names.

	Args:
	  pathmap: The configuration pathmap.
	Returns:
	  List of tuples, each tuple containing an expanded Subversion path
	  and git name.
	"""
	results = []
	for svn_path, git_name in pathmap.items():
		results.extend(parse_svn_path(svn_path, git_name))

	return results

def open_or_init_repo(path):
	if not os.path.exists(path):
		os.mkdir(path)
		return Repo.init_bare(path)
	else:
		return Repo(path)

if len(sys.argv) != 2:
	print "Usage: %s <config>" % sys.argv[0]
	sys.exit(0)

# Read configuration file and make essential sanity check.

config = parse_config(sys.argv[1])
assert ("SVN_REPO" in config), \
       "Must provide path to Subversion repository to convert"
assert ("GIT_REPO" in config), \
       "Must provide path to output Git repository"

# Set up merge_callbacks and add svn:mergeinfo handler.
merge_callbacks = config.get('MERGE_CALLBACKS', {}).copy()
merge_callbacks['svn:mergeinfo'] = mergeinfo_callback

gitrepo = open_or_init_repo(config["GIT_REPO"])
svnclient = pysvn.Client()
commits = shelve.open("%s/commits.db" % gitrepo.path)

# Create branches. If the branches have not been specified in the
# configuration file, fall back to a single branch that captures the
# history of the entire repository.

if "BRANCHES" in config:
	branches = config["BRANCHES"]
else:
	branches = { "/" : "master" }

for path, branch in parse_svn_path_map(branches):
	print "===== %s" % branch
	head_id = get_history_for_path(path)
	gitrepo.refs['refs/heads/%s' % branch] = head_id

for path, tag in parse_svn_path_map(config.get("TAGS", {})):
	print "===== %s" % tag
	head_id = get_history_for_path(path)
	if config.get("CREATE_TAG_OBJECTS", True):
		head_id = create_tag_object(tag, head_id)
	gitrepo.refs['refs/tags/%s' % tag] = head_id

