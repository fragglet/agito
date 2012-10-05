
from dulwich.repo import Repo
from dulwich.objects import Blob, Commit, Tree
import git
import os
import pysvn
import re
import shelve

MERGEINFO_LINE_RE = re.compile(r'([\w/\-]+):.*-(\d+)')

SVN_DEFAULT_IGNORES = """
# These are the default patterns globally ignored by Subversion:
*.o
*.lo
*.la
*.al
.libs
*.so
*.so.[0-9]*
*.a
*.pyc
*.pyo
*.rej
*~
.#*
.*.swp
.DS_store
"""

SVN_ROOT = "file:///home/fraggle/projects/chocolate-doom-repo"

BRANCHES = {
	"master" : "/trunk/chocolate-doom",
	"v2-branch" : "/branches/v2-branch",
	"opl-branch" : "/branches/opl-branch",
	"raven-branch" : "/branches/raven-branch",
	"strife-branch" : "/branches/strife-branch",
	"cndoom" : "/branches/cndoom",
	"render-limits" : "/branches/render-limits",
}

TAGS = {
	"chocolate-doom-0.0.1" : "/tags/chocolate-doom-0.0.1"
}

FILTER_REVISIONS = [ 391, 1027 ]

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

def create_blob_from_svn(path, revision):
	"""Add a blob for the given Subversion file.

	Args:
	  path: Path to the file in the Subversion repository.
	  revision: Subversion revision number.
	  of the file to add.
	Returns:
	  ID (hash) of the blob that was added.
	"""
	svnpath = "%s/%s" % (SVN_ROOT, path)
	data = svnclient.cat(svnpath, svn_revision(revision))
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
	svnpath = SVN_ROOT + path
	info_list = svnclient.info2(svnpath, svn_revision(revision),
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
	prop = svnclient.propget(prop, SVN_ROOT + path,
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
		ignore += SVN_DEFAULT_IGNORES

	ignore_file = os.path.join(filepath, ".gitignore")

	if ignore != '':
		blob = Blob.from_string(ignore)
		gitrepo.object_store.add_object(blob)
		treedir[ignore_file] = (0100644, blob.id)

		print "\t    <- %s" % ignore_file
	elif ignore_file in treedir:
		del treedir[ignore_file]

def recursive_copy(treedir, filepath, changed_path):
	svnpath = SVN_ROOT + changed_path.copyfrom_path
	files = svnclient.info2(svnpath, changed_path.copyfrom_revision,
	                        recurse=True)

	for _, info in files:
		assert (info.URL == svnpath
		     or info.URL.startswith(svnpath + '/'))
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
		if changed_path.action == 'A' and filepath != '':
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
		if not changed_path.path.startswith(path + '/'):
			continue

		filepath = changed_path.path[len(path) + 1:]
		action = changed_path.action

		#if filepath == "":
		#	continue

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

def get_merge_parents(parents, path, entry):
	"""Find the 'merge parents' of the given Subversion log entry.

	If the root of the branch path has been modified, the svn:mergeinfo
	property is checked to see if a merge has been performed. If so, the
	head of the branch being merged is returned.
	"""
	# Check that the branch root was modified.
	changed_path = log_entry_get_path(entry, path)
	if changed_path is None or changed_path.action != 'M':
		return []

	# Read the value of the mergeinfo property before and after this
	# revision.
	before = propget(path, entry.revision.number-1, 'svn:mergeinfo') or ""
	after = propget(path, entry.revision.number, 'svn:mergeinfo') or ""

	diff = diff_mergeinfo(parse_mergeinfo(before), parse_mergeinfo(after))

	# No change?

	if len(diff) == 0:
		return []

	# There has been some change to the mergeinfo property, so we can
	# assume a merge has been performed. But a merge from path A might
	# introduce a merge from path B as well. So how do we know which
	# is the branch we've actually merged from? Well, we can assume that
	# the merge revision number for path A will be higher than path B -
	# the reverse can never be true.

	merged_branch = max(diff, key=lambda d: d[2])

	print "Merge from %s@%s..." % (merged_branch[0], merged_branch[2])
	print

	mergehead = get_history_for_path(merged_branch[0], merged_branch[2])

	print "Head of merged branch: %s" % mergehead
	print "Continuing %s@%s..." % (path, entry.revision.number)
	print

	return [ mergehead ]

def create_commit(path, parents, tree_id, entry):
	"""Create a new Git commit object, and add it to the object store.

	Args:
	  path: Path to the Subversion branch.
	  parents: The parents of this commit.
	  tree: The tree of files to use for this commit.
	  entry: Subversion log entry to use for the details of this commit.
	Returns:
	  New commit object.
	"""
	author = 'nobody'
	if 'author' in entry:
		author = entry['author']
	email = "%s <%s@users.sourceforge.net>" % (author, author)

	message = entry.message.rstrip() + "\n\n" \
	        + ("Subversion-branch: %s\n" % path) \
	        + ("Subversion-revision: %i\n" % entry.revision.number)

	commit = Commit()
	commit.tree = tree_id
	commit.author = commit.committer = email
	commit.commit_time = commit.author_time = int(entry.date)
	commit.commit_timezone = commit.author_timezone = 0
	commit.encoding = "UTF-8"
	commit.message = message
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

	assert changed_path is not None

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
		tree_id = treedir.save()

		# If this is a filtered revision, skip to the next revision
		# without creating a commit.

		if entry.revision.number in FILTER_REVISIONS:
			continue

		parents = []
		if commit_id is not None:
			parents.append(commit_id)
			parents += get_merge_parents(parents, path, entry)

		newcommit = create_commit(path, parents, tree_id, entry)
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

	log = svnclient.log(SVN_ROOT + path,
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

def open_or_init_repo(path):
	if not os.path.exists(path):
		os.mkdir(path)
		return Repo.init_bare(path)
	else:
		return Repo(path)

gitrepo = open_or_init_repo("gitrepo")
svnclient = pysvn.Client()
commits = shelve.open("%s/commits.db" % gitrepo.path)

for branch, path in BRANCHES.items():
	print "===== %s" % branch
	head_id = get_history_for_path(path)
	gitrepo.refs['refs/heads/%s' % branch] = head_id

for tag, path in TAGS.items():
	print "===== %s" % tag
	head_id = get_history_for_path(path)
	gitrepo.refs['refs/tags/%s' % tag] = head_id
