# Ultimo - ACL
Simple access control list

The ACL allows (or denies) priviliges to roles. Roles can have one or more parent roles. A child role inherits the allowed (or denied) privileges of all its parents. ACLs can be merged.

## Requirements
* PHP 5.3

## Usage

	$acl = new \ultimo\security\ACL();
	
	// add roles
	$acl->addRole('guest');
	$acl->addRole('user', array('guest'));
	$acl->addRole('forum_moderator', array('user'));
	$acl->addRole('comment_moderator', array('user'));
	$acl->addRole('admin', array('forum_moderator', 'comment_moderator'));
	
	// add privileges (roles are denied everything by default)
	$acl->allow('guest', array('forum.read'));
	$acl->allow('user', array('forum.create'));
	$acl->allow('forum_moderator', array('forum.update', 'forum.delete'));
	$acl->allow('admin'); // allows admin everything
	
	// check privileges
	
	// false
	$acl->isAllowed('guest', 'forum.update');
	
	// true
	$acl->isAllowed('comment_moderator', 'forum.create');
