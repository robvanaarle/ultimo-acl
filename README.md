# Ultimo - ACL
[![Build Status](https://travis-ci.org/robvanaarle/ultimo-acl.svg?branch=master)](https://travis-ci.org/robvanaarle/ultimo-acl)
[![Test Coverage](https://lima.codeclimate.com/github/robvanaarle/ultimo-acl/badges/coverage.svg)](https://lima.codeclimate.com/github/robvanaarle/ultimo-acl/coverage)

Simple access control list

The ACL allows (or denies) priviliges to roles. Roles can have one or more parent roles. A child role inherits the allowed (or denied) privileges of all its parents. ACLs can be merged.

## Requirements
* PHP 5.3

## Usage

	$acl = new \ultimo\security\Acl();
	
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
