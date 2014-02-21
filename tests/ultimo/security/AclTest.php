<?php

namespace ultimo\security;

class AclTest extends \PHPUnit_Framework_TestCase
{
  protected $acl;
  
  public function setup() {
    $this->acl = new Acl();
    
    $this->acl->addRole('guest');
    $this->acl->addRole('member', array('guest'));
    $this->acl->addRole('news_admin', array('member'));
    $this->acl->addRole('forum_admin', 'member');
    $this->acl->addRole('admin', array('news_admin', 'forum_admin'));
    
    $this->acl->allow('guest', array('news.read', 'forum.read', 'profile.create'));
    $this->acl->allow('member', array('forum.create'));
    $this->acl->allow('news_admin', array('news.create', 'news.update'));
    $this->acl->allow('forum_admin', 'forum.update');
    $this->acl->allow('admin');
    
    $this->acl->deny('member', 'profile.create');
  }
  
  /**
   * Test first degree parent
   */
  public function testMemberBelongsToGuest() {
    $this->assertTrue($this->acl->belongsTo('member', 'guest'));
  }
  
  /**
   * Test multi degree parent
   */
  public function testAdminBelongsToGuest() {
    $this->assertTrue($this->acl->belongsTo('admin', 'guest'));
  }
  
  /**
   * Test parent can be set not without using an array
   */
  public function testForumAdminBelongsToMember() {
    $this->assertTrue($this->acl->belongsTo('forum_admin', 'member'));
  }
  
  /**
   * Test parent does not belong to child
   */
  public function testGuestDoesNotBelongToAdmin() {
    $this->assertFalse($this->acl->belongsTo('guest', 'admin'));
  }
  
  /**
   * Test unrelated roles do not belong to each other
   */
  public function testNewsAdminDoesNotBelongToForumAdmin() {
    $this->assertFalse($this->acl->belongsTo('news_admin', 'forum_admin'));
  }
  
  /**
   * Test a role is its own parent
   */
  public function testMemberBelongsToMember() {
    $this->assertTrue($this->acl->belongsTo('member', 'member'));
  }
  
  /**
   * Test parent can be added later
   */
  public function testAnotherParentCanBeAdded() {
    $this->acl->addRole('test');
    $this->acl->addRole('admin', 'test');
    $this->assertTrue($this->acl->belongsTo('admin', 'test'));
  }
  
  /**
   * Test unexisting role does not have parents
   */
  public function testUnexistingRoleHasNoParents() {
    $this->assertFalse($this->acl->belongsTo('santa', 'admin'));
  }
  
  /**
   * Test unexisting role cannot be used as parent
   */
  public function testUnexistingRoleCannotBeAParent() {
    $this->setExpectedException('\ultimo\security\AclException');
    $this->acl->addRole('admin', 'santa');
  }
  
  /**
   * Test direct privilege
   */
  public function testGuestIsAllowedToReadNews() {
    $this->assertTrue($this->acl->isAllowed('guest', 'news.read'));
  }
  
  /**
   * Test first degree inherited privilege
   */
  public function testMemberIsAllowedToReadNews() {
    $this->assertTrue($this->acl->isAllowed('member', 'news.read'));
  }
  
  /**
   * Test multi degree inherited privilege
   */
  public function testAdminIsAllowedToDeleteNews() {
    $this->assertTrue($this->acl->isAllowed('admin', 'news.delete'));
  }
  
  /**
   * Test privilege can be set without using an array
   */
  public function testFormAdminIsAllowedToUpdateForum() {
    $this->assertTrue($this->acl->isAllowed('forum_admin', 'forum.update'));
  }
  
  /**
   * Test role does not have an unallowed privilege
   */
  public function testGuestIsNotAllowedToDeleteNews() {
    $this->assertFalse($this->acl->isAllowed('guest', 'news.delete'));
  }
  
  /**
   * Test role does not have an denied privilege
   */
  public function testMemberIsNotAllowedToCreateProfile() {
    $this->assertFalse($this->acl->isAllowed('member', 'profile.create'));
  }
  
  /**
   * Test role does not have inherited permission if denied everything
   */
  public function testDeniedMemberIsNotAllowedToReadNews() {
    $this->acl->deny('member');
    $this->assertFalse($this->acl->isAllowed('member', 'news.read'));
  }
  
  /**
   * Test denied privilege is inherited
   */
  public function testForumAdminIsNotAllowedToCreateProfile() {
    $this->assertFalse($this->acl->isAllowed('forum_admin', 'profile.create'));
  }
  
  /**
   * Test role does not have inherticed permission if specificly denied
   */
  public function testAllowedAndDeniedMemberIsNotAllowedToReadNews() {
    $this->acl->deny('member', 'news.read');
    $this->assertFalse($this->acl->isAllowed('member', 'news.read'));
  }
  
  /**
   * Test unexisting role has no permissions
   */
  public function testUnexistingRoleHasNoPermissions() {
    $this->assertFalse($this->acl->isAllowed('santa', 'chimney'));
  }
  
  /**
   * Test unexisting role cannot be allowed privileges
   */
  public function testUnexistingRoleCannotBeAllowedPrivileges() {
    $this->setExpectedException('\ultimo\security\AclException');
    $this->acl->allow('santa', 'chimney');
  }
  
  /**
   * Test unexisting role cannot be denied privileges
   */
  public function testUnexistingRoleCannotBeDeniedPrivileges() {
    $this->setExpectedException('\ultimo\security\AclException');
    $this->acl->deny('santa', 'chimney');
  }
  
  /**
   * Test specificly denied and then allowed privilege is not allowed
   */
  public function testSpecificlyDeniedAndThenAllowedPrivilegeIsAllowed() {
    $this->acl->deny('guest', 'frontpage.read');
    $this->acl->allow('guest', 'frontpage.read');
    $this->assertTrue($this->acl->isAllowed('guest', 'frontpage.read'));
  }
  
  /**
   * Test specificly allowed and then denied privilege is not allowed
   */
  public function testSpecificlyAllowedAndThenDeniedPrivilegeIsNotAllowed() {
    $this->acl->allow('guest', 'website.delete');
    $this->acl->deny('guest', 'website.delete');
    $this->assertFalse($this->acl->isAllowed('guest', 'website.delete'));
  }
  
  /**
   * Test *all* privileges allowed is cancelled is one privilege is denied
   */
  public function testEverythingAllowedIsCancelledIfAPrivilegeIsDenied() {
    $this->acl->allow('admin');
    $this->acl->deny('admin', 'website.delete');
    $this->assertFalse($this->acl->isAllowed('admin', 'website.read'));
  }
  
  /**
   * Test privilege callback is called
   */
  public function testPrivilegeCallbackIsCalled() {
    $mock = $this->getMock('stdClass', array('callback'));
    $mock->expects($this->once())
         ->method('callback')
         ->with($this->equalTo('member'), $this->equalTo('privilege.withcallback'), $this->equalTo(42))
         ->will($this->returnValue(true));
         
    $this->acl->allow('member', 'privilege.withcallback', array($mock, 'callback'));
    $this->acl->isAllowed('member', 'privilege.withcallback', 42);
  }
  
  /**
   * Test privilege callback allows
   */
  public function testPrivilegeCallbackAllows() {
    $mock = $this->getMock('stdClass', array('callback'));
    $mock->expects($this->once())
         ->method('callback')
         ->will($this->returnValue(true));
         
    $this->acl->allow('member', 'privilege.withcallback', array($mock, 'callback'));
    $this->assertTrue($this->acl->isAllowed('member', 'privilege.withcallback', 42));
  }
  
  /**
   * Test privilege callback denies
   */
  public function testPrivilegeCallbackDenies() {
    $mock = $this->getMock('stdClass', array('callback'));
    $mock->expects($this->once())
         ->method('callback')
         ->will($this->returnValue(false));
         
    $this->acl->allow('member', 'privilege.withcallback', array($mock, 'callback'));
    $this->assertFalse($this->acl->isAllowed('member', 'privilege.withcallback', 42));
  }
  
  /**
   * Test exactly added roles are present
   */
  public function testAllRolesArePresent() {
    $this->assertSame(array('guest', 'member', 'news_admin', 'forum_admin', 'admin'), $this->acl->getRoles());
  }
}