<?php

namespace ultimo\security;

class Acl {
  /**
   * Holds the parents for each role, a hashtable with role names as key and
   * an array with their parents as value.
   * @var array
   */
  protected $parents;
  
  /**
   * Hold the allowed privileges for each role, a hashtable with role names as
   * key and a hashtable with allowed privileges as value. The privileges
   * hashtable has privileges names as key, and custom callbackk functions as
   * value (null if no callback function was specified).
   * @var array
   */
  protected $allowed;
  
  /**
   * Holds the denied privileged for each role, a hashtable with role names as
   * key and an array with denied privileges as value. The privileges
   * hashtable has privileges names as key, and custom callbackk functions as
   * value (null if no callback function was specified).
   * @var array
   */
  protected $denied;
  
  const ALL_PRIVILEGES = '_all_';
  
  /**
   * Constructor.
   */
  public function __construct(){
    $this->parents = array();
    $this->allowed = array();
    $this->denied = array();
  }
  
  /**
   * Adds a role with the specifed parents. If the role already exists,
   * the the parents are added to the current specified parents.
   * @param string $role The name of the role to add.
   * @param array|string $parents The parent roles of the role to add.
   * @return Acl This instance for fluid design.
   */
  public function addRole($role, $parents = array()) {
    // ensure parents is an array
    if (!is_array($parents)) {
      $parents = array($parents);
    }
    
    if (!array_key_exists($role, $this->parents)) {
      // the role does not exist, so add it
      $this->parents[$role] = $parents;
      $this->allowed[$role] = array();
      $this->denied[$role] = array();
    } else {
      // the role already exists, add the new parents to it
      foreach($parents as $parent) {
        
        if (!array_key_exists($parent, $this->parents)) {
          throw new AclException("Role '$parent' does not exist.", AclException::ROLE_NOT_FOUND);
        }
        
        if ($parent != $role && !in_array($parent, $this->parents[$role])) {
          $this->parents[$role][] = $parent;
        }
      }
    }
    return $this;
  }
  
  /**
   * Adds an allowed privilege to a role. This also removes it from the
   * denied list.
   * @param string $role The role to add the allowed privilege to.
   * @param string|array $privileges The privileges to add to the role, or null
   * if all privileges are allowed.
   * @param callback A callback function to call when to check for the
   * permission of the privilege. This function must return true on allowed or
   * false on denied. Use null for no callback function.
   * @return Acl This instance for fluid design.
   */
  public function allow($role, $privileges = null, $callback=null) {
    // check if the role exists
    if (!array_key_exists($role, $this->parents)) {
      throw new AclException("Role '$role' does not exist.", AclException::ROLE_NOT_FOUND);
    }
    
    if ($privileges === null) {
      // all privileges are allowed, so denied should be empty
      $this->allowed[$role][self::ALL_PRIVILEGES] = $callback;
      $this->denied[$role] = array();
    } else {
      // ensure privileges is an array
      if (!is_array($privileges)) {
        $privileges = array($privileges);
      }
      
      // if all privileges are denied, remove that entry
      if (!empty($privileges) && array_key_exists(self::ALL_PRIVILEGES, $this->denied[$role])) {
        // This is not necessary, as unexisting priviliges are denied by default
        unset($this->denied[$role][self::ALL_PRIVILEGES]);
      }
      
      // add each privilege to the allowed list, and remove it from the denied list
      foreach($privileges as $privilege) {
        $this->allowed[$role][$privilege] = $callback;
        if (array_key_exists($privilege, $this->denied[$role])) {
          unset($this->denied[$role][$privilege]);
        }
      }
    }
    return $this;
  }
  
  /**
   * Adds an denied privilege to a role. This also removes it from the
   * allowed list.
   * @param string $role The role to add the denied privilege to.
   * @param array $privileges The privileges to add to the role, or null if
   * all privileges are denied.
   * @param callback A callback function to call when to check for the
   * permission of the privilege. This function must return true on denied or
   * false on allowed. Use null for no callback function.
   * @return Acl This instance for fluid design.
   */
  public function deny($role, $privileges = null, $callback=null) {
    // check if the role exists
    if (!array_key_exists($role, $this->parents)) {
      throw new AclException("Role '$role' does not exist.", AclException::ROLE_NOT_FOUND);
    }
    
    if ($privileges === null) {
      // all privileges are denied, so allowed should be empty
      $this->denied[$role][self::ALL_PRIVILEGES] = $callback;
      $this->allowed[$role] = array();
    } else {
      // ensure privileges is an array
      if (!is_array($privileges)) {
        $privileges = array($privileges);
      }
      
      // if all privileges are allowed, remove that entry
      if (!empty($privileges) && array_key_exists(self::ALL_PRIVILEGES, $this->allowed[$role])) {
        unset($this->allowed[$role][self::ALL_PRIVILEGES]);
      }
      
      // add each privilege to the denied list, and remove it from the allowed list
      foreach($privileges as $privilege) {
        $this->denied[$role][$privilege] = $callback;
        if (array_key_exists($privilege, $this->allowed[$role])) {
          unset($this->allowed[$role][$privilege]);
        }
      }
    }
    return $this;
  }
  
  /**
   * Returns whether a privilege is allowed for a role.
   * @param string $role The role to check the privilege for.
   * @param mixed $privilege The privilege to check.
   * @param mixed $callbackParam The custom parameter for the callback function
   * of the privilege.
   * @return boolean Whether privilege is allowed for a role.
   */
  public function isAllowed($role, $privilege, $callbackParam = null) {
    if (!array_key_exists($role, $this->parents)) {
      return false;
    }
    
    $permission = $this->isAllowedRecursive($role, $privilege, $callbackParam);
    if ($permission === null) {
      return false;
    } else {
      return $permission;
    }
  }

  /**
   * Executes a privilege callback function and returns its result.
   * @param callback $callback The privilege callback function to execute.
   * @param string $role The name of the role to execute the callback function
   * for.
   * @param string $privilege The name of the privilege to execute the callback
   * function for
   * @param mixed $param The custom parameter for the privilege callback
   * function.
   * @return boolean The result of the privilege callback function.
   */
  protected function executeCallback($callback, $role, $privilege, $param) {
    if ($callback === null) {
      // No callback function wss specfied, the result is then true
      return true;
    }
    return call_user_func($callback, $role, $privilege, $param);
  }
  
  /**
   * Returns whether privilege is allowed for a role, or null if it is unknown.
   * This is done by checking the allowed and denied list of the role. If the
   * privilege is not found in one of these, this function is called
   * recursively for each of the parent roles.
   * @param string $role The role to check the privilege for.
   * @param mixed $privilege The privilege to check.
   * @param mixed $callbackParam The custom parameter for the callback function
   * of the privilege.
   * @return boolean Whether privilege is allowed for a role, or null if it is unknown.
   */
  protected function isAllowedRecursive($role, $privilege, $callbackParam) {
    if (array_key_exists($privilege, $this->allowed[$role])) {
      // the privilege is specified in the allowed list
      return $this->executeCallback($this->allowed[$role][$privilege], $role, $privilege, $callbackParam);
    } elseif (array_key_exists(self::ALL_PRIVILEGES, $this->allowed[$role])) {
      // all privileges are allowed
      return $this->executeCallback($this->allowed[$role][self::ALL_PRIVILEGES], $role, self::ALL_PRIVILEGES, $callbackParam);
    } elseif (array_key_exists($privilege, $this->denied[$role])) {
      // the privilege is specified in the denied list
      return !$this->executeCallback($this->denied[$role][$privilege], $role, $privilege, $callbackParam);
    } elseif (array_key_exists(self::ALL_PRIVILEGES, $this->denied[$role])) {
      // all privileges are denied
      return !$this->executeCallback($this->denied[$role][self::ALL_PRIVILEGES], $role, self::ALL_PRIVILEGES, $callbackParam);
    } else {
      // check each parent if the privilige is allowed
      foreach ($this->parents[$role] as $parent) {
        $isParentAllowed = $this->isAllowedRecursive($parent, $privilege, $callbackParam);
        if ($isParentAllowed !== null) {
          return $isParentAllowed;
        }
      }
      
      // it is still unknown, so return null
      return null;
    }
  }
  
  /**
   * Returns whether a role has a role as parent.
   * @param string $child The role to check if it has a parent.
   * @param string $parent The parent role.
   * @return boolean Whether a role has a role as parent.
   */
  public function belongsTo($child, $parent) {
    if (!array_key_exists($child, $this->parents)) {
      return false;
    }
    
    if ($child == $parent) {
      return true;
    }
    
    if (in_array($parent, $this->parents[$child])) {
      return true;
    } else {
      foreach($this->parents[$child] as $role) {
        if ($this->belongsTo($role, $parent)) {
          return true;
        }
      }
      return false;
    }
  }
  
  /**
   * Merges this accesslist with another accesslist.
   * @param Acl $acl The accesslist to merge with.
   * @return Acl This instance for fluid design.
   */
  public function merge(Acl $acl) {
    foreach ($acl->parents as $role => $parents) {
      $this->addRole($role, $parents);
    }
    
    foreach ($acl->allowed as $role => $privileges) {
      foreach ($privileges as $privilege => $callback) {
        $this->allow($role, $privilege, $callback);
      }
    }
    
    foreach ($acl->denied as $role => $privileges) {
      foreach ($privileges as $privilege => $callback) {
        $this->deny($role, $privilege, $callback);
      }
    }
    return $this;
  }
  
  /**
   * Returns all roles with parents.
   * @return array All roles with parents.
   */
  public function getRoles() {
    return array_keys($this->parents);
  }
  
}