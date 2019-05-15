<?php
namespace Neos\Ldap\Service\BindProvider;

/*
 * This file is part of the Neos.Ldap package.
 *
 * (c) Contributors of the Neos Project - www.neos.io
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Error\Exception;
use Neos\Flow\Security\Exception\MissingConfigurationException;
use Neos\Utility\Arrays;

/**
 * Bind to an OpenLdap Server
 *
 * @Flow\Scope("prototype")
 */
class LdapBind extends AbstractBindProvider
{

    /**
     * Bind to an ldap server in three different ways.
     *
     * Settings example for anonymous binding (dn and password will be ignored):
     *   ...
     *   bind:
     *       anonymous: TRUE
     *
     * Settings example for binding with service account and its password:
     *   ...
     *   bind:
     *       dn: 'uid=admin,dc=example,dc=com'
     *       password: 'secret'
     *
     * Settings example for binding with user ID and password (the ? will be replaced by user ID):
     *   ...
     *   bind:
     *       dn: 'uid=?,ou=Users,dc=example,dc=com'
     *
     * @param string $username
     * @param string $password
     *
     * @throws MissingConfigurationException
     */
    public function bind($username, $password)
    {
        $bindPassword = Arrays::getValueByPath($this->options, 'bind.password');
        $bindDn = Arrays::getValueByPath($this->options, 'bind.dn');

        if (!empty($username) && !empty($password) && empty($bindPassword)) {
            // if credentials are given, use them to authenticate
            $this->bindWithDn(sprintf($bindDn, $username), $password);
            return;
        }


        if (!empty($username) && !empty($bindPassword)) {
            $this->bindWithDn(sprintf($bindDn, $username), $bindPassword);
            return;
        }

        if (!empty($bindPassword)) {
            // if the settings specify a bind password, we are safe to assume no anonymous authentication is needed
            $this->bindWithDn($bindDn, $bindPassword);
        }

        $anonymousBind = Arrays::getValueByPath($this->options, 'bind.anonymous');
        if ($anonymousBind) {
            // if allowed, bind without username or password
            $this->bindAnonymously();
        }

        throw new MissingConfigurationException(
            'You misconfigured the Neos.Ldap configuration. Please check your configuration',
            1554828615
        );
    }

}
